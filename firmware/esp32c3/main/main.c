#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "esp_system.h"
#include "esp_mac.h"
#include "esp_err.h"
#include "esp_http_server.h"
#include "esp_http_client.h"
#include "esp_crt_bundle.h"
#include "esp_ota_ops.h"
#include "esp_partition.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "mbedtls/sha256.h"
#include "cJSON.h"
#include "lwip/inet.h"

#ifndef CONFIG_CLEANNET_UPSTREAM_DNS
#define CONFIG_CLEANNET_UPSTREAM_DNS "1.1.1.1"
#endif
#ifndef CONFIG_CLEANNET_DNS_TIMEOUT_MS
#define CONFIG_CLEANNET_DNS_TIMEOUT_MS 1800
#endif
#ifndef CONFIG_CLEANNET_SETUP_AP_SSID
#define CONFIG_CLEANNET_SETUP_AP_SSID "CLEANNET-SETUP"
#endif
#ifndef CONFIG_CLEANNET_OTA_MANIFEST_URL
#define CONFIG_CLEANNET_OTA_MANIFEST_URL "https://cleannet-api-qkv4.onrender.com/api/firmware/manifest"
#endif
#ifndef CONFIG_CLEANNET_OTA_CHECK_SECONDS
#define CONFIG_CLEANNET_OTA_CHECK_SECONDS 21600
#endif

#define DNS_PORT 53
#define DNS_PACKET_MAX 512
#define WIFI_NAMESPACE "cleannet"
#define DEVICE_VERSION "0.2.0"
#define OTA_BUFFER_SIZE 2048

static const char *TAG = "CLEANNET";
static EventGroupHandle_t s_wifi_events;
static bool s_dns_started = false;
static bool s_ota_started = false;
static char s_setup_ssid[33];
static char s_setup_password[17];

static const char *BLOCKED_DOMAINS[] = {
    "doubleclick.net", "googlesyndication.com", "googleadservices.com",
    "googletagservices.com", "adservice.google.com", "adnxs.com",
    "adform.net", "adsrvr.org", "taboola.com", "outbrain.com",
    "criteo.com", "scorecardresearch.com", "quantserve.com", "hotjar.com",
    "app-measurement.com", "connect.facebook.net", "amazon-adsystem.com",
    "applovin.com", "inmobi.com", "pubmatic.com", "openx.net",
    "rubiconproject.com", "casalemedia.com", "smartadserver.com", "yieldmo.com"
};
static const size_t BLOCKED_COUNT = sizeof(BLOCKED_DOMAINS) / sizeof(BLOCKED_DOMAINS[0]);

static bool domain_is_blocked(const char *name) {
    for (size_t i = 0; i < BLOCKED_COUNT; i++) {
        const char *blocked = BLOCKED_DOMAINS[i];
        size_t n = strlen(name), b = strlen(blocked);
        if ((n == b && strcasecmp(name, blocked) == 0) ||
            (n > b && name[n - b - 1] == '.' && strcasecmp(name + n - b, blocked) == 0)) return true;
    }
    return false;
}

static bool get_query_name(const uint8_t *packet, size_t len, char *out, size_t out_len) {
    if (len < 17 || out_len < 2) return false;
    size_t pos = 12, used = 0;
    while (pos < len) {
        uint8_t label_len = packet[pos++];
        if (label_len == 0) { out[used] = '\0'; return used > 0; }
        if ((label_len & 0xC0) != 0 || label_len > 63 || pos + label_len > len) return false;
        if (used) { if (used + 1 >= out_len) return false; out[used++] = '.'; }
        if (used + label_len >= out_len) return false;
        for (uint8_t i = 0; i < label_len; i++) {
            char c = (char)packet[pos++];
            out[used++] = (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
        }
    }
    return false;
}

static void send_nxdomain(int sock, const uint8_t *query, size_t len,
                          const struct sockaddr_in *client, socklen_t client_len) {
    if (len < 12 || len > DNS_PACKET_MAX) return;
    uint8_t response[DNS_PACKET_MAX];
    memcpy(response, query, len);
    uint16_t flags = ((uint16_t)response[2] << 8) | response[3];
    flags |= 0x8080;
    flags = (flags & 0xFFF0) | 0x0003;
    response[2] = (uint8_t)(flags >> 8); response[3] = (uint8_t)flags;
    memset(response + 6, 0, 6);
    sendto(sock, response, len, 0, (const struct sockaddr *)client, client_len);
}

static bool forward_dns(const uint8_t *query, size_t query_len, uint8_t *reply, size_t *reply_len) {
    int upstream = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (upstream < 0) return false;
    struct timeval timeout = {.tv_sec = CONFIG_CLEANNET_DNS_TIMEOUT_MS / 1000,
        .tv_usec = (CONFIG_CLEANNET_DNS_TIMEOUT_MS % 1000) * 1000};
    setsockopt(upstream, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    struct sockaddr_in dns = {.sin_family = AF_INET, .sin_port = htons(DNS_PORT)};
    if (inet_pton(AF_INET, CONFIG_CLEANNET_UPSTREAM_DNS, &dns.sin_addr) != 1) { close(upstream); return false; }
    bool ok = false;
    if (sendto(upstream, query, query_len, 0, (struct sockaddr *)&dns, sizeof(dns)) == (ssize_t)query_len) {
        ssize_t n = recvfrom(upstream, reply, DNS_PACKET_MAX, 0, NULL, NULL);
        if (n >= 12) { *reply_len = (size_t)n; ok = true; }
    }
    close(upstream);
    return ok;
}

static void dns_server_task(void *arg) {
    (void)arg;
    int server = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (server < 0) { ESP_LOGE(TAG, "DNS socket failed: %d", errno); vTaskDelete(NULL); return; }
    struct sockaddr_in local = {.sin_family = AF_INET, .sin_port = htons(DNS_PORT), .sin_addr.s_addr = htonl(INADDR_ANY)};
    if (bind(server, (struct sockaddr *)&local, sizeof(local)) < 0) {
        ESP_LOGE(TAG, "DNS bind failed: %d", errno); close(server); vTaskDelete(NULL); return;
    }
    ESP_LOGI(TAG, "DNS proxy listening on UDP/53");
    uint8_t query[DNS_PACKET_MAX], reply[DNS_PACKET_MAX];
    while (1) {
        struct sockaddr_in client; socklen_t client_len = sizeof(client);
        ssize_t n = recvfrom(server, query, sizeof(query), 0, (struct sockaddr *)&client, &client_len);
        if (n < 12) continue;
        char qname[254] = {0};
        if (!get_query_name(query, (size_t)n, qname, sizeof(qname))) continue;
        if (domain_is_blocked(qname)) {
            ESP_LOGI(TAG, "BLOCK %s", qname);
            send_nxdomain(server, query, (size_t)n, &client, client_len);
        } else {
            size_t reply_len = 0;
            if (forward_dns(query, (size_t)n, reply, &reply_len)) {
                sendto(server, reply, reply_len, 0, (struct sockaddr *)&client, client_len);
                ESP_LOGD(TAG, "ALLOW %s", qname);
            } else ESP_LOGW(TAG, "Upstream timeout: %s", qname);
        }
    }
}

static esp_err_t root_handler(httpd_req_t *req) {
    static const char page[] =
        "<!doctype html><html><head><meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>CLEANNET Setup</title><style>body{font:16px Arial;background:#101827;color:#fff;margin:0;padding:24px}"
        "main{max-width:520px;margin:auto;background:#1e293b;padding:22px;border-radius:16px}button,input,select{width:100%;padding:13px;margin:8px 0;border-radius:8px;border:0;box-sizing:border-box}"
        "button{background:#16a34a;color:white;font-weight:bold}small{color:#cbd5e1}</style></head><body><main>"
        "<h2>CLEANNET Wi-Fi Setup</h2><p>Scan nearby 2.4 GHz Wi-Fi networks, select yours and enter its password.</p>"
        "<button onclick='scan()'>Scan Wi-Fi Networks</button><select id='nets'><option>Select network</option></select>"
        "<input id='ssid' placeholder='Wi-Fi name (SSID)'><input id='pw' type='password' placeholder='Wi-Fi password'>"
        "<button onclick='connectNet()'>Save & Connect</button><p id='msg'></p><small>Setup page: 192.168.4.1</small></main>"
        "<script>async function scan(){let m=document.getElementById('msg');m.textContent='Scanning...';try{let r=await fetch('/api/scan');let j=await r.json();let s=document.getElementById('nets');s.innerHTML='';j.networks.forEach(n=>{let o=document.createElement('option');o.value=n.ssid;o.textContent=n.ssid+' ('+n.rssi+' dBm)'+(n.secure?' 🔒':'');s.appendChild(o)});m.textContent=j.networks.length+' networks found'}catch(e){m.textContent='Scan failed: '+e}}"
        "document.getElementById('nets').onchange=e=>document.getElementById('ssid').value=e.target.value;"
        "async function connectNet(){let m=document.getElementById('msg');m.textContent='Saving and connecting...';let r=await fetch('/api/connect',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ssid:document.getElementById('ssid').value,password:document.getElementById('pw').value})});let j=await r.json();m.textContent=j.message||j.detail||'Request sent'}"
        "</script></body></html>";
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    return httpd_resp_send(req, page, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t scan_handler(httpd_req_t *req) {
    wifi_scan_config_t scan = {.show_hidden = false, .scan_type = WIFI_SCAN_TYPE_ACTIVE};
    esp_err_t err = esp_wifi_scan_start(&scan, true);
    if (err != ESP_OK) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Wi-Fi scan failed");
    uint16_t count = 0; esp_wifi_scan_get_ap_num(&count);
    if (count > 30) count = 30;
    wifi_ap_record_t *records = calloc(count ? count : 1, sizeof(wifi_ap_record_t));
    if (!records) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Out of memory");
    esp_wifi_scan_get_ap_records(&count, records);
    cJSON *root = cJSON_CreateObject(); cJSON *arr = cJSON_AddArrayToObject(root, "networks");
    for (int i = 0; i < count; i++) {
        if (!records[i].ssid[0]) continue;
        cJSON *item = cJSON_CreateObject();
        cJSON_AddStringToObject(item, "ssid", (const char *)records[i].ssid);
        cJSON_AddNumberToObject(item, "rssi", records[i].rssi);
        cJSON_AddNumberToObject(item, "channel", records[i].primary);
        cJSON_AddBoolToObject(item, "secure", records[i].authmode != WIFI_AUTH_OPEN);
        cJSON_AddItemToArray(arr, item);
    }
    free(records);
    char *body = cJSON_PrintUnformatted(root);
    httpd_resp_set_type(req, "application/json"); httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    esp_err_t result = httpd_resp_sendstr(req, body ? body : "{\"networks\":[]}");
    free(body); cJSON_Delete(root); return result;
}

static esp_err_t connect_handler(httpd_req_t *req) {
    if (req->content_len <= 0 || req->content_len > 512)
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid request size");
    char body[513] = {0}; int received = httpd_req_recv(req, body, req->content_len);
    if (received <= 0) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Request body missing");
    cJSON *json = cJSON_ParseWithLength(body, received);
    const cJSON *ssid = cJSON_GetObjectItemCaseSensitive(json, "ssid");
    const cJSON *password = cJSON_GetObjectItemCaseSensitive(json, "password");
    if (!cJSON_IsString(ssid) || !cJSON_IsString(password) || strlen(ssid->valuestring) == 0 ||
        strlen(ssid->valuestring) > 32 || strlen(password->valuestring) > 64) {
        cJSON_Delete(json); return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "SSID/password invalid");
    }
    nvs_handle_t nvs; esp_err_t err = nvs_open(WIFI_NAMESPACE, NVS_READWRITE, &nvs);
    if (err == ESP_OK) {
        err = nvs_set_str(nvs, "ssid", ssid->valuestring);
        if (err == ESP_OK) err = nvs_set_str(nvs, "password", password->valuestring);
        if (err == ESP_OK) err = nvs_commit(nvs);
        nvs_close(nvs);
    }
    if (err != ESP_OK) { cJSON_Delete(json); return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Could not save credentials"); }
    wifi_config_t cfg = {0};
    strlcpy((char *)cfg.sta.ssid, ssid->valuestring, sizeof(cfg.sta.ssid));
    strlcpy((char *)cfg.sta.password, password->valuestring, sizeof(cfg.sta.password));
    cfg.sta.threshold.authmode = WIFI_AUTH_OPEN;
    cfg.sta.pmf_cfg.capable = true; cfg.sta.pmf_cfg.required = false;
    esp_wifi_disconnect();
    esp_wifi_set_config(WIFI_IF_STA, &cfg);
    esp_wifi_connect();
    cJSON_Delete(json);
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(req, "{\"ok\":true,\"message\":\"Credentials saved. CLEANNET is connecting; check serial monitor for its LAN IP.\"}");
}

static void start_setup_server(void) {
    httpd_config_t config = HTTPD_DEFAULT_CONFIG(); config.server_port = 80; config.max_uri_handlers = 8;
    httpd_handle_t server = NULL;
    if (httpd_start(&server, &config) != ESP_OK) { ESP_LOGE(TAG, "Setup web server failed"); return; }
    httpd_uri_t root = {.uri="/", .method=HTTP_GET, .handler=root_handler};
    httpd_uri_t scan = {.uri="/api/scan", .method=HTTP_GET, .handler=scan_handler};
    httpd_uri_t connect = {.uri="/api/connect", .method=HTTP_POST, .handler=connect_handler};
    httpd_register_uri_handler(server, &root); httpd_register_uri_handler(server, &scan);
    httpd_register_uri_handler(server, &connect);
}

static void start_setup_ap(void) {
    uint8_t mac[6] = {0}; esp_read_mac(mac, ESP_MAC_WIFI_SOFTAP);
    snprintf(s_setup_ssid, sizeof(s_setup_ssid), "%s-%02X%02X", CONFIG_CLEANNET_SETUP_AP_SSID, mac[4], mac[5]);
    snprintf(s_setup_password, sizeof(s_setup_password), "CN%02X%02X%02X", mac[3], mac[4], mac[5]);
    wifi_config_t ap = {0};
    strlcpy((char *)ap.ap.ssid, s_setup_ssid, sizeof(ap.ap.ssid));
    strlcpy((char *)ap.ap.password, s_setup_password, sizeof(ap.ap.password));
    ap.ap.ssid_len = strlen(s_setup_ssid); ap.ap.channel = 1; ap.ap.max_connection = 4;
    ap.ap.authmode = WIFI_AUTH_WPA2_PSK;
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap));
    ESP_LOGI(TAG, "Setup Wi-Fi: %s | Password: %s | Open http://192.168.4.1", s_setup_ssid, s_setup_password);
}

static bool load_wifi_credentials(wifi_config_t *cfg) {
    nvs_handle_t nvs; if (nvs_open(WIFI_NAMESPACE, NVS_READONLY, &nvs) != ESP_OK) return false;
    size_t ssid_len = sizeof(cfg->sta.ssid), pass_len = sizeof(cfg->sta.password);
    esp_err_t a = nvs_get_str(nvs, "ssid", (char *)cfg->sta.ssid, &ssid_len);
    esp_err_t b = nvs_get_str(nvs, "password", (char *)cfg->sta.password, &pass_len);
    nvs_close(nvs);
    cfg->sta.threshold.authmode = WIFI_AUTH_OPEN;
    cfg->sta.pmf_cfg.capable = true; cfg->sta.pmf_cfg.required = false;
    return a == ESP_OK && b == ESP_OK && cfg->sta.ssid[0] != 0;
}

static void ota_task(void *arg);

static void wifi_event_handler(void *arg, esp_event_base_t base, int32_t id, void *data) {
    (void)arg;
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        ESP_LOGW(TAG, "Router Wi-Fi disconnected; setup AP remains available");
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)data;
        ESP_LOGI(TAG, "Router connected. CLEANNET LAN IP: " IPSTR, IP2STR(&event->ip_info.ip));
        if (!s_dns_started) { s_dns_started = true; xTaskCreate(dns_server_task, "cleannet_dns", 6144, NULL, 5, NULL); }
        if (!s_ota_started) { s_ota_started = true; xTaskCreate(ota_task, "cleannet_ota", 8192, NULL, 4, NULL); }
    }
}

static bool version_is_newer(const char *candidate, const char *current) {
    unsigned int a=0,b=0,c=0,x=0,y=0,z=0;
    if (sscanf(candidate, "%u.%u.%u", &a, &b, &c) != 3 ||
        sscanf(current, "%u.%u.%u", &x, &y, &z) != 3) return false;
    if (a != x) return a > x;
    if (b != y) return b > y;
    return c > z;
}

static bool ota_download_and_install(const char *url, const char *expected_sha) {
    if (strncmp(url, "https://", 8) != 0 || strlen(expected_sha) != 64) return false;
    esp_http_client_config_t cfg = {.url=url, .timeout_ms=20000, .crt_bundle_attach=esp_crt_bundle_attach,
        .buffer_size=OTA_BUFFER_SIZE, .keep_alive_enable=true};
    esp_http_client_handle_t client = esp_http_client_init(&cfg);
    if (!client) return false;
    if (esp_http_client_open(client, 0) != ESP_OK) { esp_http_client_cleanup(client); return false; }
    int content_length = esp_http_client_fetch_headers(client);
    if (esp_http_client_get_status_code(client) != 200 || content_length <= 0) {
        esp_http_client_close(client); esp_http_client_cleanup(client); return false;
    }
    const esp_partition_t *partition = esp_ota_get_next_update_partition(NULL);
    if (!partition || (size_t)content_length > partition->size) {
        ESP_LOGE(TAG, "OTA image does not fit target partition"); esp_http_client_close(client); esp_http_client_cleanup(client); return false;
    }
    esp_ota_handle_t handle = 0;
    if (esp_ota_begin(partition, content_length, &handle) != ESP_OK) {
        esp_http_client_close(client); esp_http_client_cleanup(client); return false;
    }
    mbedtls_sha256_context sha; mbedtls_sha256_init(&sha); mbedtls_sha256_starts_ret(&sha, 0);
    uint8_t buffer[OTA_BUFFER_SIZE], digest[32]; int total = 0; bool ok = true;
    while (total < content_length) {
        int n = esp_http_client_read(client, (char *)buffer, sizeof(buffer));
        if (n <= 0) { ok = false; break; }
        if (esp_ota_write(handle, buffer, n) != ESP_OK) { ok = false; break; }
        mbedtls_sha256_update_ret(&sha, buffer, n); total += n;
    }
    mbedtls_sha256_finish_ret(&sha, digest); mbedtls_sha256_free(&sha);
    esp_http_client_close(client); esp_http_client_cleanup(client);
    char actual[65]; for (int i=0;i<32;i++) snprintf(actual+i*2,3,"%02x",digest[i]); actual[64]=0;
    if (total != content_length || strcasecmp(actual, expected_sha) != 0) ok = false;
    if (!ok) { esp_ota_abort(handle); ESP_LOGE(TAG, "OTA download/hash verification failed"); return false; }
    if (esp_ota_end(handle) != ESP_OK) return false;
    if (esp_ota_set_boot_partition(partition) != ESP_OK) return false;
    ESP_LOGW(TAG, "Verified firmware downloaded. Restarting into new OTA image.");
    vTaskDelay(pdMS_TO_TICKS(1000)); esp_restart(); return true;
}

static void ota_task(void *arg) {
    (void)arg;
    vTaskDelay(pdMS_TO_TICKS(30000));
    while (1) {
        esp_http_client_config_t cfg = {.url=CONFIG_CLEANNET_OTA_MANIFEST_URL, .timeout_ms=20000,
            .crt_bundle_attach=esp_crt_bundle_attach, .buffer_size=1024};
        esp_http_client_handle_t client = esp_http_client_init(&cfg);
        if (client && esp_http_client_open(client, 0) == ESP_OK) {
            int length = esp_http_client_fetch_headers(client);
            if (esp_http_client_get_status_code(client) == 200 && length > 0 && length < 4096) {
                char *body = calloc(1, 4097);
                if (body) {
                    int total = 0, n = 0;
                    while (total < length && (n = esp_http_client_read(client, body + total, length - total)) > 0) total += n;
                    if (total == length) {
                        cJSON *root = cJSON_ParseWithLength(body, total);
                        cJSON *enabled = cJSON_GetObjectItem(root, "enabled");
                        cJSON *version = cJSON_GetObjectItem(root, "version");
                        cJSON *url = cJSON_GetObjectItem(root, "url");
                        cJSON *sha = cJSON_GetObjectItem(root, "sha256");
                        if (cJSON_IsTrue(enabled) && cJSON_IsString(version) && cJSON_IsString(url) &&
                            cJSON_IsString(sha) && version_is_newer(version->valuestring, DEVICE_VERSION)) {
                            ESP_LOGW(TAG, "New OTA release %s available (current %s)", version->valuestring, DEVICE_VERSION);
                            ota_download_and_install(url->valuestring, sha->valuestring);
                        }
                        cJSON_Delete(root);
                    }
                    free(body);
                }
            } else ESP_LOGW(TAG, "OTA manifest returned HTTP %d or invalid size", esp_http_client_get_status_code(client));
            esp_http_client_close(client);
        } else ESP_LOGW(TAG, "OTA manifest check unavailable; will retry later");
        if (client) esp_http_client_cleanup(client);
        vTaskDelay(pdMS_TO_TICKS(CONFIG_CLEANNET_OTA_CHECK_SECONDS * 1000ULL));
    }
}

void app_main(void) {
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase()); ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);
    esp_err_t ota_state = esp_ota_mark_app_valid_cancel_rollback();
    if (ota_state == ESP_OK) ESP_LOGI(TAG, "OTA image marked valid after boot");
    ESP_LOGI(TAG, "CLEANNET %s booting; upstream DNS %s; blocklist %u entries",
        DEVICE_VERSION, CONFIG_CLEANNET_UPSTREAM_DNS, (unsigned)BLOCKED_COUNT);
    s_wifi_events = xEventGroupCreate();
    ESP_ERROR_CHECK(esp_netif_init()); ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta(); esp_netif_create_default_wifi_ap();
    wifi_init_config_t init = WIFI_INIT_CONFIG_DEFAULT(); ESP_ERROR_CHECK(esp_wifi_init(&init));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL));
    wifi_config_t sta = {0}; bool have_creds = load_wifi_credentials(&sta);
    if (!have_creds) ESP_LOGW(TAG, "No router credentials saved. Use CLEANNET setup Wi-Fi.");
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    if (have_creds) ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &sta));
    start_setup_ap();
    ESP_ERROR_CHECK(esp_wifi_start());
    start_setup_server();
    if (have_creds) ESP_ERROR_CHECK(esp_wifi_connect());
}
