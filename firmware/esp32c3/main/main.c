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
#include "freertos/semphr.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "driver/gpio.h"
#include "led_strip.h"
#include "esp_wifi.h"
#include "esp_system.h"
#include "esp_heap_caps.h"
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
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "host/ble_hs.h"
#include "host/ble_gap.h"
#include "services/gap/ble_svc_gap.h"
#include "services/gatt/ble_svc_gatt.h"

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
#ifndef CONFIG_CLEANNET_BLOCKLIST_URL
#define CONFIG_CLEANNET_BLOCKLIST_URL "https://cleannet-api-qkv4.onrender.com/api/blocklist?since=0"
#endif
#ifndef CONFIG_CLEANNET_HEARTBEAT_URL
#define CONFIG_CLEANNET_HEARTBEAT_URL "https://cleannet-api-qkv4.onrender.com/api/device/heartbeat"
#endif
#define CLEANNET_HEARTBEAT_SECONDS 900

#define DNS_PORT 53
#define DNS_PACKET_MAX 512
#define WIFI_NAMESPACE "cleannet"
#define DEVICE_VERSION "0.3.1"
#define OTA_BUFFER_SIZE 2048

static const char *TAG = "CLEANNET";
static EventGroupHandle_t s_wifi_events;
static SemaphoreHandle_t s_https_mutex;
static bool s_dns_started = false;
static bool s_ota_started = false;
static bool s_heartbeat_started = false;
static char s_device_token[201] = {0};

/* Capture heap headroom around HTTPS/TLS operations for OTA diagnostics. */
static void log_ota_heap(const char *stage) {
    size_t free_heap = esp_get_free_heap_size();
    size_t min_free = esp_get_minimum_free_heap_size();
    size_t largest = heap_caps_get_largest_free_block(MALLOC_CAP_8BIT);
    ESP_LOGI(TAG, "OTA heap [%s]: free=%u min_free=%u largest_block=%u",
        stage, (unsigned)free_heap, (unsigned)min_free, (unsigned)largest);
}
static volatile uint32_t s_dns_queries_window = 0;
static led_strip_handle_t s_led_strip = NULL;
typedef enum { LED_OTA_IDLE = 0, LED_OTA_RECEIVING, LED_OTA_VERIFYING, LED_OTA_INSTALLING, LED_OTA_READY } led_ota_state_t;
static volatile led_ota_state_t s_led_ota_state = LED_OTA_IDLE;
static volatile TickType_t s_pairing_until = 0;
static volatile bool s_pairing_active = false;
static httpd_handle_t s_setup_httpd = NULL;
static volatile bool s_ble_ready = false;
static volatile bool s_router_connected = false;
static volatile bool s_internet_available = false;
static volatile bool s_server_available = false;
static volatile bool s_blocklist_sync_started = false;
static char s_remote_blocked_domains[32][254];
static volatile size_t s_remote_blocked_count = 0;
static uint32_t s_blocklist_version = 0;
static volatile uint32_t s_dns_total = 0, s_dns_blocked = 0, s_dns_upstream_failures = 0;

/* Five-pixel WS2812 chain. Test build uses physical pixels 2..4 only.
 * Logical LED1=Wi-Fi, LED2=Internet, LED3=DNS/Cloud.
 * Physical pixel 1 (power) and pixel 5 are intentionally kept off.
 * GPIO0 remains reserved for the physical PAIR button. */
#define CLEANNET_LED_DATA_GPIO GPIO_NUM_3
#define CLEANNET_LED_PIXEL_COUNT 5
#define CLEANNET_STATUS_LED_COUNT 3
#define CLEANNET_PAIR_BUTTON_GPIO GPIO_NUM_0
static char s_setup_ssid[33];
static char s_setup_password[17];
static void start_setup_ap(void);
static void stop_setup_ap(void);

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

static bool domain_matches_suffix(const char *name, const char *blocked) {
    size_t n = strlen(name), b = strlen(blocked);
    return (n == b && strcasecmp(name, blocked) == 0) ||
           (n > b && name[n - b - 1] == '.' && strcasecmp(name + n - b, blocked) == 0);
}
static bool domain_is_blocked(const char *name) {
    for (size_t i = 0; i < BLOCKED_COUNT; i++)
        if (domain_matches_suffix(name, BLOCKED_DOMAINS[i])) return true;
    size_t count = s_remote_blocked_count;
    for (size_t i = 0; i < count; i++)
        if (domain_matches_suffix(name, s_remote_blocked_domains[i])) return true;
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
        for (uint8_t i = 0; i < label_len; i++) {            char c = (char)packet[pos++];
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

static bool sync_remote_blocklist(void) {
    if (!s_router_connected || !s_internet_available) return false;
    if (s_https_mutex) xSemaphoreTake(s_https_mutex, portMAX_DELAY);
    esp_http_client_config_t cfg = {
        .url = CONFIG_CLEANNET_BLOCKLIST_URL,
        .timeout_ms = 15000,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .buffer_size = 1024
    };
    esp_http_client_handle_t client = esp_http_client_init(&cfg);
    bool ok = false;
    if (esp_get_free_heap_size() < 50000 || heap_caps_get_largest_free_block(MALLOC_CAP_8BIT) < 16000) {
        ESP_LOGW(TAG, "Skipping blocklist sync: insufficient heap headroom");
        if (s_https_mutex) xSemaphoreGive(s_https_mutex);
        return false;
    }
    char *body = (char *)malloc(4097);
    if (client && body) {
        esp_err_t err = esp_http_client_open(client, 0);
        if (err == ESP_OK) {
            int content_length = esp_http_client_fetch_headers(client);
            int status = esp_http_client_get_status_code(client);
            size_t total = 0;
            if (status == 200 && (content_length <= 0 || content_length <= 4096)) {
                while (total < 4096) {
                    int n = esp_http_client_read(client, body + total, 4096 - total);
                    if (n < 0) break;
                    if (n == 0) { ok = true; break; }
                    total += (size_t)n;
                    if (content_length > 0 && total == (size_t)content_length) { ok = true; break; }
                }
            }
            esp_http_client_close(client);
            if (ok && total > 0 && total < 8192) {
                cJSON *root = cJSON_ParseWithLength(body, total);
                cJSON *domains = cJSON_GetObjectItemCaseSensitive(root, "domains");
                cJSON *version = cJSON_GetObjectItemCaseSensitive(root, "version");
                if (cJSON_IsObject(root) && cJSON_IsArray(domains)) {
                    static char next[32][254];
                    size_t count = 0;
                    int nitems = cJSON_GetArraySize(domains);
                    if (nitems > 32) nitems = 32;
                    for (int i = 0; i < nitems; i++) {
                        cJSON *item = cJSON_GetArrayItem(domains, i);
                        if (!cJSON_IsString(item) || !item->valuestring) continue;
                        size_t len = strlen(item->valuestring);
                        if (len == 0 || len > 253) continue;
                        memcpy(next[count], item->valuestring, len + 1);
                        count++;
                    }
                    memcpy(s_remote_blocked_domains, next, count * sizeof(next[0]));
                    s_remote_blocked_count = count;
                    if (cJSON_IsNumber(version)) s_blocklist_version = (uint32_t)version->valuedouble;
                    ESP_LOGI(TAG, "Central blocklist synced: %u domains (version %u)",
                        (unsigned)count, (unsigned)s_blocklist_version);
                } else {
                    ok = false;
                    ESP_LOGW(TAG, "Central blocklist response JSON invalid");
                }
                cJSON_Delete(root);
            } else {
                ok = false;
                ESP_LOGW(TAG, "Central blocklist HTTP %d or incomplete response (%u bytes)",
                    status, (unsigned)total);
            }
        } else {
            ESP_LOGW(TAG, "Central blocklist HTTPS failed: %s", esp_err_to_name(err));
        }
    }
    if (body) free(body);
    if (client) esp_http_client_cleanup(client);
    if (s_https_mutex) xSemaphoreGive(s_https_mutex);
    return ok;
}

static void blocklist_sync_task(void *arg) {
    (void)arg;
    vTaskDelay(pdMS_TO_TICKS(12000));
    while (1) {
        sync_remote_blocklist();
        vTaskDelay(pdMS_TO_TICKS(21600000));
    }
}

static void dns_server_task(void *arg) {
    (void)arg;
    int server = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (server < 0) { s_dns_started = false; ESP_LOGE(TAG, "DNS socket failed: %d", errno); vTaskDelete(NULL); return; }
    struct sockaddr_in local = {.sin_family = AF_INET, .sin_port = htons(DNS_PORT), .sin_addr.s_addr = htonl(INADDR_ANY)};
    if (bind(server, (struct sockaddr *)&local, sizeof(local)) < 0) {
        s_dns_started = false; ESP_LOGE(TAG, "DNS bind failed: %d", errno); close(server); vTaskDelete(NULL); return;
    }
    s_dns_started = true;
    ESP_LOGI(TAG, "DNS proxy listening on UDP/53");
    uint8_t query[DNS_PACKET_MAX], reply[DNS_PACKET_MAX];
    while (1) {
        struct sockaddr_in client; socklen_t client_len = sizeof(client);
        ssize_t n = recvfrom(server, query, sizeof(query), 0, (struct sockaddr *)&client, &client_len);
        if (n < 12) continue;
        s_dns_queries_window++;
        s_dns_total++;
        char qname[254] = {0};
        if (!get_query_name(query, (size_t)n, qname, sizeof(qname))) continue;
        if (domain_is_blocked(qname)) {
            s_dns_blocked++;
            ESP_LOGI(TAG, "BLOCK %s", qname);
            send_nxdomain(server, query, (size_t)n, &client, client_len);
        } else {
            size_t reply_len = 0;
            if (forward_dns(query, (size_t)n, reply, &reply_len)) {
                sendto(server, reply, reply_len, 0, (struct sockaddr *)&client, client_len);
                ESP_LOGD(TAG, "ALLOW %s", qname);
            } else { s_dns_upstream_failures++; ESP_LOGW(TAG, "Upstream timeout: %s", qname); }
        }
    }
}


static esp_err_t status_json_handler(httpd_req_t *req) {
    esp_netif_t *sta = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    esp_netif_ip_info_t info = {0};
    esp_netif_dns_info_t dns = {0};
    bool has_ip = sta && esp_netif_get_ip_info(sta, &info) == ESP_OK && info.ip.addr != 0;
    bool has_dns = sta && esp_netif_get_dns_info(sta, ESP_NETIF_DNS_MAIN, &dns) == ESP_OK;
    char ip[16]="0.0.0.0", gw[16]="0.0.0.0", mask[16]="0.0.0.0", dns_ip[16]="unavailable";
    if (has_ip) {
        snprintf(ip,sizeof(ip),IPSTR,IP2STR(&info.ip));
        snprintf(gw,sizeof(gw),IPSTR,IP2STR(&info.gw));
        snprintf(mask,sizeof(mask),IPSTR,IP2STR(&info.netmask));
    }
    if (has_dns && dns.ip.type == ESP_IPADDR_TYPE_V4)
        snprintf(dns_ip,sizeof(dns_ip),IPSTR,IP2STR(&dns.ip.u_addr.ip4));
    cJSON *j=cJSON_CreateObject();
    uint8_t sta_mac[6] = {0};
    char mac_text[18] = "unavailable";
    if (esp_wifi_get_mac(WIFI_IF_STA, sta_mac) == ESP_OK)
        snprintf(mac_text, sizeof(mac_text), "%02X:%02X:%02X:%02X:%02X:%02X",
            sta_mac[0], sta_mac[1], sta_mac[2], sta_mac[3], sta_mac[4], sta_mac[5]);

    /* Read the immutable factory STA MAC from eFuse for the permanent Device ID.
     * Do not call esp_wifi_set_mac(): the router-facing MAC remains unchanged. */
    uint8_t factory_sta_mac[6] = {0};
    char factory_mac_text[18] = "unavailable";
    if (esp_read_mac(factory_sta_mac, ESP_MAC_WIFI_STA) == ESP_OK)
        snprintf(factory_mac_text, sizeof(factory_mac_text), "%02X:%02X:%02X:%02X:%02X:%02X",
            factory_sta_mac[0], factory_sta_mac[1], factory_sta_mac[2],
            factory_sta_mac[3], factory_sta_mac[4], factory_sta_mac[5]);
    cJSON_AddStringToObject(j,"wifi",s_router_connected?"Connected":"Disconnected");
    cJSON_AddStringToObject(j,"mac",mac_text);
    cJSON_AddStringToObject(j,"factory_mac",factory_mac_text);
    cJSON_AddStringToObject(j,"device_id",factory_mac_text);
    cJSON_AddStringToObject(j,"ip",ip);
    cJSON_AddStringToObject(j,"gateway",gw);
    cJSON_AddStringToObject(j,"subnet",mask);
    cJSON_AddStringToObject(j,"dhcp_dns",dns_ip);
    cJSON_AddStringToObject(j,"internet",s_internet_available?"Online":"Offline / checking");
    cJSON_AddStringToObject(j,"server",s_server_available?"Reachable":"Unavailable / checking");
    cJSON_AddStringToObject(j,"dns_service",s_dns_started?"UDP/53 listening":(s_router_connected?"Starting / unavailable":"Waiting for Wi-Fi"));
    cJSON_AddNumberToObject(j,"dns_total",s_dns_total);
    cJSON_AddNumberToObject(j,"dns_blocked",s_dns_blocked);
    cJSON_AddNumberToObject(j,"dns_failures",s_dns_upstream_failures);
    cJSON_AddStringToObject(j,"firmware",DEVICE_VERSION);
    cJSON_AddStringToObject(j,"router_dns_instruction",has_ip ?
        "Set this ESP32 IP as Primary DNS in router LAN DHCP DNS. Leave Secondary DNS blank." :
        "Wait for ESP32 to connect and receive a LAN IP before changing router DNS.");
    char *body=cJSON_PrintUnformatted(j);
    httpd_resp_set_type(req,"application/json");
    httpd_resp_set_hdr(req,"Cache-Control","no-store");
    esp_err_t result=httpd_resp_sendstr(req,body?body:"{}");
    free(body); cJSON_Delete(j); return result;
}


static esp_err_t capabilities_handler(httpd_req_t *req) {
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "device", "CLEANNET-ESP32C3");
    cJSON_AddStringToObject(root, "firmware", DEVICE_VERSION);
    cJSON_AddBoolToObject(root, "ota_supported", true);
    cJSON_AddBoolToObject(root, "ble_supported_in_build", true);
    cJSON_AddBoolToObject(root, "ble_advertising", s_ble_ready);
    cJSON_AddBoolToObject(root, "pairing_ap_active", s_pairing_active);
    cJSON_AddNumberToObject(root, "pairing_remaining_seconds",
        s_pairing_active && s_pairing_until != 0 &&
        (int32_t)(s_pairing_until - xTaskGetTickCount()) > 0 ?
        (uint32_t)((s_pairing_until - xTaskGetTickCount()) * portTICK_PERIOD_MS / 1000) : 0);
    cJSON *pins = cJSON_AddArrayToObject(root, "gpio");
    for (int pin = 0; pin <= 21; pin++) {
        cJSON *item = cJSON_CreateObject();
        const char *role = "unassigned";
        const char *state = "board_verification_required";
        if (pin == CLEANNET_LED_DATA_GPIO) { role = "addressable_rgb_led_data"; state = "reserved"; }
        else if (pin == CLEANNET_PAIR_BUTTON_GPIO) { role = "pair_button_active_low"; state = "reserved_boot_strap_caution"; }
        else if (pin >= 12 && pin <= 17) { role = "module_flash_or_unavailable"; state = "do_not_use"; }
        else if (pin == 18 || pin == 19) { role = "native_usb_possible"; state = "board_verification_required"; }
        else if (pin == 2 || pin == 8 || pin == 9) { role = "strapping_pin"; state = "do_not_use_without_board_test"; }
        else if (pin == 20 || pin == 21) { role = "uart_possible"; state = "board_verification_required"; }
        cJSON_AddNumberToObject(item, "gpio", pin);
        cJSON_AddStringToObject(item, "role", role);
        cJSON_AddStringToObject(item, "state", state);        cJSON_AddItemToArray(pins, item);
    }
    cJSON_AddStringToObject(root, "pin_policy",
        "Only board-verified, unreserved GPIOs may be enabled by a future signed OTA configuration. GPIO capabilities vary by board revision.");
    char *body = cJSON_PrintUnformatted(root);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    esp_err_t result = httpd_resp_sendstr(req, body ? body : "{}");
    free(body);    cJSON_Delete(root);
    return result;
}

static esp_err_t status_page_handler(httpd_req_t *req) {
    static const char page[] =
      "<!doctype html><html><head><meta name='viewport' content='width=device-width,initial-scale=1'>"
      "<meta charset='utf-8'><title>CLEANNET Status</title><style>"
      "body{font:16px system-ui;background:#071426;color:#eef6ff;margin:0;padding:20px}"
      "main{max-width:720px;margin:auto;background:#10233b;padding:22px;border-radius:18px}"
      "h1{color:#42d6cf}.item{padding:12px;margin:8px 0;background:#08182a;border:1px solid #28435f;border-radius:10px;overflow-wrap:anywhere}"
      "small{color:#9db2c9}</style></head><body><main><h1>CLEANNET Device Status</h1>"
      "<small>Auto refresh every 5 seconds · No Serial Monitor needed</small><div id='v'>Loading…</div>"
      "<script>async function go(){try{let r=await fetch('/api/status',{cache:'no-store'}),s=await r.json();"
      "let rows=[['Wi-Fi',s.wifi],['Wi-Fi MAC Address',s.mac],['CLEANNET DNS Server IP (Primary DNS)',s.ip],['Internet',s.internet],['CLEANNET Render server',s.server],['DNS service',s.dns_service],"
      "['ESP32 LAN IP',s.ip],['Gateway',s.gateway],['Subnet mask',s.subnet],['Router DHCP DNS',s.dhcp_dns],"
      "['DNS requests',s.dns_total],['Blocked domains',s.dns_blocked],['Upstream failures',s.dns_failures],['Firmware',s.firmware],"
      "['Router DNS instruction',s.router_dns_instruction]];"
      "document.getElementById('v').innerHTML=rows.map(x=>'<div class=item><b>'+x[0]+':</b> '+x[1]+'</div>').join('')"
      "}catch(e){document.getElementById('v').textContent='Status not available yet. Stay connected to CLEANNET and reload.'}}"
      "go();setInterval(go,5000)</script></main></body></html>";
    httpd_resp_set_type(req,"text/html; charset=utf-8");
    httpd_resp_set_hdr(req,"Cache-Control","no-store");
    return httpd_resp_send(req,page,HTTPD_RESP_USE_STRLEN);
}

static esp_err_t root_handler(httpd_req_t *req) {
    static const char page[] =
        "<!doctype html>"
        "<html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta name='theme-color' content='#071426'><title>CLEANNET | Device Setup</title>"
        "<style>"
        ":root{color-scheme:dark;--bg:#071426;--panel:#10233b;--panel2:#142b46;--line:#28435f;--muted:#9db2c9;--text:#f4f8fc;--cyan:#42d6cf;--blue:#5c9cff;--green:#36d399;--red:#fb7185}"
        "*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 12% 0%,#123a55 0,transparent 38%),linear-gradient(145deg,#071426,#0b1d32 65%,#101e35);font:15px system-ui,-apple-system,Segoe UI,Arial;color:var(--text);min-height:100vh;padding:22px}"
        ".shell{max-width:920px;margin:auto}.top{display:flex;align-items:center;justify-content:space-between;gap:12px;margin:4px 0 24px}.brand{display:flex;align-items:center;gap:12px}.logo{width:48px;height:48px;flex:none}.brand strong{display:block;font-size:20px;letter-spacing:2px}.brand small,.muted{color:var(--muted)}.pill{border:1px solid #28616a;background:#103b48;color:#8ff5e7;border-radius:99px;padding:7px 12px;font-size:12px}"
        ".hero{display:grid;grid-template-columns:1.2fr .8fr;gap:18px;margin-bottom:18px}.heroText,.art,.card{background:linear-gradient(145deg,#112944,#0d2037);border:1px solid var(--line);border-radius:22px;padding:24px;box-shadow:0 18px 50px #02091455}.eyebrow{color:var(--cyan);font-size:12px;font-weight:700;letter-spacing:2px;text-transform:uppercase}.hero h1{font-size:clamp(27px,5vw,42px);line-height:1.08;margin:10px 0}.hero p{color:var(--muted);line-height:1.65;margin-bottom:0}.art{display:flex;align-items:center;justify-content:center;min-height:190px;background:radial-gradient(circle at 50% 50%,#174b65,#10233b 68%)}.art svg{width:min(100%,230px);height:auto}"
        ".steps{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin:0 0 18px}.step{border:1px solid var(--line);border-radius:14px;padding:13px;background:#0e2138}.num{display:inline-grid;place-items:center;width:25px;height:25px;border-radius:8px;background:#16445a;color:var(--cyan);font-weight:800;margin-right:7px}.step b{font-size:13px}.step small{display:block;color:var(--muted);margin:7px 0 0 33px;line-height:1.4}"
        ".card h2{margin:0 0 6px;font-size:21px}.card p{color:var(--muted);margin:0 0 16px;line-height:1.5}.actions{display:flex;gap:10px;flex-wrap:wrap}button,input,select{font:inherit;border-radius:12px}button{border:0;padding:13px 17px;font-weight:750;cursor:pointer}.primary{background:linear-gradient(100deg,#23c6b9,#49a8ff);color:#041727}.secondary{background:#1a3552;color:#e8f3ff;border:1px solid #31516e}.field{margin:14px 0}.field label{display:block;font-size:13px;color:#c3d4e5;margin-bottom:7px}.field input,.field select{width:100%;padding:14px;background:#08182a;color:#fff;border:1px solid #31516e;outline:none}.field input:focus,.field select:focus{border-color:var(--cyan);box-shadow:0 0 0 3px #42d6cf22}.passwordRow{display:flex;gap:8px}.passwordRow input{flex:1;min-width:0}.passwordRow button{padding:0 14px;background:#1a3552;color:white;border:1px solid #31516e}.status{margin-top:14px;border-radius:12px;padding:12px;background:#0a1b2d;border:1px solid #28435f;color:#c8d8e8;min-height:46px}.modal{display:none;position:fixed;inset:0;background:#020914dd;z-index:20;padding:18px;align-items:center;justify-content:center}.modal.show{display:flex}.modalBox{width:min(100%,520px);max-height:90vh;overflow:auto;background:#102944;border:1px solid #42d6cf;border-radius:20px;padding:22px}.modalBox h2{color:#42d6cf;margin:0 0 8px}.iprow{padding:10px;margin:8px 0;background:#08182a;border:1px solid #31516e;border-radius:10px;overflow-wrap:anywhere}.iprow b{display:block;color:#9db2c9;font-size:12px;margin-bottom:3px}.footer{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;color:#829ab3;font-size:12px;padding:18px 4px}.hint{font-size:12px;color:var(--muted);margin-top:8px}"
        "@media(max-width:680px){body{padding:14px}.hero{grid-template-columns:1fr}.art{min-height:140px}.steps{grid-template-columns:1fr}.top{margin-bottom:16px}.heroText,.art,.card{padding:19px}}"
        "</style></head><body><div class='shell'>"
        "<header class='top'><div class='brand'><svg class='logo' viewBox='0 0 64 64' role='img' aria-label='CLEANNET logo'><defs><linearGradient id='g' x1='0' y1='0' x2='1' y2='1'><stop stop-color='#42d6cf'/><stop offset='1' stop-color='#5c9cff'/></linearGradient></defs><rect x='3' y='3' width='58' height='58' rx='18' fill='#123c55' stroke='#3d8496'/><path d='M32 10 49 17v13c0 12-7 19-17 24C22 49 15 42 15 30V17z' fill='url(#g)'/><path d='m23 32 6 6 13-15' fill='none' stroke='#062238' stroke-width='4' stroke-linecap='round' stroke-linejoin='round'/></svg><div><strong>CLEANNET</strong><small>by TAKNA TECHNOLOGY</small></div></div><span class='pill'>● DEVICE SETUP</span></header>"
        "<section class='hero'><div class='heroText'><div class='eyebrow'>Secure your home network</div><h1>Clean internet.<br>Clear control.</h1><p>Connect your CLEANNET device to your 2.4 GHz Wi-Fi network. Scan, select and connect in a few simple steps.</p></div>"
        "<div class='art' aria-hidden='true'><svg viewBox='0 0 240 180'><circle cx='120' cy='88' r='72' fill='#153e59'/><circle cx='120' cy='88' r='53' fill='none' stroke='#2a7890' stroke-width='2' stroke-dasharray='5 7'/><path d='M75 74q45-42 90 0M89 91q31-28 62 0M105 108q15-13 30 0' fill='none' stroke='#42d6cf' stroke-width='7' stroke-linecap='round'/><circle cx='120' cy='125' r='6' fill='#42d6cf'/><path d='M120 20v20M190 88h-20M50 88h20' stroke='#5c9cff' stroke-width='3' stroke-linecap='round'/><path d='m167 37 8-8m-110 8-8-8' stroke='#5c9cff' stroke-width='3' stroke-linecap='round'/></svg></div></section>"
        "<section class='steps'><div class='step'><span class='num'>1</span><b>Scan networks</b><small>Find nearby 2.4 GHz Wi-Fi.</small></div><div class='step'><span class='num'>2</span><b>Choose your Wi-Fi</b><small>Select your router network.</small></div><div class='step'><span class='num'>3</span><b>Connect CLEANNET</b><small>Enter password and save.</small></div></section>"
        "<section class='card'><h2>Connect to your router</h2><p>Choose your home network and enter its Wi-Fi password. Your credentials are saved on this device.</p>"
        "<div class='actions'><button class='primary' id='scanBtn' onclick='scan()'>⌕ &nbsp; Scan Wi-Fi networks</button></div>"
        "<div class='field'><label for='nets'>Nearby networks</label><select id='nets'><option value=''>Scan to find networks</option></select></div>"
        "<div class='field'><label for='deviceToken'>Cloud Device Token (optional)</label><input id='deviceToken' type='password' maxlength='200' autocomplete='off' placeholder='Paste the one-time device token from Admin Panel'><div class='hint'>Required for cloud heartbeat and approximate location. Saved locally over the WPA2 setup AP; cloud heartbeat uses HTTPS.</div></div>"
        "<div class='field'><label for='ssid'>Wi-Fi name (SSID)</label><input id='ssid' maxlength='32' autocomplete='off' placeholder='Enter Wi-Fi name'></div>"
        "<div class='field'><label for='pw'>Wi-Fi password</label><div class='passwordRow'><input id='pw' type='password' maxlength='64' autocomplete='new-password' placeholder='Enter Wi-Fi password'><button type='button' onclick='togglePassword()'>Show</button></div><div class='hint'>Your Wi-Fi password is sent only to this CLEANNET device over its local setup connection.</div></div>"
        "<button class='primary' id='connectBtn' style='width:100%' onclick='connectNet()'>Save &amp; Connect</button><div id='msg' class='status' role='status' aria-live='polite'>Ready. Scan for nearby Wi-Fi networks to begin.</div></section>"
        "<div class='modal' id='resultModal' role='dialog' aria-modal='true'><div class='modalBox'><h2>CLEANNET Connected</h2><p id='resultSummary' class='muted'>Wi-Fi connection confirmed.</p><div id='resultDetails'></div><div class='actions' style='margin-top:16px'><button class='primary' onclick='copyDnsIp()'>Copy DNS Server IP</button><a class='secondary' href='/status'>Open Full Status</a><button class='secondary' onclick='closeResult()'>Close</button></div></div></div><footer class='footer'><span>Factory MAC Device ID: <b id='deviceId'>Loading…</b></span><span>Unique to this ESP32-C3 · Read-only · Router MAC unchanged</span><span>CLEANNET · Local setup · 192.168.4.1</span></footer></div>"
        "<script>"
        "const $=id=>document.getElementById(id);"
        "async function loadDeviceId(){try{const r=await fetch('/api/status',{cache:'no-store'});if(!r.ok)throw new Error('status');const s=await r.json();$('deviceId').textContent=s.device_id||s.factory_mac||'Unavailable'}catch(e){$('deviceId').textContent='Unavailable'}}loadDeviceId();"
        "async function scan(){const b=$('scanBtn'),m=$('msg'),s=$('nets');b.disabled=true;b.textContent='Scanning…';m.textContent='Searching for nearby networks…';try{const r=await fetch('/api/scan',{cache:'no-store'});if(!r.ok)throw new Error('HTTP '+r.status);const j=await r.json();s.innerHTML='<option value=\"\">Select a Wi-Fi network</option>';j.networks.forEach(n=>{const o=document.createElement('option');o.value=n.ssid;o.textContent=n.ssid+' · '+n.rssi+' dBm'+(n.secure?' · secured':' · open');s.appendChild(o)});m.textContent=j.networks.length+' network(s) found. Select your router.'}catch(e){m.textContent='Scan failed: '+e.message}finally{b.disabled=false;b.textContent='⌕  Scan Wi-Fi networks'}}"
        "$('nets').addEventListener('change',e=>{if(e.target.value)$('ssid').value=e.target.value});"
        "function togglePassword(){const p=$('pw'),b=p.nextElementSibling;p.type=p.type==='password'?'text':'password';b.textContent=p.type==='password'?'Show':'Hide'}"
        "let latestDnsIp='';function closeResult(){$('resultModal').classList.remove('show')}async function copyDnsIp(){if(!latestDnsIp)return;try{await navigator.clipboard.writeText(latestDnsIp);$('resultSummary').textContent='DNS Server IP copied: '+latestDnsIp}catch(e){$('resultSummary').textContent='Copy unavailable; DNS IP: '+latestDnsIp}}function showConnection(s){latestDnsIp=s.ip;const fields=[['Factory MAC Device ID',s.device_id||s.factory_mac],['Wi-Fi status',s.wifi],['CLEANNET DNS Server / Primary DNS IP',s.ip],['Wi-Fi MAC Address (router-facing)',s.mac],['Router Gateway',s.gateway],['Subnet Mask',s.subnet],['Router DHCP DNS',s.dhcp_dns],['Internet',s.internet],['CLEANNET Server',s.server],['DNS Service',s.dns_service]];$('resultDetails').innerHTML=fields.map(x=>'<div class=iprow><b>'+x[0]+'</b>'+String(x[1]||'Unavailable')+'</div>').join('');$('resultModal').classList.add('show');$('resultSummary').textContent='Connection confirmed. Set CLEANNET DNS Server IP as Primary DNS in Jio AirFiber LAN/DHCP settings.'}async function waitForConnection(){const m=$('msg'),started=Date.now();while(Date.now()-started<60000){await new Promise(resolve=>setTimeout(resolve,1500));try{const r=await fetch('/api/status',{cache:'no-store'});if(r.ok){const s=await r.json();if(s.wifi==='Connected'&&s.ip&&s.ip!=='0.0.0.0'){m.textContent='Connected! CLEANNET LAN IP: '+s.ip;showConnection(s);return}}}catch(e){}m.textContent='Waiting for router connection and IP address…'}m.textContent='Credentials saved, but connection is not confirmed yet. Check Wi-Fi/password and open /status.'}async function connectNet(){const b=$('connectBtn'),m=$('msg'),ssid=$('ssid').value.trim(),password=$('pw').value;if(!ssid){m.textContent='Please enter or select your Wi-Fi name.';return}b.disabled=true;b.textContent='Connecting…';m.textContent='Saving Wi-Fi details and connecting to your router…';try{const r=await fetch('/api/connect',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ssid,password,device_token:$('deviceToken').value.trim()})});const j=await r.json();if(!r.ok)throw new Error(j.detail||'Connection request failed');$('deviceToken').value='';m.textContent='Credentials saved. Waiting for connection and IP…';await waitForConnection()}catch(e){m.textContent='Could not connect: '+e.message}finally{b.disabled=false;b.textContent='Save & Connect'}}"
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
    const cJSON *device_token = cJSON_GetObjectItemCaseSensitive(json, "device_token");
    if (!cJSON_IsString(ssid) || !cJSON_IsString(password) || strlen(ssid->valuestring) == 0 ||
        strlen(ssid->valuestring) > 32 || strlen(password->valuestring) > 64 ||
        (device_token && (!cJSON_IsString(device_token) ||
            (strlen(device_token->valuestring) != 0 && strlen(device_token->valuestring) < 20) ||
            strlen(device_token->valuestring) > 200))) {
        cJSON_Delete(json); return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "SSID/password invalid");
    }
    nvs_handle_t nvs; esp_err_t err = nvs_open(WIFI_NAMESPACE, NVS_READWRITE, &nvs);
    if (err == ESP_OK) {
        err = nvs_set_str(nvs, "ssid", ssid->valuestring);
        if (err == ESP_OK) err = nvs_set_str(nvs, "password", password->valuestring);
        if (err == ESP_OK && device_token && strlen(device_token->valuestring) >= 20)
            err = nvs_set_str(nvs, "device_token", device_token->valuestring);
        if (err == ESP_OK) err = nvs_commit(nvs);
        nvs_close(nvs);
    }
    if (err != ESP_OK) { cJSON_Delete(json); return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Could not save credentials"); }
    wifi_config_t cfg = {0};
    strlcpy((char *)cfg.sta.ssid, ssid->valuestring, sizeof(cfg.sta.ssid));
    strlcpy((char *)cfg.sta.password, password->valuestring, sizeof(cfg.sta.password));
    cfg.sta.threshold.authmode = WIFI_AUTH_OPEN;
    cfg.sta.pmf_cfg.capable = true; cfg.sta.pmf_cfg.required = false;
    /* Keep the setup AP available and retain the factory eFuse Wi-Fi MAC. */
    start_setup_ap();
    err = esp_wifi_set_mode(WIFI_MODE_APSTA);
    if (err != ESP_OK) {
        cJSON_Delete(json);
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
            "Could not enable Wi-Fi station interface");
    }
    err = esp_wifi_set_config(WIFI_IF_STA, &cfg);
    if (err != ESP_OK) {
        cJSON_Delete(json);
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
            "Could not apply router Wi-Fi settings");
    }
    /* Keep Setup AP available briefly so the phone can receive connection status. */    s_pairing_until = xTaskGetTickCount() + pdMS_TO_TICKS(180000);
    start_setup_ap();
    esp_wifi_connect();
    cJSON_Delete(json);
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(req, "{\"ok\":true,\"message\":\"Credentials saved. CLEANNET is connecting; check serial monitor for its LAN IP.\"}");
}
/* Ignore query strings added by browsers or link wrappers when matching routes. */
static bool uri_match_ignore_query(const char *registered_uri, const char *request_uri, size_t request_uri_len) {
    const char *query = memchr(request_uri, '?', request_uri_len);
    size_t path_len = query ? (size_t)(query - request_uri) : request_uri_len;
    return strlen(registered_uri) == path_len &&
           strncmp(registered_uri, request_uri, path_len) == 0;
}

static void start_setup_server(void) {
    if (s_setup_httpd) return;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.server_port = 80;
    config.max_uri_handlers = 8;
    config.uri_match_fn = uri_match_ignore_query;
    httpd_handle_t server = NULL;
    esp_err_t start_err = httpd_start(&server, &config);
    if (start_err != ESP_OK || server == NULL) {
        ESP_LOGE(TAG, "Setup web server failed: %s", esp_err_to_name(start_err));
        return;
    }

    s_setup_httpd = server;
    const httpd_uri_t routes[] = {
        {.uri="/", .method=HTTP_GET, .handler=root_handler},
        {.uri="/status", .method=HTTP_GET, .handler=status_page_handler},
        {.uri="/api/status", .method=HTTP_GET, .handler=status_json_handler},
        {.uri="/api/capabilities", .method=HTTP_GET, .handler=capabilities_handler},
        {.uri="/api/scan", .method=HTTP_GET, .handler=scan_handler},
        {.uri="/api/connect", .method=HTTP_POST, .handler=connect_handler}
    };
    for (size_t i = 0; i < sizeof(routes) / sizeof(routes[0]); i++) {
        esp_err_t err = httpd_register_uri_handler(server, &routes[i]);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "HTTP route registration failed for %s: %s",
                     routes[i].uri, esp_err_to_name(err));
        } else {
            ESP_LOGI(TAG, "HTTP route registered: %s", routes[i].uri);
        }
    }
    ESP_LOGI(TAG, "CLEANNET setup/status HTTP server ready on port 80");
}

static void start_setup_ap(void) {
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    uint8_t mac[6] = {0}; esp_read_mac(mac, ESP_MAC_WIFI_SOFTAP);
    snprintf(s_setup_ssid, sizeof(s_setup_ssid), "%s-%02X%02X", CONFIG_CLEANNET_SETUP_AP_SSID, mac[4], mac[5]);
    snprintf(s_setup_password, sizeof(s_setup_password), "CN%02X%02X%02X", mac[3], mac[4], mac[5]);
    wifi_config_t ap = {0};
    strlcpy((char *)ap.ap.ssid, s_setup_ssid, sizeof(ap.ap.ssid));
    strlcpy((char *)ap.ap.password, s_setup_password, sizeof(ap.ap.password));
    ap.ap.ssid_len = strlen(s_setup_ssid); ap.ap.channel = 1; ap.ap.max_connection = 4;
    ap.ap.authmode = WIFI_AUTH_WPA2_PSK;
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap));
    s_pairing_active = true;
    ESP_LOGI(TAG, "Pairing Setup Wi-Fi: %s | Password: %s | Open http://192.168.4.1", s_setup_ssid, s_setup_password);
}

static void stop_setup_ap(void) {
    if (!s_pairing_active) return;
    esp_err_t err = esp_wifi_set_mode(WIFI_MODE_STA);
    if (err == ESP_OK) {
        s_pairing_active = false;
        ESP_LOGI(TAG, "Pairing window closed; Setup AP disabled, router Wi-Fi remains active");
    } else {
        ESP_LOGE(TAG, "Could not disable Setup AP: %s", esp_err_to_name(err));
    }
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

static void load_device_token(void) {
    nvs_handle_t nvs;
    size_t length = sizeof(s_device_token);
    if (nvs_open(WIFI_NAMESPACE, NVS_READONLY, &nvs) != ESP_OK) return;
    if (nvs_get_str(nvs, "device_token", s_device_token, &length) != ESP_OK)
        s_device_token[0] = '\0';
    nvs_close(nvs);
}

static void ota_task(void *arg);

static void led_set_rgb(uint8_t red, uint8_t green, uint8_t blue) {
    if (!s_led_strip) return;
    for (int i = 0; i < CLEANNET_LED_PIXEL_COUNT; i++)
        led_strip_set_pixel(s_led_strip, i, red, green, blue);
    led_strip_refresh(s_led_strip);
}

static void led_set_one(int led_number, uint8_t red, uint8_t green, uint8_t blue) {
    if (!s_led_strip || led_number < 1 || led_number > CLEANNET_STATUS_LED_COUNT) return;
    /* Map logical status LEDs 1..3 to physical chain pixels 2..4. */
    led_strip_set_pixel(s_led_strip, led_number, red, green, blue);
}

static void indicators_init(void) {
    led_strip_config_t strip_config = {
        .strip_gpio_num = CLEANNET_LED_DATA_GPIO,
        .max_leds = CLEANNET_LED_PIXEL_COUNT,
        .led_model = LED_MODEL_WS2812,
        .color_component_format = LED_STRIP_COLOR_COMPONENT_FMT_GRB,
        .flags.invert_out = false,
    };
    led_strip_rmt_config_t rmt_config = {
        .clk_src = RMT_CLK_SRC_DEFAULT,
        .resolution_hz = 10 * 1000 * 1000,
        .mem_block_symbols = 64,
        .flags.with_dma = false,
    };
    ESP_ERROR_CHECK(led_strip_new_rmt_device(&strip_config, &rmt_config, &s_led_strip));
    ESP_ERROR_CHECK(led_strip_clear(s_led_strip));
}

static void indicators_task(void *arg) {
    (void)arg;
    const TickType_t boot_started = xTaskGetTickCount();

    while (1) {
        const uint32_t now_ms = xTaskGetTickCount() * portTICK_PERIOD_MS;
        const bool blink_500 = ((now_ms / 500U) % 2U) == 0U;
        const bool blink_250 = ((now_ms / 250U) % 2U) == 0U;
        const bool pulse_700 = ((now_ms / 700U) % 2U) == 0U;

        /* OTA blue/cyan chase across the three active status LEDs. */
        if (s_led_ota_state != LED_OTA_IDLE) {
            int active = (int)((now_ms / 180U) % CLEANNET_STATUS_LED_COUNT) + 1;
            for (int led = 1; led <= CLEANNET_STATUS_LED_COUNT; led++) {
                uint8_t r = 0, g = 0, b = 0;
                if (s_led_ota_state == LED_OTA_READY) {
                    if (led == CLEANNET_STATUS_LED_COUNT) b = 255;
                } else if (led == active) {
                    if (s_led_ota_state == LED_OTA_VERIFYING) { g = 180; b = 255; }
                    else { b = 255; }
                }
                led_set_one(led, r, g, b);
            }
            led_strip_refresh(s_led_strip);
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }

        /* Pairing: purple chase across the three active status LEDs. */
        if (s_pairing_until != 0 &&
            (int32_t)(s_pairing_until - xTaskGetTickCount()) > 0) {
            int active = (int)((now_ms / 300U) % CLEANNET_STATUS_LED_COUNT) + 1;
            for (int led = 1; led <= CLEANNET_STATUS_LED_COUNT; led++)
                led_set_one(led, led == active ? 180 : 0, 0, led == active ? 255 : 0);
            led_strip_refresh(s_led_strip);
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }

        /* Status LED1 (physical pixel 2): Router Wi-Fi link. */
        if (s_router_connected) led_set_one(1, 0, 0, 255);
        else led_set_one(1, blink_500 ? 255 : 0, 0, 0);

        /* Status LED2 (physical pixel 3): Internet reachability. */
        if (s_internet_available) led_set_one(2, 0, pulse_700 ? 255 : 35, 0);
        else led_set_one(2, blink_500 ? 255 : 0, blink_500 ? 80 : 0, 0);

        /* Status LED3 (physical pixel 4): DNS + Cloud/API combined.
         * Green=cloud reachable; cyan=DNS active; amber=internet only. */
        if (s_server_available) led_set_one(3, 0, blink_500 ? 255 : 50, blink_500 ? 80 : 15);
        else if (s_dns_started) led_set_one(3, 0, pulse_700 ? 180 : 30, pulse_700 ? 255 : 50);
        else if (s_internet_available) led_set_one(3, blink_500 ? 255 : 0, blink_500 ? 100 : 0, 0);
        else led_set_one(3, 0, 0, 0);

    }
}

/* Hold the physical PAIR button for 3 seconds to show pairing mode for 3 minutes.
 * GPIO0 is a boot-strapping pin on ESP32-C3: do not hold the button while powering on.
 * The setup AP is already available; this button provides a timed pairing indication. */
static void pairing_button_task(void *arg) {
    (void)arg;
    bool pressed = false;
    TickType_t pressed_at = 0;
    while (1) {
        bool now_pressed = (gpio_get_level(CLEANNET_PAIR_BUTTON_GPIO) == 0);
        if (now_pressed && !pressed) {
            pressed = true;
            pressed_at = xTaskGetTickCount();
        } else if (!now_pressed && pressed) {
            pressed = false;
        }
        if (pressed && s_pairing_until == 0 &&
            (xTaskGetTickCount() - pressed_at) >= pdMS_TO_TICKS(3000)) {
            s_pairing_until = xTaskGetTickCount() + pdMS_TO_TICKS(180000);
            start_setup_ap();
            ESP_LOGI(TAG, "PAIR mode active for 180 seconds (purple LED + Setup AP)");
        }
        if (s_pairing_until != 0 &&
            (int32_t)(xTaskGetTickCount() - s_pairing_until) >= 0) {
            s_pairing_until = 0;
            stop_setup_ap();
            ESP_LOGI(TAG, "PAIR mode expired; Setup AP disabled, router STA remains active");
        }
        vTaskDelay(pdMS_TO_TICKS(20));
    }
}

static void pairing_button_init(void) {
    gpio_config_t cfg = {
        .pin_bit_mask = 1ULL << CLEANNET_PAIR_BUTTON_GPIO,
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    ESP_ERROR_CHECK(gpio_config(&cfg));
}


static bool send_device_heartbeat(void) {
    if (!s_device_token[0] || !s_router_connected || !s_internet_available) return false;
    if (s_https_mutex) xSemaphoreTake(s_https_mutex, portMAX_DELAY);

    uint8_t factory_mac[6] = {0};
    char device_id[18] = "unavailable";
    if (esp_read_mac(factory_mac, ESP_MAC_WIFI_STA) == ESP_OK)
        snprintf(device_id, sizeof(device_id), "%02X:%02X:%02X:%02X:%02X:%02X",
            factory_mac[0], factory_mac[1], factory_mac[2],
            factory_mac[3], factory_mac[4], factory_mac[5]);

    char lan_ip[16] = "0.0.0.0";
    esp_netif_t *sta = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    esp_netif_ip_info_t ip_info = {0};
    if (sta && esp_netif_get_ip_info(sta, &ip_info) == ESP_OK && ip_info.ip.addr)
        snprintf(lan_ip, sizeof(lan_ip), IPSTR, IP2STR(&ip_info.ip));

    cJSON *root = cJSON_CreateObject();
    if (!root) {
        if (s_https_mutex) xSemaphoreGive(s_https_mutex);
        return false;
    }
    cJSON_AddStringToObject(root, "device_id", device_id);
    cJSON_AddStringToObject(root, "firmware", DEVICE_VERSION);
    cJSON_AddStringToObject(root, "wifi", s_router_connected ? "Connected" : "Disconnected");
    cJSON_AddStringToObject(root, "lan_ip", lan_ip);
    cJSON_AddNumberToObject(root, "dns_total", s_dns_total);
    cJSON_AddNumberToObject(root, "dns_blocked", s_dns_blocked);
    char *body = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!body) {
        if (s_https_mutex) xSemaphoreGive(s_https_mutex);
        return false;
    }

    esp_http_client_config_t cfg = {
        .url = CONFIG_CLEANNET_HEARTBEAT_URL,
        .timeout_ms = 12000,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .buffer_size = 512
    };
    esp_http_client_handle_t client = esp_http_client_init(&cfg);
    bool ok = false;
    if (client) {
        char authorization[208];
        snprintf(authorization, sizeof(authorization), "Bearer %s", s_device_token);
        esp_http_client_set_method(client, HTTP_METHOD_POST);
        esp_http_client_set_header(client, "Content-Type", "application/json");
        esp_http_client_set_header(client, "Authorization", authorization);
        esp_http_client_set_post_field(client, body, (int)strlen(body));
        esp_err_t err = esp_http_client_perform(client);
        int status = esp_http_client_get_status_code(client);
        ok = (err == ESP_OK && status == 200);
        if (ok) ESP_LOGI(TAG, "Cloud heartbeat accepted for %s", device_id);
        else ESP_LOGW(TAG, "Cloud heartbeat failed: %s HTTP %d", esp_err_to_name(err), status);
        esp_http_client_cleanup(client);
    }
    free(body);
    if (s_https_mutex) xSemaphoreGive(s_https_mutex);
    return ok;
}

static void device_heartbeat_task(void *arg) {
    (void)arg;
    vTaskDelay(pdMS_TO_TICKS(30000));
    while (1) {
        if (s_router_connected && s_internet_available && s_device_token[0]) {
            send_device_heartbeat();
            vTaskDelay(pdMS_TO_TICKS(CLEANNET_HEARTBEAT_SECONDS * 1000ULL));
        } else {
            vTaskDelay(pdMS_TO_TICKS(60000));
        }
    }
}

static void server_monitor_task(void *arg) {
    (void)arg;
    while (1) {
        s_server_available = false;
        if (s_router_connected && s_internet_available) {
            if (s_https_mutex) xSemaphoreTake(s_https_mutex, portMAX_DELAY);
            esp_http_client_config_t cfg = {.url=CONFIG_CLEANNET_OTA_MANIFEST_URL,
                .timeout_ms=12000,.crt_bundle_attach=esp_crt_bundle_attach,.buffer_size=512};
            esp_http_client_handle_t client=esp_http_client_init(&cfg);
            if (client) {
                log_ota_heap("before server-monitor HTTPS");
                esp_err_t err=esp_http_client_perform(client);
                int status=esp_http_client_get_status_code(client);
                log_ota_heap("after server-monitor HTTPS");
                s_server_available=(err==ESP_OK && status==200);
                ESP_LOGI(TAG,"CLEANNET server check: %s (HTTP %d)",s_server_available?"reachable":"unavailable",status);
                esp_http_client_cleanup(client);
            }
            if (s_https_mutex) xSemaphoreGive(s_https_mutex);
        }
        vTaskDelay(pdMS_TO_TICKS(60000));
    }
}

static void internet_monitor_task(void *arg) {
    (void)arg;
    while (1) {
        if (!s_router_connected) {
            s_internet_available = false;
        } else {
            esp_http_client_config_t cfg = {
                .url = "https://connectivitycheck.gstatic.com/generate_204",
                .timeout_ms = 7000,
                .crt_bundle_attach = esp_crt_bundle_attach,
                .buffer_size = 256
            };
            if (s_https_mutex) xSemaphoreTake(s_https_mutex, portMAX_DELAY);
            log_ota_heap("before internet-monitor HTTPS");
            esp_http_client_handle_t client = esp_http_client_init(&cfg);
            if (client) {
                esp_err_t err = esp_http_client_perform(client);
                log_ota_heap("after internet-monitor HTTPS");
                int status = esp_http_client_get_status_code(client);
                s_internet_available = (err == ESP_OK && (status == 204 || status == 200));
                esp_http_client_cleanup(client);
            } else {
                s_internet_available = false;
            }
            if (s_https_mutex) xSemaphoreGive(s_https_mutex);
        }
        vTaskDelay(pdMS_TO_TICKS(15000));
    }
}

static void wifi_event_handler(void *arg, esp_event_base_t base, int32_t id, void *data) {
    (void)arg;
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        s_router_connected = false;
        s_internet_available = false;
        if (s_wifi_events) xEventGroupSetBits(s_wifi_events, BIT0);
        ESP_LOGW(TAG, "Router Wi-Fi disconnected; setup AP remains available");
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)data;
        s_router_connected = true;
        ESP_LOGI(TAG, "Router connected. CLEANNET LAN IP: " IPSTR, IP2STR(&event->ip_info.ip));
        ESP_LOGI(TAG, "Gateway: " IPSTR " | Subnet: " IPSTR, IP2STR(&event->ip_info.gw), IP2STR(&event->ip_info.netmask));
        ESP_LOGI(TAG, "Set router Primary DNS to CLEANNET LAN IP: " IPSTR, IP2STR(&event->ip_info.ip));
        if (!s_dns_started) {
            BaseType_t dns_task = xTaskCreate(dns_server_task, "cleannet_dns", 6144, NULL, 5, NULL);
            if (dns_task != pdPASS) ESP_LOGE(TAG, "Could not create DNS task");
        }
        if (!s_blocklist_sync_started) {
            BaseType_t sync_task_created = xTaskCreate(blocklist_sync_task, "cleannet_blocklist", 6144, NULL, 3, NULL);
            if (sync_task_created == pdPASS) s_blocklist_sync_started = true;
            else ESP_LOGE(TAG, "Could not create central blocklist sync task");
        }
        if (!s_ota_started) {
            BaseType_t ota_task_created = xTaskCreate(ota_task, "cleannet_ota", 8192, NULL, 4, NULL);
            if (ota_task_created == pdPASS) s_ota_started = true;
            else ESP_LOGE(TAG, "Could not create OTA task");
        }
        if (!s_heartbeat_started) {
            BaseType_t heartbeat_created = xTaskCreate(device_heartbeat_task, "cleannet_heartbeat", 8192, NULL, 3, NULL);
            if (heartbeat_created == pdPASS) s_heartbeat_started = true;
            else ESP_LOGE(TAG, "Could not create device heartbeat task");
        }
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
    s_led_ota_state = LED_OTA_RECEIVING;
    if (!url || strncmp(url, "https://", 8) != 0 || !expected_sha || strlen(expected_sha) != 64) {
        ESP_LOGE(TAG, "OTA manifest URL or SHA-256 is invalid");
        return false;
    }

    const esp_partition_t *partition = esp_ota_get_next_update_partition(NULL);
    if (!partition) {
        ESP_LOGE(TAG, "No OTA update partition available");
        return false;
    }

    esp_http_client_config_t cfg = {        .url = url, .timeout_ms = 45000, .crt_bundle_attach = esp_crt_bundle_attach,
        .buffer_size = OTA_BUFFER_SIZE, .keep_alive_enable = true
    };
    esp_http_client_handle_t client = esp_http_client_init(&cfg);
    if (!client) return false;

    esp_err_t err = esp_http_client_open(client, 0);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "OTA binary connection failed: %s", esp_err_to_name(err));
        esp_http_client_cleanup(client);        return false;
    }

    int content_length = esp_http_client_fetch_headers(client);
    int status = esp_http_client_get_status_code(client);
    if (status != 200 || content_length > (int)partition->size) {
        ESP_LOGE(TAG, "OTA binary HTTP %d or invalid size %d (partition %u)",
            status, content_length, (unsigned)partition->size);
        esp_http_client_close(client);
        esp_http_client_cleanup(client);
        return false;
    }

    esp_ota_handle_t handle = 0;
    if (esp_ota_begin(partition, OTA_SIZE_UNKNOWN, &handle) != ESP_OK) {
        ESP_LOGE(TAG, "Could not begin OTA write");
        esp_http_client_close(client);
        esp_http_client_cleanup(client);
        return false;
    }

    mbedtls_sha256_context sha;
    mbedtls_sha256_init(&sha);
    mbedtls_sha256_starts(&sha, 0);
    uint8_t buffer[OTA_BUFFER_SIZE], digest[32];
    size_t total = 0;
    bool ok = true;

    while (total < partition->size) {
        int n = esp_http_client_read(client, (char *)buffer, sizeof(buffer));
        if (n < 0) {
            ESP_LOGE(TAG, "OTA binary read failed");
            ok = false;
            break;
        }
        if (n == 0) break;
        if (total + (size_t)n > partition->size ||
            (content_length > 0 && total + (size_t)n > (size_t)content_length)) {
            ESP_LOGE(TAG, "OTA binary exceeds declared/partition size");
            ok = false;
            break;
        }
        if (esp_ota_write(handle, buffer, n) != ESP_OK) {
            ESP_LOGE(TAG, "OTA flash write failed");
            ok = false;
            break;
        }
        mbedtls_sha256_update(&sha, buffer, (size_t)n);
        total += (size_t)n;
    }

    mbedtls_sha256_finish(&sha, digest);
    mbedtls_sha256_free(&sha);
    esp_http_client_close(client);
    esp_http_client_cleanup(client);

    s_led_ota_state = LED_OTA_VERIFYING;
    if (total == 0 || (content_length > 0 && total != (size_t)content_length)) ok = false;
    char actual[65];
    for (int i = 0; i < 32; i++) snprintf(actual + i * 2, 3, "%02x", digest[i]);
    actual[64] = '\0';
    if (strcasecmp(actual, expected_sha) != 0) ok = false;

    if (!ok) {
        s_led_ota_state = LED_OTA_IDLE;
        esp_ota_abort(handle);
        ESP_LOGE(TAG, "OTA download incomplete or SHA-256 verification failed");
        return false;
    }
    s_led_ota_state = LED_OTA_INSTALLING;
    if (esp_ota_end(handle) != ESP_OK) {
        s_led_ota_state = LED_OTA_IDLE;
        ESP_LOGE(TAG, "OTA image validation failed");
        return false;
    }
    if (esp_ota_set_boot_partition(partition) != ESP_OK) {
        s_led_ota_state = LED_OTA_IDLE;
        ESP_LOGE(TAG, "Could not select new OTA boot partition");
        return false;
    }

    ESP_LOGW(TAG, "OTA image downloaded and SHA-256 verified (%u bytes). Restarting.",
        (unsigned)total);
    s_led_ota_state = LED_OTA_READY;
    vTaskDelay(pdMS_TO_TICKS(1500));
    led_set_rgb(0, 0, 0);
    esp_restart();
    return true;
}

static void ota_task(void *arg) {
    (void)arg;
    vTaskDelay(pdMS_TO_TICKS(30000));
    while (1) {
        char pending_ota_url[512] = {0};
        char pending_ota_sha[65] = {0};
        bool pending_ota = false;
        esp_http_client_config_t cfg = {
            .url = CONFIG_CLEANNET_OTA_MANIFEST_URL,
            .timeout_ms = 25000,
            .crt_bundle_attach = esp_crt_bundle_attach,
            .buffer_size = 1024
        };
        if (s_https_mutex) xSemaphoreTake(s_https_mutex, portMAX_DELAY);
        log_ota_heap("before manifest client init");
        esp_http_client_handle_t client = esp_http_client_init(&cfg);
        if (client) {
            log_ota_heap("after manifest client init");
            log_ota_heap("before manifest TLS handshake");
            esp_err_t open_err = esp_http_client_open(client, 0);
            log_ota_heap(open_err == ESP_OK ? "manifest connected" : "manifest TLS/connect failed");
            if (open_err == ESP_OK) {
                int length = esp_http_client_fetch_headers(client);
                int status = esp_http_client_get_status_code(client);
                if (status == 200 && length <= 1024) {
                    char body[1025] = {0};
                    int total = 0;
                    bool read_ok = true;
                    while (total < 1024) {
                        int n = esp_http_client_read(client, body + total, 1024 - total);
                        if (n < 0) { read_ok = false; break; }
                        if (n == 0) break;
                        total += n;
                    }
                    bool complete = read_ok && total > 0 &&
                        (length <= 0 || total == length) && total < 1024;
                    if (complete) {
                        cJSON *root = cJSON_ParseWithLength(body, (size_t)total);
                        if (cJSON_IsObject(root)) {
                            cJSON *enabled = cJSON_GetObjectItemCaseSensitive(root, "enabled");
                            cJSON *version = cJSON_GetObjectItemCaseSensitive(root, "version");
                            cJSON *url = cJSON_GetObjectItemCaseSensitive(root, "url");
                            cJSON *sha = cJSON_GetObjectItemCaseSensitive(root, "sha256");
                            if (cJSON_IsTrue(enabled) && cJSON_IsString(version) &&
                                cJSON_IsString(url) && cJSON_IsString(sha)) {
                                if (version_is_newer(version->valuestring, DEVICE_VERSION)) {
                                    size_t url_len = strlen(url->valuestring);
                                    size_t sha_len = strlen(sha->valuestring);
                                    if (url_len > 0 && url_len < sizeof(pending_ota_url) && sha_len == 64) {
                                        memcpy(pending_ota_url, url->valuestring, url_len + 1);
                                        memcpy(pending_ota_sha, sha->valuestring, sizeof(pending_ota_sha));
                                        pending_ota = true;
                                        ESP_LOGW(TAG, "New OTA release %s available (current %s)",
                                            version->valuestring, DEVICE_VERSION);
                                    } else {
                                        ESP_LOGE(TAG, "OTA manifest URL/SHA length invalid");
                                    }
                                } else {
                                    ESP_LOGI(TAG, "OTA manifest OK; device version %s is up to date",
                                        DEVICE_VERSION);
                                }
                            } else if (cJSON_IsFalse(enabled)) {
                                ESP_LOGI(TAG, "OTA manifest OK; no firmware release is currently published");
                            } else {
                                ESP_LOGW(TAG, "OTA manifest JSON missing required fields");
                            }
                        } else {
                            ESP_LOGW(TAG, "OTA manifest response is not valid JSON");
                        }
                        cJSON_Delete(root);
                    } else {
                        ESP_LOGW(TAG, "OTA manifest body incomplete/too large/read failed (HTTP %d, Content-Length %d, received %d)",
                            status, length, total);
                    }
                } else {
                    ESP_LOGW(TAG, "OTA manifest HTTP %d or manifest too large (Content-Length %d; max 1024)",
                        status, length);
                }
                esp_http_client_close(client);
            } else {
                ESP_LOGW(TAG, "OTA manifest connection failed: %s", esp_err_to_name(open_err));
            }
            /* Free the manifest TLS context before allocating the binary TLS context. */
            esp_http_client_cleanup(client);
            client = NULL;
            log_ota_heap("after manifest client cleanup");
        } else {
            ESP_LOGW(TAG, "OTA manifest client initialization failed");
        }

        if (pending_ota) {
            log_ota_heap("before OTA binary client init");
            ota_download_and_install(pending_ota_url, pending_ota_sha);
        }
        if (s_https_mutex) xSemaphoreGive(s_https_mutex);
        vTaskDelay(pdMS_TO_TICKS(CONFIG_CLEANNET_OTA_CHECK_SECONDS * 1000ULL));
    }
}


static void ble_on_sync(void) {
    uint8_t addr_type;
    int rc = ble_hs_id_infer_auto(0, &addr_type);
    if (rc != 0) { ESP_LOGE(TAG, "BLE address inference failed: %d", rc); return; }
    struct ble_hs_adv_fields fields;
    memset(&fields, 0, sizeof(fields));
    const char *name = "CLEANNET-C3";
    fields.flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;
    fields.name = (const uint8_t *)name;
    fields.name_len = strlen(name);
    fields.name_is_complete = 1;
    rc = ble_gap_adv_set_fields(&fields);
    if (rc != 0) { ESP_LOGE(TAG, "BLE advertising fields failed: %d", rc); return; }
    struct ble_gap_adv_params params;
    memset(&params, 0, sizeof(params));
    params.conn_mode = BLE_GAP_CONN_MODE_UND;
    params.disc_mode = BLE_GAP_DISC_MODE_GEN;
    rc = ble_gap_adv_start(addr_type, NULL, BLE_HS_FOREVER, &params, NULL, NULL);
    if (rc == 0) { s_ble_ready = true; ESP_LOGI(TAG, "BLE advertising: %s", name); }
    else ESP_LOGE(TAG, "BLE advertising start failed: %d", rc);
}
static void ble_host_task(void *param) {
    (void)param;
    nimble_port_run();
    nimble_port_freertos_deinit();
}
static void ble_init(void) {
    esp_err_t err = nimble_port_init();
    if (err != ESP_OK) { ESP_LOGE(TAG, "NimBLE init failed: %s", esp_err_to_name(err)); return; }
    ble_svc_gap_init();
    ble_svc_gatt_init();
    ble_svc_gap_device_name_set("CLEANNET-C3");
    ble_hs_cfg.sync_cb = ble_on_sync;
    nimble_port_freertos_init(ble_host_task);
}

void app_main(void) {
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase()); ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);
    load_device_token();
    esp_err_t ota_state = esp_ota_mark_app_valid_cancel_rollback();
    if (ota_state == ESP_OK) ESP_LOGI(TAG, "OTA image marked valid after boot");
    s_https_mutex = xSemaphoreCreateMutex();
    if (!s_https_mutex) ESP_LOGE(TAG, "Could not create HTTPS mutex; HTTPS checks will be unsafe");
    indicators_init();
    ble_init();
    pairing_button_init();
    xTaskCreate(indicators_task, "cleannet_leds", 2048, NULL, 2, NULL);
    xTaskCreate(pairing_button_task, "cleannet_pair", 2048, NULL, 2, NULL);
    xTaskCreate(internet_monitor_task, "cleannet_netcheck", 4096, NULL, 3, NULL);
    xTaskCreate(server_monitor_task, "cleannet_servercheck", 4096, NULL, 2, NULL);
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
    ESP_ERROR_CHECK(esp_wifi_set_mode(have_creds ? WIFI_MODE_STA : WIFI_MODE_APSTA));
    if (have_creds) {
        ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &sta));
    } else {
        /* First boot without saved credentials: keep provisioning AP available. */
        start_setup_ap();
    }
    /* Do not override the factory STA MAC; ESP-IDF uses the eFuse-derived address. */
    ESP_ERROR_CHECK(esp_wifi_start());
    uint8_t factory_sta_mac[6] = {0};
    if (esp_wifi_get_mac(WIFI_IF_STA, factory_sta_mac) == ESP_OK) {
        ESP_LOGI(TAG, "Permanent factory Wi-Fi MAC: %02X:%02X:%02X:%02X:%02X:%02X",
            factory_sta_mac[0], factory_sta_mac[1], factory_sta_mac[2],
            factory_sta_mac[3], factory_sta_mac[4], factory_sta_mac[5]);
    }
    start_setup_server();
    if (have_creds) ESP_ERROR_CHECK(esp_wifi_connect());
}