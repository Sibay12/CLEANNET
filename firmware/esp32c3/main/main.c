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
#include "driver/gpio.h"
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
static volatile uint32_t s_dns_queries_window = 0;
static volatile bool s_router_connected = false;
static volatile bool s_internet_available = false;

/* Provisional ESP32-C3 SuperMini mapping; verify board wiring before connecting LEDs. */
#define CLEANNET_LED_GREEN GPIO_NUM_3
#define CLEANNET_LED_RED GPIO_NUM_4
#define CLEANNET_LED_DNS GPIO_NUM_5
#define CLEANNET_LED_ONBOARD GPIO_NUM_8
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
        s_dns_queries_window++;
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
        "<!doctype html>"
        "<html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta name='theme-color' content='#071426'><title>CLEANNET | Device Setup</title>"
        "<style>"
        ":root{color-scheme:dark;--bg:#071426;--panel:#10233b;--panel2:#142b46;--line:#28435f;--muted:#9db2c9;--text:#f4f8fc;--cyan:#42d6cf;--blue:#5c9cff;--green:#36d399;--red:#fb7185}"
        "*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 12% 0%,#123a55 0,transparent 38%),linear-gradient(145deg,#071426,#0b1d32 65%,#101e35);font:15px system-ui,-apple-system,Segoe UI,Arial;color:var(--text);min-height:100vh;padding:22px}"
        ".shell{max-width:920px;margin:auto}.top{display:flex;align-items:center;justify-content:space-between;gap:12px;margin:4px 0 24px}.brand{display:flex;align-items:center;gap:12px}.logo{width:48px;height:48px;flex:none}.brand strong{display:block;font-size:20px;letter-spacing:2px}.brand small,.muted{color:var(--muted)}.pill{border:1px solid #28616a;background:#103b48;color:#8ff5e7;border-radius:99px;padding:7px 12px;font-size:12px}"
        ".hero{display:grid;grid-template-columns:1.2fr .8fr;gap:18px;margin-bottom:18px}.heroText,.art,.card{background:linear-gradient(145deg,#112944,#0d2037);border:1px solid var(--line);border-radius:22px;padding:24px;box-shadow:0 18px 50px #02091455}.eyebrow{color:var(--cyan);font-size:12px;font-weight:700;letter-spacing:2px;text-transform:uppercase}.hero h1{font-size:clamp(27px,5vw,42px);line-height:1.08;margin:10px 0}.hero p{color:var(--muted);line-height:1.65;margin-bottom:0}.art{display:flex;align-items:center;justify-content:center;min-height:190px;background:radial-gradient(circle at 50% 50%,#174b65,#10233b 68%)}.art svg{width:min(100%,230px);height:auto}"
        ".steps{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin:0 0 18px}.step{border:1px solid var(--line);border-radius:14px;padding:13px;background:#0e2138}.num{display:inline-grid;place-items:center;width:25px;height:25px;border-radius:8px;background:#16445a;color:var(--cyan);font-weight:800;margin-right:7px}.step b{font-size:13px}.step small{display:block;color:var(--muted);margin:7px 0 0 33px;line-height:1.4}"
        ".card h2{margin:0 0 6px;font-size:21px}.card p{color:var(--muted);margin:0 0 16px;line-height:1.5}.actions{display:flex;gap:10px;flex-wrap:wrap}button,input,select{font:inherit;border-radius:12px}button{border:0;padding:13px 17px;font-weight:750;cursor:pointer}.primary{background:linear-gradient(100deg,#23c6b9,#49a8ff);color:#041727}.secondary{background:#1a3552;color:#e8f3ff;border:1px solid #31516e}.field{margin:14px 0}.field label{display:block;font-size:13px;color:#c3d4e5;margin-bottom:7px}.field input,.field select{width:100%;padding:14px;background:#08182a;color:#fff;border:1px solid #31516e;outline:none}.field input:focus,.field select:focus{border-color:var(--cyan);box-shadow:0 0 0 3px #42d6cf22}.passwordRow{display:flex;gap:8px}.passwordRow input{flex:1;min-width:0}.passwordRow button{padding:0 14px;background:#1a3552;color:white;border:1px solid #31516e}.status{margin-top:14px;border-radius:12px;padding:12px;background:#0a1b2d;border:1px solid #28435f;color:#c8d8e8;min-height:46px}.footer{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;color:#829ab3;font-size:12px;padding:18px 4px}.hint{font-size:12px;color:var(--muted);margin-top:8px}"
        "@media(max-width:680px){body{padding:14px}.hero{grid-template-columns:1fr}.art{min-height:140px}.steps{grid-template-columns:1fr}.top{margin-bottom:16px}.heroText,.art,.card{padding:19px}}"
        "</style></head><body><div class='shell'>"
        "<header class='top'><div class='brand'><svg class='logo' viewBox='0 0 64 64' role='img' aria-label='CLEANNET logo'><defs><linearGradient id='g' x1='0' y1='0' x2='1' y2='1'><stop stop-color='#42d6cf'/><stop offset='1' stop-color='#5c9cff'/></linearGradient></defs><rect x='3' y='3' width='58' height='58' rx='18' fill='#123c55' stroke='#3d8496'/><path d='M32 10 49 17v13c0 12-7 19-17 24C22 49 15 42 15 30V17z' fill='url(#g)'/><path d='m23 32 6 6 13-15' fill='none' stroke='#062238' stroke-width='4' stroke-linecap='round' stroke-linejoin='round'/></svg><div><strong>CLEANNET</strong><small>by TAKNA TECHNOLOGY</small></div></div><span class='pill'>● DEVICE SETUP</span></header>"
        "<section class='hero'><div class='heroText'><div class='eyebrow'>Secure your home network</div><h1>Clean internet.<br>Clear control.</h1><p>Connect your CLEANNET device to your 2.4 GHz Wi-Fi network. Scan, select and connect in a few simple steps.</p></div>"
        "<div class='art' aria-hidden='true'><svg viewBox='0 0 240 180'><circle cx='120' cy='88' r='72' fill='#153e59'/><circle cx='120' cy='88' r='53' fill='none' stroke='#2a7890' stroke-width='2' stroke-dasharray='5 7'/><path d='M75 74q45-42 90 0M89 91q31-28 62 0M105 108q15-13 30 0' fill='none' stroke='#42d6cf' stroke-width='7' stroke-linecap='round'/><circle cx='120' cy='125' r='6' fill='#42d6cf'/><path d='M120 20v20M190 88h-20M50 88h20' stroke='#5c9cff' stroke-width='3' stroke-linecap='round'/><path d='m167 37 8-8m-110 8-8-8' stroke='#5c9cff' stroke-width='3' stroke-linecap='round'/></svg></div></section>"
        "<section class='steps'><div class='step'><span class='num'>1</span><b>Scan networks</b><small>Find nearby 2.4 GHz Wi-Fi.</small></div><div class='step'><span class='num'>2</span><b>Choose your Wi-Fi</b><small>Select your router network.</small></div><div class='step'><span class='num'>3</span><b>Connect CLEANNET</b><small>Enter password and save.</small></div></section>"
        "<section class='card'><h2>Connect to your router</h2><p>Choose your home network and enter its Wi-Fi password. Your credentials are saved on this device.</p>"
        "<div class='actions'><button class='primary' id='scanBtn' onclick='scan()'>⌕ &nbsp; Scan Wi-Fi networks</button></div>"
        "<div class='field'><label for='nets'>Nearby networks</label><select id='nets'><option value=''>Scan to find networks</option></select></div>"
        "<div class='field'><label for='ssid'>Wi-Fi name (SSID)</label><input id='ssid' maxlength='32' autocomplete='off' placeholder='Enter Wi-Fi name'></div>"
        "<div class='field'><label for='pw'>Wi-Fi password</label><div class='passwordRow'><input id='pw' type='password' maxlength='64' autocomplete='new-password' placeholder='Enter Wi-Fi password'><button type='button' onclick='togglePassword()'>Show</button></div><div class='hint'>Your Wi-Fi password is sent only to this CLEANNET device over its local setup connection.</div></div>"
        "<button class='primary' id='connectBtn' style='width:100%' onclick='connectNet()'>Save &amp; Connect</button><div id='msg' class='status' role='status' aria-live='polite'>Ready. Scan for nearby Wi-Fi networks to begin.</div></section>"
        "<footer class='footer'><span> CLEANNET · Device Provisioning</span><span>Local setup · 192.168.4.1</span></footer></div>"
        "<script>"
        "const $=id=>document.getElementById(id);"
        "async function scan(){const b=$('scanBtn'),m=$('msg'),s=$('nets');b.disabled=true;b.textContent='Scanning…';m.textContent='Searching for nearby networks…';try{const r=await fetch('/api/scan',{cache:'no-store'});if(!r.ok)throw new Error('HTTP '+r.status);const j=await r.json();s.innerHTML='<option value=\"\">Select a Wi-Fi network</option>';j.networks.forEach(n=>{const o=document.createElement('option');o.value=n.ssid;o.textContent=n.ssid+' · '+n.rssi+' dBm'+(n.secure?' · secured':' · open');s.appendChild(o)});m.textContent=j.networks.length+' network(s) found. Select your router.'}catch(e){m.textContent='Scan failed: '+e.message}finally{b.disabled=false;b.textContent='⌕  Scan Wi-Fi networks'}}"
        "$('nets').addEventListener('change',e=>{if(e.target.value)$('ssid').value=e.target.value});"
        "function togglePassword(){const p=$('pw'),b=p.nextElementSibling;p.type=p.type==='password'?'text':'password';b.textContent=p.type==='password'?'Show':'Hide'}"
        "async function connectNet(){const b=$('connectBtn'),m=$('msg'),ssid=$('ssid').value.trim(),password=$('pw').value;if(!ssid){m.textContent='Please enter or select your Wi-Fi name.';return}b.disabled=true;b.textContent='Connecting…';m.textContent='Saving Wi-Fi details and connecting to your router…';try{const r=await fetch('/api/connect',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ssid,password})});const j=await r.json();if(!r.ok)throw new Error(j.detail||'Connection request failed');m.textContent=j.message||'Credentials saved. Check device status.'}catch(e){m.textContent='Could not connect: '+e.message}finally{b.disabled=false;b.textContent='Save & Connect'}}"
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

static void indicators_init(void) {
    const gpio_num_t pins[] = {CLEANNET_LED_GREEN, CLEANNET_LED_RED, CLEANNET_LED_DNS, CLEANNET_LED_ONBOARD};
    for (size_t i = 0; i < sizeof(pins) / sizeof(pins[0]); i++) {
        gpio_reset_pin(pins[i]);
        ESP_ERROR_CHECK(gpio_set_direction(pins[i], GPIO_MODE_OUTPUT));
        ESP_ERROR_CHECK(gpio_set_level(pins[i], 0));
    }
}

static void indicators_task(void *arg) {
    (void)arg;
    bool dns_led = false, onboard_led = false;
    while (1) {
        gpio_set_level(CLEANNET_LED_GREEN, s_router_connected ? 1 : 0);
        gpio_set_level(CLEANNET_LED_RED, (s_router_connected && !s_internet_available) ? 1 : 0);
        uint32_t load = s_dns_queries_window;
        s_dns_queries_window = 0;
        dns_led = !dns_led;
        gpio_set_level(CLEANNET_LED_DNS, dns_led ? 1 : 0);
        onboard_led = !onboard_led;
        /* Common SuperMini onboard LED is active-low; clone polarity may differ. */
        gpio_set_level(CLEANNET_LED_ONBOARD, onboard_led ? 0 : 1);
        vTaskDelay(pdMS_TO_TICKS(load >= 20 ? 120 : 550));
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
            esp_http_client_handle_t client = esp_http_client_init(&cfg);
            if (client) {
                esp_err_t err = esp_http_client_perform(client);
                int status = esp_http_client_get_status_code(client);
                s_internet_available = (err == ESP_OK && (status == 204 || status == 200));
                esp_http_client_cleanup(client);
            } else {
                s_internet_available = false;
            }
        }
        vTaskDelay(pdMS_TO_TICKS(15000));
    }
}

static void wifi_event_handler(void *arg, esp_event_base_t base, int32_t id, void *data) {
    (void)arg;
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        s_router_connected = false;
        s_internet_available = false;
        ESP_LOGW(TAG, "Router Wi-Fi disconnected; setup AP remains available");
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)data;
        s_router_connected = true;
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
    mbedtls_sha256_context sha; mbedtls_sha256_init(&sha); mbedtls_sha256_starts(&sha, 0);
    uint8_t buffer[OTA_BUFFER_SIZE], digest[32]; int total = 0; bool ok = true;
    while (total < content_length) {
        int n = esp_http_client_read(client, (char *)buffer, sizeof(buffer));
        if (n <= 0) { ok = false; break; }
        if (esp_ota_write(handle, buffer, n) != ESP_OK) { ok = false; break; }
        mbedtls_sha256_update(&sha, buffer, n); total += n;
    }
    mbedtls_sha256_finish(&sha, digest); mbedtls_sha256_free(&sha);
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
    indicators_init();
    xTaskCreate(indicators_task, "cleannet_leds", 2048, NULL, 2, NULL);
    xTaskCreate(internet_monitor_task, "cleannet_netcheck", 4096, NULL, 3, NULL);
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
