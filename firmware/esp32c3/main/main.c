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
#include "nvs_flash.h"
#include "lwip/inet.h"

#ifndef CONFIG_CLEANNET_WIFI_SSID
#define CONFIG_CLEANNET_WIFI_SSID ""
#endif
#ifndef CONFIG_CLEANNET_WIFI_PASSWORD
#define CONFIG_CLEANNET_WIFI_PASSWORD ""
#endif
#ifndef CONFIG_CLEANNET_UPSTREAM_DNS
#define CONFIG_CLEANNET_UPSTREAM_DNS "1.1.1.1"
#endif
#ifndef CONFIG_CLEANNET_DNS_TIMEOUT_MS
#define CONFIG_CLEANNET_DNS_TIMEOUT_MS 1800
#endif

#define DNS_PORT 53
#define DNS_PACKET_MAX 512
#define WIFI_MAX_RETRIES 12

static const char *TAG = "CLEANNET";
static EventGroupHandle_t s_wifi_events;
static int s_retry_num = 0;
static bool s_dns_started = false;

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
        if (n == b && strcasecmp(name, blocked) == 0) return true;
        if (n > b && name[n - b - 1] == '.' && strcasecmp(name + n - b, blocked) == 0) return true;
    }
    return false;
}

static bool get_query_name(const uint8_t *packet, size_t len, char *out, size_t out_len) {
    if (len < 17 || out_len < 2) return false;
    size_t pos = 12, used = 0;
    while (pos < len) {
        uint8_t label_len = packet[pos++];
        if (label_len == 0) {
            out[used] = '\0';
            return used > 0;
        }
        if ((label_len & 0xC0) != 0 || label_len > 63 || pos + label_len > len) return false;
        if (used && used + 1 < out_len) out[used++] = '.';
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
    response[2] = (uint8_t)(flags >> 8);
    response[3] = (uint8_t)flags;
    response[6] = response[7] = 0;
    response[8] = response[9] = 0;
    response[10] = response[11] = 0;
    sendto(sock, response, len, 0, (const struct sockaddr *)client, client_len);
}

static bool forward_dns(const uint8_t *query, size_t query_len, uint8_t *reply, size_t *reply_len) {
    int upstream = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (upstream < 0) return false;
    struct timeval timeout = {
        .tv_sec = CONFIG_CLEANNET_DNS_TIMEOUT_MS / 1000,
        .tv_usec = (CONFIG_CLEANNET_DNS_TIMEOUT_MS % 1000) * 1000
    };
    setsockopt(upstream, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    struct sockaddr_in dns = {.sin_family = AF_INET, .sin_port = htons(DNS_PORT)};
    if (inet_pton(AF_INET, CONFIG_CLEANNET_UPSTREAM_DNS, &dns.sin_addr) != 1) {
        close(upstream);
        return false;
    }
    bool ok = false;
    if (sendto(upstream, query, query_len, 0, (struct sockaddr *)&dns, sizeof(dns)) == (ssize_t)query_len) {
        ssize_t n = recvfrom(upstream, reply, DNS_PACKET_MAX, 0, NULL, NULL);
        if (n >= 12) {
            *reply_len = (size_t)n;
            ok = true;
        }
    }
    close(upstream);
    return ok;
}

static void dns_server_task(void *arg) {
    (void)arg;
    int server = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (server < 0) {
        ESP_LOGE(TAG, "Cannot create DNS socket: errno=%d", errno);
        vTaskDelete(NULL);
        return;
    }
    struct sockaddr_in local = {
        .sin_family = AF_INET, .sin_port = htons(DNS_PORT),
        .sin_addr.s_addr = htonl(INADDR_ANY)
    };
    if (bind(server, (struct sockaddr *)&local, sizeof(local)) < 0) {
        ESP_LOGE(TAG, "Cannot bind UDP port 53: errno=%d", errno);
        close(server);
        vTaskDelete(NULL);
        return;
    }
    ESP_LOGI(TAG, "DNS proxy listening on UDP port 53");
    uint8_t query[DNS_PACKET_MAX], reply[DNS_PACKET_MAX];
    while (1) {
        struct sockaddr_in client;
        socklen_t client_len = sizeof(client);
        ssize_t n = recvfrom(server, query, sizeof(query), 0, (struct sockaddr *)&client, &client_len);
        if (n < 12) continue;
        char qname[254] = {0};
        if (!get_query_name(query, (size_t)n, qname, sizeof(qname))) continue;
        if (domain_is_blocked(qname)) {
            ESP_LOGI(TAG, "BLOCK %s", qname);
            send_nxdomain(server, query, (size_t)n, &client, client_len);
            continue;
        }
        size_t reply_len = 0;
        if (forward_dns(query, (size_t)n, reply, &reply_len)) {
            sendto(server, reply, reply_len, 0, (struct sockaddr *)&client, client_len);
            ESP_LOGD(TAG, "ALLOW %s", qname);
        } else {
            ESP_LOGW(TAG, "Upstream timeout for %s", qname);
        }
    }
}

static void wifi_event_handler(void *arg, esp_event_base_t base, int32_t id, void *data) {
    (void)arg;
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        if (s_retry_num < WIFI_MAX_RETRIES) {
            esp_wifi_connect();
            s_retry_num++;
            ESP_LOGW(TAG, "Wi-Fi reconnect attempt %d/%d", s_retry_num, WIFI_MAX_RETRIES);
        } else {
            xEventGroupSetBits(s_wifi_events, BIT1);
        }
        xEventGroupClearBits(s_wifi_events, BIT0);
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)data;
        ESP_LOGI(TAG, "Wi-Fi connected. Device IP: " IPSTR, IP2STR(&event->ip_info.ip));
        ESP_LOGI(TAG, "Set router LAN/DHCP DNS to this IP only after single-device test.");
        s_retry_num = 0;
        xEventGroupSetBits(s_wifi_events, BIT0);
        if (!s_dns_started) {
            s_dns_started = true;
            xTaskCreate(dns_server_task, "cleannet_dns", 6144, NULL, 5, NULL);
        }
    }
}

static void wifi_init_sta(void) {
    s_wifi_events = xEventGroupCreate();
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL));
    wifi_config_t wifi_config = {0};
    strlcpy((char *)wifi_config.sta.ssid, CONFIG_CLEANNET_WIFI_SSID, sizeof(wifi_config.sta.ssid));
    strlcpy((char *)wifi_config.sta.password, CONFIG_CLEANNET_WIFI_PASSWORD, sizeof(wifi_config.sta.password));
    wifi_config.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
    wifi_config.sta.pmf_cfg.capable = true;
    wifi_config.sta.pmf_cfg.required = false;
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());
    EventBits_t bits = xEventGroupWaitBits(s_wifi_events, BIT0 | BIT1, pdFALSE, pdFALSE, pdMS_TO_TICKS(30000));
    if (bits & BIT0) ESP_LOGI(TAG, "CLEANNET test firmware is online.");
    else ESP_LOGE(TAG, "Wi-Fi connection failed. Check SSID/password and 2.4 GHz availability.");
}

void app_main(void) {
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);
    ESP_LOGI(TAG, "CLEANNET ESP32-C3 DNS test firmware starting");
    ESP_LOGI(TAG, "Upstream DNS: %s", CONFIG_CLEANNET_UPSTREAM_DNS);
    ESP_LOGI(TAG, "Blocklist entries: %u", (unsigned)BLOCKED_COUNT);
    if (strlen(CONFIG_CLEANNET_WIFI_SSID) == 0) {
        ESP_LOGE(TAG, "Wi-Fi SSID is empty. Run idf.py menuconfig and set CLEANNET DNS Configuration.");
        return;
    }
    wifi_init_sta();
}
