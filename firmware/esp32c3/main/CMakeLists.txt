idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS "."
    REQUIRES esp_driver_gpio esp_wifi esp_event esp_netif nvs_flash esp_http_server esp_http_client app_update mbedtls json esp_partition esp-tls led_strip bt
)
