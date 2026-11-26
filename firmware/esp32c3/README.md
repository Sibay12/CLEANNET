# CLEANNET ESP32-C3 DNS Test Firmware

This is an initial LAN DNS filtering test firmware for ESP32-C3 SuperMini. It connects to an existing 2.4 GHz Wi-Fi router as a station, listens for DNS queries on UDP/53, returns NXDOMAIN for configured blocked domains, and forwards other queries to an upstream DNS resolver.

## Important limitations

- This is an early test build, not production firmware.
- It uses a small built-in domain blocklist. Remote blocklist updates are not implemented.
- It currently handles ordinary UDP DNS only. DNS-over-HTTPS, DNS-over-TLS, VPN DNS, hard-coded app resolvers, and IPv6 DNS can bypass it.
- Test with one phone before changing router-wide DHCP DNS.
- Some routers expose separate WAN DNS and LAN/DHCP DNS. For this test, clients must receive the ESP32 IP as their DNS server.
- The ESP32-C3 has limited RAM/CPU. This first build forwards requests sequentially and is intended for a small 4–5 device trial, not a performance guarantee.
- YouTube and first-party/in-app ads are not guaranteed to be blocked.
- Never publish your Wi-Fi password or sdkconfig file.

## Requirements

- ESP32-C3 SuperMini board and known-good USB data cable
- Windows PC
- ESP-IDF 5.x with ESP32-C3 toolchain
- 2.4 GHz Wi-Fi network (ESP32-C3 does not support 5 GHz Wi-Fi)

## Configure and build on Windows

Open ESP-IDF 5.x CMD, then:

    cd path\\to\\CLEANNET\\firmware\\esp32c3
    idf.py set-target esp32c3
    idf.py menuconfig

Under CLEANNET DNS Configuration, set your router 2.4 GHz SSID, Wi-Fi password, and upstream DNS IPv4 (default 1.1.1.1). Save and exit. Then:

    idf.py build
    idf.py -p COMx flash monitor

Replace COMx with the port shown in Windows Device Manager. If download mode does not start automatically, hold BOOT, tap RESET, release RESET, then release BOOT and retry.

## First test: one phone

1. Flash firmware and open the serial monitor.
2. Wait for the log line showing Device IP: x.x.x.x.
3. On one test phone, open the connected Wi-Fi network details. Set DNS 1 to the ESP32 IP. If Android requires Static IP mode, preserve the existing IP, gateway and prefix values exactly; change only DNS. Do not guess the ESP32 IP.
4. Browse normal sites and check the serial monitor for BLOCK domain.example lines.
5. If internet stops working, restore DNS to Automatic.

## Test 4–5 devices

After the single-phone test succeeds, reserve the ESP32 MAC/IP in the router if supported. Set the router LAN DHCP DNS/DNS server handed to clients to the ESP32 IP. Reconnect Wi-Fi on each test device. Do not change WAN/upstream DNS unless the router documentation confirms it controls client DNS.

If the router cannot advertise a custom LAN DNS address, use manual DNS on each test device or a separate router/AP that supports custom DHCP DNS.

## Restore

Set client DNS back to Automatic or restore the router's previous LAN DHCP DNS value. The ESP32 can then be unplugged without affecting normal connectivity.

## Implemented in this test build

- Wi-Fi station connection to a 2.4 GHz router
- DHCP IP address and serial logging
- UDP DNS listener on port 53
- Basic suffix-aware domain blocklist
- NXDOMAIN response for blocked domains
- Upstream DNS forwarding for allowed domains

## Not implemented

- Web setup portal / BLE provisioning
- Admin/customer device authentication and heartbeat
- Remote blocklist updates
- DNS cache and concurrent request processing
- IPv6 DNS handling
- DNS-over-TLS / DNS-over-HTTPS policy
- Signed OTA updates
- Production security hardening and hardware stress tests
