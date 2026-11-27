# CLEANNET ESP32-C3 Firmware (Provisioning + DNS + OTA foundation)

Firmware version: **0.2.9**  
Target: ESP32-C3 SuperMini, ESP-IDF 5.5.x.

## Features in this source revision

- Starts a protected setup Wi-Fi access point named `CLEANNET-SETUP-XXXX`.
- Derives a per-device setup password from the SoftAP MAC suffix and prints it to the serial monitor.
- Serves a mobile-friendly modular CLEANNET setup dashboard at `http://192.168.4.1`, with an embedded vector logo/illustration, network scan, password visibility toggle, and connection status feedback.
- Serves `/status` and `/api/status` on the router LAN IP; route matching ignores browser-added query strings and logs registration failures.
- Scans nearby 2.4 GHz Wi-Fi networks and displays SSID, RSSI, channel and whether the network is secured.
- Reads the immutable Factory STA MAC from ESP32-C3 eFuse and exposes it as the permanent, read-only Device ID; no router-facing MAC override is applied.
- Saves selected router SSID/password and optional cloud device token in NVS and connects as a station.
- Sends an authenticated HTTPS heartbeat every 15 minutes when internet is available and a device token has been provisioned.
- Runs the prototype DNS filter on UDP/53 after the router assigns an IP.
- Periodically checks the HTTPS Render firmware manifest.
- Downloads only HTTPS firmware URLs, checks the downloaded image SHA-256 before selecting it as the next boot image, and uses ESP-IDF OTA rollback support.
- Uses two OTA application partitions sized for the confirmed 4 MB ESP32-C3 board (`partitions_ota_4mb.csv`), plus a small reserved filesystem partition.

## First install / clean configuration

Open ESP-IDF 5.5.x CMD:

    cd path\to\CLEANNET\firmware\esp32c3
    idf.py set-target esp32c3
    idf.py fullclean
    idf.py build
    idf.py -p COM4 flash monitor

Replace COM4 with the port shown in Device Manager. The custom partition table is required for OTA. The first flash writes the new partition table and app; it may replace the existing test partition layout. Back up anything important before flashing.

After boot, serial output prints a setup SSID and password, for example:

    Setup Wi-Fi: CLEANNET-SETUP-A1B2 | Password: CNA1B2C3 | Open http://192.168.4.1

Connect a phone or PC to that setup Wi-Fi, then open **http://192.168.4.1**. Press Scan, choose the Jio AirFiber 2.4 GHz SSID, enter its password, and press Save & Connect. The setup AP remains available for future reconfiguration. Do not share the setup password or router password.

Once connected, serial output prints the device's DHCP IP address. Test DNS manually on one phone first. Do not change router-wide LAN/DHCP DNS until the one-device test passes.

## Factory MAC Device ID and cloud location heartbeat

The setup page footer displays **Factory MAC Device ID**. Firmware reads it with `esp_read_mac(..., ESP_MAC_WIFI_STA)`, which returns the eFuse-derived factory address. The existing router-facing STA MAC is left unchanged; firmware does not call `esp_wifi_set_mac()`.

### Provision the cloud heartbeat token

1. Power the ESP32-C3 and connect to its CLEANNET setup AP.
2. Copy the Factory MAC Device ID shown at the bottom of the setup page.
3. In the CLEANNET Admin Panel, register that exact MAC as the Device ID.
4. Save the one-time **device heartbeat token** returned by Admin. Do not confuse it with the separate customer claim token.
5. Reopen the local setup page, paste the device heartbeat token into **Cloud Device Token**, then press Save & Connect. The token is saved in NVS namespace `cleannet`, key `device_token`.
6. When the device has router Wi-Fi and internet, it sends a Bearer-authenticated HTTPS POST to:
   
       https://cleannet-api-qkv4.onrender.com/api/device/heartbeat

The heartbeat includes Factory MAC Device ID, firmware version, Wi-Fi state, LAN IP and DNS counters. The interval is 900 seconds (15 minutes). If no device token is configured or internet is offline, the firmware does not send a heartbeat; it retries its readiness check after 60 seconds.

The backend stores only a hash of the device token. The raw token is stored in device NVS. It is submitted to the device over the WPA2-protected local setup AP (the setup page itself uses local HTTP), then sent to the cloud only in the HTTPS Authorization header. A blocked device is rejected by the API.

### Location accuracy

The backend derives the public client IP from the Render/Cloudflare request metadata and looks it up with ipdata.co. The Admin Panel map shows approximate IP-based coordinates, not GPS. Carrier CGNAT, ISP routing, VPNs and corporate networks can make the marker inaccurate. It cannot identify an exact home/building/street. The geolocation provider attribution is shown in the Admin Panel. No GPS hardware is used.

## OTA backend configuration

The device checks:

    https://cleannet-api-qkv4.onrender.com/api/firmware/manifest

The backend returns `enabled=false` until an administrator publishes a release. To publish a release:

1. Build and test the new firmware for the exact ESP32-C3 target and OTA partition layout.
2. Create a GitHub Release and upload the generated `cleannet_esp32c3_dns.bin` as an immutable release asset.
3. Calculate SHA-256 of that exact binary (Windows: `certutil -hashfile cleannet_esp32c3_dns.bin SHA256`).
4. In the existing Render service Environment, set:
   - `FIRMWARE_ENABLED=true`
   - `FIRMWARE_VERSION` to a strictly higher semantic version (for example `0.2.1`)
   - `FIRMWARE_CHANNEL=stable`
   - `FIRMWARE_URL` to the direct HTTPS GitHub Release asset URL
   - `FIRMWARE_SHA256` to the 64-character SHA-256 hex digest
5. Save the environment changes and wait for the Render service restart. The device checks every 6 hours by default.

The device rejects non-HTTPS URLs, checks the SHA-256 digest, and only installs a semantically newer version. TLS certificate verification is enabled using the ESP certificate bundle. SHA-256 verifies transfer integrity against the HTTPS manifest; this revision does **not** implement a separate public-key signature scheme. Do not enable a release until its binary has been built and tested. Never point production devices at an untested build.

## Important limitations / test status

- This is a development/test firmware source revision. It has not yet been compiled or flashed on the owner's physical board in this revision.
- Wi-Fi provisioning currently uses a local setup AP and HTTP page. Its unique password is printed on serial; setup should be performed locally.
- NVS stores Wi-Fi credentials. NVS encryption is not configured in this revision.
- The setup page is opened manually at 192.168.4.1; captive-portal auto-popup is not implemented.
- OTA only becomes active after a real firmware asset is uploaded and the Render manifest variables are set.
- The backend's free Render service may sleep; OTA checks can be delayed while it wakes.
- The DNS proxy is an early prototype: small built-in blocklist, sequential UDP DNS forwarding, no cache/concurrency, no TCP DNS, no IPv6 DNS, no DoH/DoT enforcement. VPNs and hard-coded resolvers can bypass DNS filtering.
- YouTube, first-party and in-app ads are not guaranteed to be blocked.
- Router DHCP DNS support varies. Test one phone manually before changing the Jio AirFiber LAN/DHCP DNS. Never change WAN DNS for this test.
- Confirm actual board flash size before flashing. The 4 MB OTA layout is selected in `sdkconfig.defaults`. If an older local `sdkconfig` overrides that default, remove that generated config only after backing it up, then regenerate configuration before building. Confirm flash size before flashing.

## Restore / recovery

If Wi-Fi setup fails, reconnect to the CLEANNET setup AP and retry. If DNS filtering interrupts internet, restore the phone's DNS to Automatic. If OTA fails validation, the current firmware remains selected; rollback is enabled for an OTA image that fails to boot and is not marked valid.


## LED status indicators

The firmware now includes these provisional indicators:

| Indicator | GPIO | Meaning |
|---|---:|---|
| Green external LED | GPIO3 | Router Wi-Fi connected |
| Red external LED | GPIO4 | Router connected but internet probe failed |
| DNS activity external LED | GPIO5 | Blinks slowly at low DNS query load and faster at higher load |
| Onboard LED | GPIO8 | System heartbeat (active-low on many SuperMini boards) |

**Electrical safety:** Do not connect an external LED directly between a GPIO and GND/3V3 without a current-limiting resistor. Use a 220–330 ohm resistor in series with each external LED. Direct connection can damage the ESP32-C3 GPIO or the LED. The onboard LED is already on the module and should not receive an external series resistor.

The GPIO mapping is provisional for common ESP32-C3 SuperMini variants. Check your exact board pin labels and any existing breadboard wiring before connecting. GPIO8 is reserved for the onboard LED in this firmware. No external PAIR button is assigned in this revision.

The indicator source change has been pushed, but it must still pass the ESP-IDF build and be tested on the physical board before flashing.


## Setup dashboard design

The local setup UI is self-contained in firmware: CSS, JavaScript, inline SVG logo and decorative network illustration are embedded in `main.c`. It does not fetch remote images, fonts, or scripts, so the page remains available without internet and does not require a separate web-assets partition. The 4 MB partition map reserves two OTA slots of 0x1D0000 bytes each and a 0x40000-byte filesystem region.
