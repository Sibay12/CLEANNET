# CLEANNET ESP32-C3 Firmware (Provisioning + DNS + OTA foundation)

Firmware version: **0.2.0**  
Target: ESP32-C3 SuperMini, ESP-IDF 5.5.x.

## Features in this source revision

- Starts a protected setup Wi-Fi access point named `CLEANNET-SETUP-XXXX`.
- Derives a per-device setup password from the SoftAP MAC suffix and prints it to the serial monitor.
- Serves a mobile-friendly setup page at `http://192.168.4.1`.
- Scans nearby 2.4 GHz Wi-Fi networks and displays SSID, RSSI, channel and whether the network is secured.
- Saves selected router SSID/password in NVS and connects as a station.
- Runs the prototype DNS filter on UDP/53 after the router assigns an IP.
- Periodically checks the HTTPS Render firmware manifest.
- Downloads only HTTPS firmware URLs, checks the downloaded image SHA-256 before selecting it as the next boot image, and uses ESP-IDF OTA rollback support.
- Uses two OTA application partitions; the configured layout is intended for a 2 MB flash device.

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
- Confirm actual board flash size before flashing. The configured OTA partition layout is sized for 2 MB flash. If the board reports a different size, adjust the partition table before flashing.

## Restore / recovery

If Wi-Fi setup fails, reconnect to the CLEANNET setup AP and retry. If DNS filtering interrupts internet, restore the phone's DNS to Automatic. If OTA fails validation, the current firmware remains selected; rollback is enabled for an OTA image that fails to boot and is not marked valid.
