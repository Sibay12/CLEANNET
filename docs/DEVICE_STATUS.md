# CLEANNET Live Device Status

The ESP32-C3 firmware exposes a local status page and JSON endpoint.

## Open the status page

- During provisioning, connect a phone to the CLEANNET setup Wi-Fi and open `http://192.168.4.1/status`.
- After the ESP32 joins the home router, connect a phone/computer to that same router and open `http://<ESP32-LAN-IP>/status`.
- The page refreshes every five seconds and does not require the ESP-IDF Serial Monitor.

## Information shown

Wi-Fi connection state, ESP32 LAN IPv4 address, gateway, subnet mask, router-provided DHCP DNS, internet connectivity, CLEANNET API/Render reachability, DNS listener status, total DNS requests, blocked requests, upstream failures, and firmware version.

The JSON endpoint is `/api/status`.

## Router DNS guidance

Only after the status page reports Wi-Fi connected and displays a valid ESP32 LAN IP, configure the router's LAN/DHCP DNS to use that ESP32 LAN IP as the primary DNS server. Leave the secondary DNS empty if the router permits it; a public secondary DNS can bypass filtering. Do not use the computer's IP or the router gateway as the CLEANNET DNS address.

Reserve the ESP32 IP in the router's DHCP reservation list if available, so it does not change after reboot. The firmware currently uses a DHCP-assigned IP; it does not configure a static IP itself.

## Important limitations

- Internet status is a connectivity probe; CLEANNET API status is checked separately and periodically.
- A sleeping free-tier Render service may take time to wake, so the first server check can report unavailable while it starts.
- The page reports the DNS server configured by router DHCP; it does not mean router DHCP DNS has already been changed to CLEANNET.
- The status page is local HTTP and should only be used on a trusted home network.
