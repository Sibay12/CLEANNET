# CLEANNET OTA Release Operations

## Current architecture

- ESP32-C3 checks the public HTTPS manifest at the Render API route: GET /api/firmware/manifest?channel=stable.
- Render returns release metadata only when FIRMWARE_ENABLED=true.
- The firmware binary is hosted as an immutable GitHub Release asset, not on Render's ephemeral filesystem.
- The device requires HTTPS, verifies the binary SHA-256 against the HTTPS manifest, and uses ESP-IDF dual OTA partitions with rollback support.
- This revision does not yet use a separate asymmetric digital signature for the manifest. Treat Render environment access and GitHub release publishing permissions as sensitive.

## Publish a release

1. Build and hardware-test the exact firmware source and partition table.
2. Confirm the target board flash size is compatible with partitions_ota.csv.
3. Create a GitHub Release and upload the built cleannet_esp32c3_dns.bin.
4. Copy the direct HTTPS asset URL.
5. On Windows calculate the digest:

   ```bat
   certutil -hashfile cleannet_esp32c3_dns.bin SHA256
   ```

6. In Render Dashboard → cleannet-api-qkv4 → Environment, set:
   - FIRMWARE_ENABLED=true
   - FIRMWARE_VERSION=0.2.1 (must be greater than the firmware already installed)
   - FIRMWARE_CHANNEL=stable
   - FIRMWARE_URL=https://... (direct GitHub Release asset URL)
   - FIRMWARE_SHA256=<64 hex characters>
7. Save changes and wait for the API to restart.
8. Check the manifest endpoint in a browser. Confirm it reports the expected board, version, HTTPS URL and SHA-256.
9. Monitor one test board's serial log before enabling the same release for a wider fleet.

## Disable / rollback

Set FIRMWARE_ENABLED=false in Render to stop new OTA downloads. Do not publish an older version number to force a downgrade. If a release is faulty, disable the manifest and publish a corrected, higher semantic version after testing. ESP-IDF rollback can recover an OTA image that fails the configured boot validation; it cannot guarantee recovery from every hardware or power failure.

## Important

- Render Free services may sleep; an OTA check can be delayed while the service wakes.
- The manifest endpoint currently uses Render environment variables, not an Admin UI.
- Do not enable OTA until the binary has been built and tested on the actual ESP32-C3 board.
- The current firmware source itself still requires local compilation and physical-board validation.
