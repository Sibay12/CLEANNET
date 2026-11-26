# CLEANNET Shared DNS Blocklist

## Architecture

- A small emergency/default domain list remains compiled into the ESP32-C3 firmware so filtering can continue without the API.
- The complete shared domain list is stored in MongoDB Atlas in the `blocklists` collection, document `_id=global`.
- The FastAPI service exposes a public read-only device endpoint and an admin-authenticated replacement endpoint.
- Devices should keep only a bounded working/cache set in RAM or NVS. The server remains the source of truth for the complete list.

## API

### Read current list (device)

`GET /api/blocklist`

Example response:

```json
{
  "version": 3,
  "not_modified": false,
  "updated_at": "2026-11-26T12:00:00+00:00",
  "domains": ["ads.example.com", "tracker.example.net"]
}
```

A device that already has version 3 can request `GET /api/blocklist?since=3`. The response then contains `not_modified: true` and an empty domains array.

### Replace list (admin only)

`PUT /api/admin/blocklist`

Requires the existing admin session cookie. JSON body:

```json
{
  "domains": [
    "ads.example.com",
    "tracker.example.net"
  ]
}
```

The API normalizes domains to lowercase, validates DNS domain syntax, removes duplicates, atomically replaces the global list, and increments its version.

## Storage policy

Do not copy an unbounded server list into ESP32 flash. Keep the built-in safety list in firmware and use a size-limited cache for the downloaded list. The ESP32-C3 SuperMini flash size must be identified before choosing cache capacity or final partition sizes. The full list remains in MongoDB Atlas; a future admin UI can manage categories, allowlists, import/export and audit history.

## Firmware integration status

The server API is now committed, but the current ESP32 firmware does not yet fetch or apply this endpoint. That firmware integration, bounded persistent cache, retry/backoff, and hardware tests are still required. OTA remains disabled until a compiled binary for the exact board/partition layout is tested and published.
