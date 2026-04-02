# Subdomain Manager (Cloudflare)

Calagopus extension for managing server subdomains in Cloudflare.

This extension includes:
- Backend extension: `backend-extensions/dev_luxxy_cloudflaresubdomain`
- Frontend extension: `frontend/extensions/dev_luxxy_cloudflaresubdomain`

## Features

- Assign one managed subdomain per server
- Cloudflare provider + managed zone/domain configuration
- Regex blacklist rules for reserved labels
- Alias rules for mapping allocation IP/IP alias to DNS target
- Record templates (including SRV support)
- Safe cleanup on assignment removal (including fallback cleanup for previously untracked records)
- Allocation picker in server UI
- Server type mapping in server UI:
  - `Minecraft` -> `SRV`
  - `Web` -> `A`

## Minecraft SRV Behavior

For Minecraft server type, SRV names are generated with:

`_minecraft._tcp.<subdomain>`

Example:
- Label: `sus`
- Base domain: `luxxy.pro`
- Resulting SRV name: `_minecraft._tcp.sus.luxxy.pro`

SRV port defaults to the selected allocation port unless explicitly overridden by a record template.

## Cloudflare Token Requirements

Use a **scoped API token** with:
- `Zone.DNS:Edit`
- `Zone.Zone:Read`

On the zones you want to manage.

## Installation / Wiring

This extension is already wired in this repo through:
- `backend-extensions/internal-list/src/lib.rs`
- `frontend/extensions/dev_luxxy_cloudflaresubdomain/src/index.ts`

If you are setting up from scratch:
1. Ensure backend extension folder exists in `backend-extensions/`.
2. Ensure frontend extension folder exists in `frontend/extensions/`.
3. Ensure backend extension is included in `backend-extensions/internal-list`.
4. Run extension migrations.
5. Rebuild/restart panel backend and frontend.

## Database Migrations

Migration path:

`database/extension-migrations/dev_luxxy_cloudflaresubdomain/20260402190000_subdomain_manager_init/`

Includes tables for:
- providers
- managed domains
- blacklist rules
- alias rules
- record templates
- assignments
- generated records
- audit events

## UI Locations

- Admin configuration is available via the extension card **Configure** action.
- Server assignment page:
  - `Server -> Subdomain`

## Effective Permissions Used

The extension currently uses built-in permissions:

- Admin routes:
  - `settings.read`
  - `settings.update`
- Server routes:
  - `allocations.read`
  - `allocations.update`

## Troubleshooting

### 1) `cloudflare ... Authentication error`
- Verify token is valid and not expired.
- Verify token has `Zone.DNS Edit` + `Zone.Zone Read`.
- Verify token has access to the specific zone.

### 2) `invalid zone identifier` / zone verification failure
- Ensure `Zone ID` is the Cloudflare zone UUID (32 hex chars), not zone name.

### 3) `SRV target must be a hostname`
- SRV target cannot be an IP.
- Use a hostname in alias/template target (for example `n4.example.com`).

### 4) Remove clicked but DNS record remained
- Current cleanup includes fallback deletion by `name + type` in Cloudflare for records that were not previously tracked.
- Retry remove once after updating extension.

### 5) Wrong SRV port
- Ensure allocation selected in server page is correct.
- SRV now defaults to selected allocation port when template port is empty.

## Development Check

For extension-only compile check:

```bash
SQLX_OFFLINE=true cargo check -p dev_luxxy_cloudflaresubdomain
```

