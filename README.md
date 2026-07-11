# RustBlocker

A DNS blocker written in Rust — similar to Pi-hole but simpler. It intercepts DNS queries, applies blocklist/allowlist/rewrite rules, and forwards unblocked queries to upstream resolvers.

## Features

- **Blocklist** — block domains by exact match or wildcard (`*.example.com`)
- **Allowlist** — bypass blocklist for specific domains
- **DNS Rewrite** — return custom IPs for specific domains (local DNS overrides)
- **Parallel Forwarding** — races queries across multiple upstream resolvers, uses the first response
- **UDP + TCP** — listens on both protocols simultaneously
- **Web Management UI** — manage all settings from a browser (TailwindCSS, dark theme)
- **Query Statistics** — tracks total queries, blocked/allowed/rewritten/forwarded counts, top clients, top domains
- **Live Query Log** — real-time streaming via Server-Sent Events (SSE)
- **Configurable retention** — auto-prune old query logs (default 30 days)
- **REST API** — full CRUD for blocklists, allowlists, rewrites, settings, upstreams, and stats
- **SQLite database** — portable single-file storage, zero-config startup
- **Hot-reload** — blocklist/allowlist/rewrite changes via web UI take effect immediately
- **Auto-update sources** — add blocklist URLs, set update interval, automatic refresh on schedule
- **URL import** — import blocklists from URLs via web UI or API
- **Hosts file format** — auto-strips `0.0.0.0` / `127.0.0.1` prefixes
- **Admin password authentication** — login-protected web UI, password generated/reset via CLI (`--genpass`)
- **Security headers** — CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy
- **Replica sync** — configure a second RustBlocker as a replica; it polls a master and pulls only changed categories (hash-diffed, efficient for large blocklists)
- **HTTPS with ACME** — automatic Let's Encrypt certificate acquisition via DNS-01 challenge (Cloudflare)
- **Auto-renewal** — background scheduler renews certificates 7 days before expiry
- **Activity log** — real-time progress streaming for all operations (ACME, settings, restart) via SSE

## Quick Start

**One-line install (Alpine, Ubuntu, Debian, any Linux):**

```bash
curl -sSL https://raw.githubusercontent.com/shabilullah/rustblocker/main/scripts/install.sh | sudo bash
```

This installs the binary, sets up a system service (OpenRC or systemd), and starts it. Re-run to update.

**Uninstall:**

```bash
curl -sSL https://raw.githubusercontent.com/shabilullah/rustblocker/main/scripts/install.sh | sudo bash -s -- --uninstall
```
**Or build from source:**

```bash
# Prerequisites: Rust toolchain + Node.js (for CSS build)
npm install
npm run build:css
cargo build --release
sudo ./target/release/rustblocker
```

For cross-compiling a static Alpine/Linux binary from Windows or another host, use `cargo zigbuild`:

```bash
cargo install cargo-zigbuild
cargo zigbuild --release --target x86_64-unknown-linux-musl
```

See [Deploy on Alpine Linux](#deploy-on-alpine-linux) for the full deployment steps.

The server starts with sensible defaults:
- DNS on `0.0.0.0:53` (accessible from LAN)
- Web UI on port 54 (accessible from LAN at `http://<your-ip>:54`)
- Upstream: Google DNS (`8.8.8.8:53`)
- Sinkhole: `0.0.0.0` (IPv4) / `::` (IPv6)

Open the web UI in your browser to configure everything. All settings are stored in `rustblocker.db` (created automatically).

Port 53 requires elevated privileges — use `sudo` or run as root.

**CLI options:**
```bash
rustblocker                                    # Default: DNS 53, web 54
rustblocker --dns-port 5353 --web-port 8080    # Custom ports (useful for local dev)
sudo rustblocker --genpass                     # Generate/reset the admin password on a deployed service
rustblocker --genpass --db-path /path/to/db    # Explicit database path (local dev)
rustblocker                                      # HTTP, plus HTTPS on 443 when a valid cert exists
rustblocker --https-port 8443                   # Use a custom HTTPS port when a valid cert exists
rustblocker --force-http                        # Force HTTP-only even if HTTPS configured
```

`--genpass` auto-detects the service database at `/var/lib/rustblocker/rustblocker.db` and restarts the `rustblocker` service when run as root, so existing web sessions are invalidated immediately.

**Set or reset the admin password:**

On a deployed service (installed via `scripts/install.sh`), the database lives at `/var/lib/rustblocker/rustblocker.db` and is owned by root. Use `sudo`:

```bash
sudo rustblocker --genpass
# Prints a random password, e.g.: 7SsEWF6Gu4i1ALU5eCnAP29S
```

- The password hash is saved to `rustblocker.db`.
- `--genpass` verifies the write actually landed and errors out if it couldn't (e.g. permission denied).
- If a `rustblocker` OpenRC/systemd service is running, `--genpass` restarts it automatically so existing web sessions are invalidated immediately.
- You can run `--genpass` while the server is running; the login takes effect immediately.

For local development or a custom database location:

```bash
rustblocker --genpass --db-path /path/to/rustblocker.db
```

## Web Management UI

Available at `http://<your-server-ip>:54` (e.g., `http://192.168.1.10:54`).

The first time you open it, a login screen asks for the admin password. There is no username — only the password generated by `rustblocker --genpass`. After logging in, you can change the password from **Settings → Admin Password**.

- **Dashboard** — stats for blocked/allowed domains, rewrites, upstream servers, auto-update sources
- **Upstreams** — add/remove upstream DNS servers
- **Sources** — manage auto-update blocklist/allowlist URLs with configurable refresh intervals
- **Blocklist** — add, remove, bulk import, search/paginate blocked domains; import from URL
- **Allowlist** — add, remove, bulk import, search/paginate allowed domains; import from URL
- **Rewrites** — manage DNS rewrite rules (domain → custom IP)
- **Settings** — configure listen address, port, sinkhole IPs, upstream timeout, and replica sync config
- **HTTPS** — manage TLS certificates, ACME settings, request/renew certificates with real-time progress
- **Activity Log** — always-visible expandable panel showing live progress for all operations
- **Theme** — dark mode with TailwindCSS

Changes to blocklist, allowlist, and rewrites take effect **immediately**. Changes to settings (listen address, port, sinkhole IPs) require a restart.

## SQLite Database

RustBlocker uses SQLite (`rustblocker.db`) for all configuration:

- **Created automatically** on first run with sensible defaults
- **No config files needed** — everything is managed via web UI or API
- **Stores**: settings, upstream servers, blocklist domains, allowlist domains, rewrite rules, TLS certificates
- **Portable**: copy `rustblocker.db` to migrate all configuration

## REST API

All configuration is accessible via a REST API at `http://<listen_address>:<listen_port + 1>/api`:

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/health` | Health check (public) |
| `POST` | `/api/auth/login` | Log in with admin password (sets session cookie) |
| `POST` | `/api/auth/logout` | Clear session cookie |
| `GET` | `/api/auth/check` | Check if a session is active (public) |
| `PUT` | `/api/auth/password` | Change the admin password |
| `GET` | `/api/settings` | Get all settings |
| `PUT` | `/api/settings` | Update a setting |
| `GET` | `/api/upstreams` | List upstream servers |
| `POST` | `/api/upstreams` | Add upstream server |
| `DELETE` | `/api/upstreams/{id}` | Remove upstream server |
| `GET` | `/api/blocklist` | List blocked domains (paginated, searchable) |
| `POST` | `/api/blocklist` | Add blocked domain |
| `DELETE` | `/api/blocklist/{id}` | Remove blocked domain |
| `POST` | `/api/blocklist/import` | Bulk import blocklist (from content or URL) |
| `GET` | `/api/allowlist` | List allowed domains (paginated, searchable) |
| `POST` | `/api/allowlist` | Add allowed domain |
| `DELETE` | `/api/allowlist/{id}` | Remove allowed domain |
| `POST` | `/api/allowlist/import` | Bulk import allowlist (from content or URL) |
| `GET` | `/api/rewrites` | List DNS rewrites |
| `POST` | `/api/rewrites` | Add DNS rewrite |
| `DELETE` | `/api/rewrites/{id}` | Remove DNS rewrite |
| `GET` | `/api/sources` | List auto-update sources |
| `POST` | `/api/sources` | Add source (immediately fetches) |
| `DELETE` | `/api/sources/{id}` | Remove source |
| `POST` | `/api/sources/refresh` | Refresh all sources now |
| `GET` | `/api/stats` | Get query statistics (top clients, top domains, counts) |
| `GET` | `/api/stats/queries` | Get recent query log (paginated) |
| `GET` | `/api/stats/live` | Live query stream (SSE) |
| `DELETE` | `/api/stats` | Clear all query statistics |
| `GET` | `/api/sync/config` | Get replica sync configuration (password masked) |
| `PUT` | `/api/sync/config` | Save replica sync configuration |
| `GET` | `/api/sync/manifest` | (Master) Per-category SHA-256 hashes for change detection |
| `GET` | `/api/sync/snapshot/{category}` | (Master) Full data snapshot for one category |
| `POST` | `/api/acme/request` | Request ACME certificate (background task) |
| `POST` | `/api/acme/renew` | Force certificate renewal |
| `GET` | `/api/acme/status` | Get certificate status (domain, expiry, days remaining) |
| `GET` | `/api/activity/stream` | Activity log stream (SSE) — real-time progress for all operations |
| `POST` | `/api/cloudflare/test` | Test Cloudflare API token validity |

### Example API usage

Protected endpoints require the session cookie returned by `/api/auth/login`.

```bash
# Check health (public)
curl http://127.0.0.1:54/api/health

# Log in and save the session cookie
curl -c jar.txt -X POST http://127.0.0.1:54/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"password": "your-genpass-password"}'

# Add a blocked domain (requires session cookie)
curl -b jar.txt -X POST http://127.0.0.1:54/api/blocklist \
  -H "Content-Type: application/json" \
  -d '{"domain": "ads.example.com"}'

# Remove a blocked domain (requires session cookie)
curl -b jar.txt -X DELETE http://127.0.0.1:54/api/blocklist/1

# Get all settings (requires session cookie)
curl -b jar.txt http://127.0.0.1:54/api/settings

# Bulk import a blocklist file (requires session cookie)
curl -b jar.txt -X POST http://127.0.0.1:54/api/blocklist/import \
  -H "Content-Type: application/json" \
  -d '{"content": "0.0.0.0 ads.example.com\n0.0.0.0 tracker.example.com"}'
```

## Auto-Update Sources

RustBlocker can automatically fetch and update blocklists from URLs on a schedule. Manage sources via the **Sources** tab in the web UI.

**Adding a source:**
1. Go to the Sources tab
2. Paste a URL (e.g., `https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts`)
3. Choose type: Blocklist or Allowlist
4. Set update interval (default: 24 hours)
5. Click "Add Source"

The server immediately fetches the URL and imports all domains. On subsequent runs, it auto-refreshes stale sources every 10 minutes.

**Manual refresh:** Click "Refresh All Now" on the Sources tab or Dashboard to immediately re-fetch all sources.

**API:**
```bash
# List sources
curl http://127.0.0.1:54/api/sources

# Add a source (immediately fetches)
curl -X POST http://127.0.0.1:54/api/sources \
  -H "Content-Type: application/json" \
  -d '{"url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", "list_type": "blocklist", "update_interval_hours": 24}'

# Refresh all sources now
curl -X POST http://127.0.0.1:54/api/sources/refresh
```

## URL Import

Import blocklists directly from a URL without saving it as a source. Use the **Import URL** button on the Blocklist or Allowlist tab, or call the API:

```bash
curl -X POST http://127.0.0.1:54/api/blocklist/import \
  -H "Content-Type: application/json" \
  -d '{"url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"}'
```

This fetches the URL, parses all domains (including hosts-file format), and imports them. Use this for one-time imports; use Sources for recurring updates.

## Replica Sync

RustBlocker supports a master/replica setup where a second instance automatically mirrors all configuration from a primary instance. The replica polls the master periodically and only fetches categories (settings, upstreams, blocklist, allowlist, rewrites, sources) whose content has changed — so a 100k-domain blocklist is not re-downloaded on every poll, only when it actually changes.

### How it works

1. The master runs normally with no special configuration.
2. The replica authenticates to the master using the master's admin password, then polls `GET /api/sync/manifest` at the configured interval.
3. The manifest returns a SHA-256 hash per category. When a hash differs from the last-seen value, the replica fetches `GET /api/sync/snapshot/{category}` and applies the update atomically.
4. The in-memory DNS stores (blocklist, allowlist, rewrites) are hot-reloaded — DNS resolution on the replica reflects the change on the next query.

### Setup via the web UI

On the **replica** instance:

1. Open the web UI → **Settings** tab → scroll to **Sync (Replica Mode)**
2. Check **Enable sync (replica mode)**
3. Enter the master's URL (e.g. `http://192.168.1.1:54`)
4. Enter the master's admin password
5. Set the poll interval (default: 30 seconds)
6. Click **Save Sync Config**
7. Restart the replica (the prompt appears automatically)

After restart the replica begins syncing. The password is stored in the replica's SQLite database and is never returned by the API.

### Setup via the API

```bash
# Configure the replica to mirror http://192.168.1.1:54
curl -b jar.txt -X PUT http://192.168.1.2:54/api/sync/config \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": true,
    "master_url": "http://192.168.1.1:54",
    "password": "<master-admin-password>",
    "interval_secs": 30
  }'

# Check current sync config (password masked)
curl -b jar.txt http://192.168.1.2:54/api/sync/config
# {"enabled":true,"master_url":"http://192.168.1.1:54","password_set":true,"interval_secs":30}
```

Then restart the replica for the setting to take effect.

### What syncs and what doesn't

| Category | Synced | Notes |
|----------|--------|-------|
| Blocklist | Yes | Full replace on change |
| Allowlist | Yes | Full replace on change |
| Rewrites | Yes | Full replace on change |
| Upstreams | Yes | Hot-reloads forwarder |
| Sources | Yes | URL list only, not domain contents |
| Settings | Yes (partial) | See below |
| Listen address / port | **No** | Replica keeps its own |
| Allowed networks (ACL) | **No** | Replica keeps its own |
| Admin password | **No** | Never synced |

Settings that could lock the replica admin out (`listen_address`, `listen_port`, `allowed_networks`) or compromise credentials (`admin_password_hash`, `session_secret`, `sync_password`) are never overwritten by sync.

### CLI overrides

The DB-based sync config can be overridden at startup with CLI flags (useful for scripted deployments):

```bash
rustblocker --sync-master http://192.168.1.1:54 \
             --sync-password <master-admin-password> \
             --sync-interval 30
```

CLI flags take precedence over the stored DB config. `--sync-master` alone also bypasses the `sync_enabled` flag in the DB.


## HTTPS & ACME Certificate Management

RustBlocker supports automatic HTTPS via Let's Encrypt using the ACME protocol with Cloudflare DNS-01 challenges. Certificates are stored in the SQLite database and auto-renewed 7 days before expiry.

### Prerequisites

- A domain managed by Cloudflare (e.g., `dns.example.com`)
- A Cloudflare API token with `Zone.DNS: Edit` permission (create at [dash.cloudflare.com](https://dash.cloudflare.com) → API Tokens)
- An email address for Let's Encrypt notifications

### Setup via the web UI

1. Open the web UI → **HTTPS** tab
2. Enter your domain (e.g., `dns.example.com`)
3. Enter your ACME email (for Let's Encrypt notifications)
4. Enter your Cloudflare API token and click **Test Connection** to verify
5. Optionally enable wildcard certificate (`*.domain.com`)
6. Click **Save Settings**
7. Click **Request Certificate** — real-time progress appears in the Activity Log panel
8. After the certificate is verified and stored, RustBlocker automatically restarts so the supervised service comes back with HTTPS enabled

### Setup via the API

```bash
# Configure HTTPS settings
curl -b jar.txt -X PUT http://127.0.0.1:54/api/settings \
  -H "Content-Type: application/json" \
  -d '{"key": "domain", "value": "dns.example.com"}'

curl -b jar.txt -X PUT http://127.0.0.1:54/api/settings \
  -H "Content-Type: application/json" \
  -d '{"key": "acme_email", "value": "admin@example.com"}'

curl -b jar.txt -X PUT http://127.0.0.1:54/api/settings \
  -H "Content-Type: application/json" \
  -d '{"key": "cloudflare_api_token", "value": "your-token-here"}'

# Test the Cloudflare token
curl -b jar.txt -X POST http://127.0.0.1:54/api/cloudflare/test \
  -H "Content-Type: application/json" \
  -d '{"api_token": "your-token-here"}'

# Request a certificate (runs in background)
curl -b jar.txt -X POST http://127.0.0.1:54/api/acme/request \
  -H "Content-Type: application/json" \
  -d '{"domain": "dns.example.com", "wildcard": false}'

# Check certificate status
curl -b jar.txt http://127.0.0.1:54/api/acme/status
```

### Running with HTTPS

```bash
# Production: HTTPS is attempted automatically on port 443 when a valid cert exists.
sudo rustblocker

# Development: use a high HTTPS port when a valid cert exists.
rustblocker --https-port 8443

# HTTP-only (ignores any HTTPS configuration)
rustblocker --force-http
```

By default, RustBlocker loads the certificate from the database and binds both HTTP and HTTPS on port 443 when a valid certificate exists. If no valid certificate is found, it runs HTTP-only with a warning. Use `--https-port` to choose a different HTTPS port, or `--force-http` to disable HTTPS even when a certificate exists. After a successful certificate request or renewal, RustBlocker exits after a short delay so OpenRC/systemd restarts it and HTTPS becomes available automatically.

### Auto-renewal

A background task checks every 24 hours for certificates expiring within 7 days and automatically renews them via ACME. On startup, RustBlocker also checks and warns about soon-expiring certificates. The HTTPS tab shows whether auto-renewal is enabled and displays the active check interval and renewal threshold.

### Activity Log

The **Activity Log** panel (bottom-right corner) shows real-time progress for all operations:
- Certificate requests and renewals (every ACME step)
- Settings saves
- Server restarts
- Cloudflare connection tests

Click the panel header to expand/collapse. New entries appear with a badge counter when collapsed.

### HTTPS Settings

| Setting | Description |
|---------|-------------|
| `domain` | Primary domain for the certificate (e.g., `dns.example.com`) |
| `acme_email` | Contact email for Let's Encrypt |
| `cloudflare_api_token` | API token with `Zone.DNS:Edit` permission (masked in API responses) |
| `wildcard_cert` | `true` to request `*.domain.com + domain.com`, `false` for domain only |
| `acme_directory_url` | Let's Encrypt directory URL (defaults to production, override for staging testing) |


## Blocklist Format

One entry per line. Lines starting with `#` are comments. Supports three formats:

```
# Plain domain
ads.example.com

# Wildcard — matches sub.example.com, sub.sub.example.com
# but NOT example.com itself
*.tracking.example.com

# Hosts file format (leading IP is stripped)
0.0.0.0 ads.example.com
127.0.0.1 tracker.example.com
```

## Hot-Reload

Changes made via the web UI or API take effect **immediately** for:
- **Blocklist domains** — blocked/allowed instantly
- **Allowlist domains** — bypasses applied instantly
- **DNS rewrites** — new IPs served instantly

Changes to **settings** (listen address, port, sinkhole IPs, upstream timeout) require a server restart.

## Network Access Control

RustBlocker has two layers of access control:

| Setting | Controls | Default |
|---------|----------|---------|
| `listen_address` | OS-level bind restriction (who can connect) | `0.0.0.0` (all interfaces) |
| `allowed_networks` | Application-level ACL (who gets a response) | empty (allow all) |

Both layers must allow a client for the request to succeed. Examples:

| `listen_address` | `allowed_networks` | Result |
|---|---|---|
| `127.0.0.1` | empty | Only localhost — OS blocks everyone else |
| `0.0.0.0` | empty | Anyone on the network — no restrictions |
| `0.0.0.0` | `192.168.0.0/24` | Server binds everywhere, ACL rejects non-matching IPs |
| `127.0.0.1` | `192.168.0.0/24` | Only localhost — ACL is irrelevant, OS already restricts |

The ACL applies to **both DNS and web UI**. It is independent of the admin password login: `allowed_networks` controls which client IPs may connect, while the password controls who can use the web UI after connecting. Set `allowed_networks` via the web UI Settings tab or API:

```bash
# Restrict to local network
curl -X PUT http://127.0.0.1:54/api/settings \
  -H "Content-Type: application/json" \
  -d '{"key": "allowed_networks", "value": "192.168.0.0/24,10.0.0.0/22"}'
```

Changes take effect immediately — no restart needed.

## Default Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `listen_address` | `0.0.0.0` | Bind address (all interfaces) |
| `listen_port` | `53` | DNS listen port (web UI on port+1) |
| `sinkhole_ipv4` | `0.0.0.0` | IPv4 returned for blocked domains |
| `sinkhole_ipv6` | `::` | IPv6 returned for blocked domains |
| `log_level` | `info` | Log level (overridable via `RUST_LOG` env var) |
| `upstream_timeout_secs` | `5` | Timeout for upstream DNS queries |
| `allowed_networks` | empty | CIDR list for ACL (empty = allow all) |
| `domain` | empty | Primary domain for HTTPS certificate |
| `acme_email` | empty | Contact email for Let's Encrypt |
| `cloudflare_api_token` | empty | Cloudflare API token (masked in API responses) |
| `wildcard_cert` | `false` | Request wildcard certificate (`*.domain.com`) |
| `acme_directory_url` | Let's Encrypt production | Override for staging/testing |

## Deploy on Alpine Linux

### One-line install

```bash
curl -sSL https://raw.githubusercontent.com/shabilullah/rustblocker/main/scripts/install.sh | sudo bash
```

### Cross-compile from your machine

The easiest way to deploy or upgrade is the install script (see [One-line install](#one-line-install)). It installs the real binary under `/usr/local/lib/rustblocker/`, creates a `/usr/local/bin/rustblocker` wrapper that defaults to the service database, and sets up the service with the service database. HTTPS does not require service flags; the binary binds HTTPS on port 443 automatically when a valid certificate exists.

To build from a non-Linux host (e.g. Windows), `cargo zigbuild` is recommended:

```bash
cargo install cargo-zigbuild
cargo zigbuild --release --target x86_64-unknown-linux-musl
```

On Linux you can also use:

```bash
rustup target add x86_64-unknown-linux-musl
sudo apt-get install musl-tools   # Debian/Ubuntu
cargo build --release --target x86_64-unknown-linux-musl
```

Then copy the binary to `/usr/local/lib/rustblocker/rustblocker` and create the wrapper script from `scripts/install.sh`, or just re-run the install script to let it handle the layout.

### Agent deployment mock test

`scripts/mock-deploy.sh` is the agent-friendly end-to-end mock test for a designated deploy machine. It reads credentials from `scripts/.deployenv`, detects the remote Linux architecture, builds the matching release target, uploads the binary through `/tmp`, installs it with root privileges, logs in to the Web UI, saves ACME/Cloudflare settings, requests a certificate, verifies that RustBlocker automatically restarts after certificate storage, and verifies that HTTPS works from the binary's default HTTPS behavior.

```bash
cp scripts/.deployenv.example scripts/.deployenv
# Fill SSH_HOST, SSH_USER, SSH_PASSWORD, WEBUI_PASSWORD, DOMAIN, ACME_EMAIL, and CF_TOKEN.

bash scripts/mock-deploy.sh --timeout=45
```

Useful options:

```bash
bash scripts/mock-deploy.sh --skip-build
bash scripts/mock-deploy.sh --skip-deploy
ACME_POLL_ATTEMPTS=30 bash scripts/mock-deploy.sh --timeout=45
```

The script prints JSON-lines status records and exits non-zero on any failed step, so agents can use it as the direct verification path for certificate and HTTPS deploy work.

### Docker multi-stage build

```dockerfile
FROM rust:1.82-alpine AS builder
RUN apk add --no-cache musl-dev
WORKDIR /build
COPY . .
RUN cargo build --release --target x86_64-unknown-linux-musl

FROM alpine:3.20
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/rustblocker /usr/local/bin/
EXPOSE 53/udp 53/tcp 54/tcp
CMD ["rustblocker"]
```

```bash
docker build -t rustblocker .
docker run -d --name rustblocker \
  -p 53:53/udp -p 53:53/tcp -p 54:54 \
  rustblocker
```

### Build directly on Alpine

```bash
apk add rust cargo musl-dev
git clone https://github.com/shabilullah/rustblocker.git && cd rustblocker
cargo build --release

# Let the install script set up the wrapper, service, and data directory:
sudo ./scripts/install.sh

# Or manually: copy the binary to /usr/local/lib/rustblocker/ and create
# the /usr/local/bin/rustblocker wrapper from scripts/install.sh.
```

### Deployment directory layout

When installed via `scripts/install.sh`:

```
/usr/local/bin/
└── rustblocker              # wrapper script (injects --db-path)
/usr/local/lib/rustblocker/
└── rustblocker              # real binary
/var/lib/rustblocker/
└── rustblocker.db          # created automatically on first run
/var/log/
└── rustblocker.log
```

### DNS client configuration

Point your clients or `/etc/resolv.conf` to the RustBlocker server:

```
nameserver 127.0.0.1
```

## Testing

```bash
cargo test
```

## Architecture

```
DNS Request
     │
     ▼
 RequestHandler (handler.rs)
     │
     ├─ 1. Rewrite match?  → Return custom IP
     ├─ 2. Allowlist match? → Skip blocklist
     ├─ 3. Blocklist match? → Return sinkhole IP
     └─ 4. Forward         → Race upstream resolvers

Web UI + API (actix-web on port+1)
     │
     ├─ SQLite database (rustblocker.db)
     ├─ Hot-reload Arc<RwLock<>> stores
     ├─ Activity Log (broadcast::channel → SSE stream)
     └─ Changes take effect immediately

HTTPS (automatic when a valid certificate exists)
     │
     ├─ ACME client (instant-acme) → Let's Encrypt
     ├─ Cloudflare DNS-01 challenge (api.rs / cloudflare.rs)
     ├─ TLS via rustls (tls.rs) → bind_rustls_0_23
     └─ Auto-renewal (renewal.rs) → every 24h, 7-day threshold

Replica Sync (sync.rs — slave side)
     │
     ├─ POST /api/auth/login      → authenticate to master
     ├─ GET  /api/sync/manifest   → SHA-256 hash per category
     ├─ diff vs. last-seen hashes
     └─ GET  /api/sync/snapshot/{category} → fetch & apply only changed
```

## License

MIT OR Apache-2.0
