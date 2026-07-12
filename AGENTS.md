# AGENTS.md

## Required Verification

Every code change must pass these checks before committing:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
```

Run `cargo fmt --all` before the check command if formatting is needed.

If `cargo test` cannot use the default target directory because a Windows binary is locked, rerun with an isolated target dir and report that explicitly:

```bash
cargo test --target-dir target/codex-test
```

If you changed `static/index.html` or `static/input.css`, also run:

```bash
npm run build:css
git diff --exit-code static/tailwind.min.css
```

If you changed `static/app.js`, also run:

```bash
node --check static/app.js
```

If any required check fails, fix it before committing. Do not commit failing code.

## Manual Runtime Verification

For behavior that affects deployed runtime paths, update `scripts/mock-deploy.sh` with a focused smoke check and run it after implementation.

This applies especially to:

- DNS handler behavior, blocklist/allowlist matching, rewrites, forwarding, and query logging.
- Web API changes that hot-reload runtime state.
- Auth, settings, sync, update, certificate, or HTTPS flows.
- Any bug fix that was found through deployed/manual behavior rather than only unit tests.

Use the smallest run that proves the behavior:

```bash
bash -n scripts/mock-deploy.sh
bash scripts/mock-deploy.sh --skip-build --skip-deploy
```

Run the full deploy path when the binary itself must be proven on the target host:

```bash
bash scripts/mock-deploy.sh
```

Cloudflare/ACME/HTTPS checks are disabled by default in `mock-deploy.sh`; enable them only through `.deployenv` when those integrations are intentionally under test.

## Architecture Rules

- Zero-config behavior matters: SQLite (`rustblocker.db`) is created on first run with sensible defaults.
- The Web UI is embedded with `include_str!`; do not introduce runtime file dependencies for the UI.
- DNS hot-reload reads from `Arc<RwLock<DomainStore>>` / `Arc<RwLock<RewriteMap>>`; Web API writes to the same locks.
- Lock guards from `parking_lot` are synchronous and not `Send`; never hold them across `.await`.
- SQLite uses `r2d2` + `rusqlite`; DB calls are synchronous. Use `tokio::task::spawn_blocking` when calling DB code from async contexts that can block runtime workers.
- Prefer `parking_lot::Mutex` / `parking_lot::RwLock` over `std::sync` equivalents.

## DNS Implementation Notes

- `MessageResponseBuilder::build()` takes five args: `build(metadata, answers, authorities, soa, additionals)`.
- Use `Metadata::response_from_request()` and set `metadata.response_code` directly.
- `Record` fields (`name`, `ttl`, `data`) are fields, not methods.
- `Request` derefs to `MessageRequest`; access `request.metadata` and `request.queries.queries()`.
- `NameServerConfig::udp_and_tcp(ip)` configures upstreams on port 53.
- `TokioResolver` is `Resolver<TokioRuntimeProvider>`, built with `Resolver::builder_with_config(config, TokioRuntimeProvider::default()).build()`.
- `MessageResponseBuilder::build()` borrows records; bind records to variables that outlive `send_response`.
- Wildcards are stored in DB with a `*.` prefix. Runtime `DomainStore.wildcards` stores the suffix without `*.`.
- Normalize domains by lowercasing and stripping a trailing dot with `normalize_domain()`.
- `ResponseInfo` constructors are not public except `serve_failed` within the crate; use `send_response` to obtain `ResponseInfo`.
