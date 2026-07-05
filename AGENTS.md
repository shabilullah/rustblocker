# AGENTS.md

## Verification Requirements

**Every code change MUST pass all checks before committing:**

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
```

**If you changed `static/index.html` or `static/input.css`, also verify CSS is up to date:**

```bash
npm run build:css
git diff --exit-code static/tailwind.min.css
```

If `tailwind.min.css` changed, commit the updated file. CI will fail if CSS is stale.

If any check fails, fix it before proceeding. Never commit code that fails CI.

## Architecture

- **Zero-config**: No config files. SQLite (`rustblocker.db`) created on first run with sensible defaults.
- **Web UI embedded**: `static/index.html` compiled into binary via `include_str!`. No external file dependencies.
- **Hot-reload**: DNS handler reads from `Arc<RwLock<DomainStore>>` / `Arc<RwLock<RewriteMap>>`. Web API writes to same locks. Lock guards MUST NOT cross `.await` points (parking_lot is synchronous).
- **SQLite**: `r2d2` connection pool. All DB calls synchronous via `rusqlite`. Use `tokio::task::spawn_blocking` for DB in async contexts if needed.

## Key Patterns

- Use `parking_lot::Mutex` / `parking_lot::RwLock` instead of `std::sync` equivalents
- `MessageResponseBuilder::build()` takes 5 args: `build(metadata, answers, authorities, soa, additionals)`
- `Metadata::response_from_request()` then set `metadata.response_code` directly
- `Record` fields (`name`, `ttl`, `data`) are accessed as fields, not methods
- `Request` derefs to `MessageRequest` — access via `request.metadata`, `request.queries.queries()`
- `NameServerConfig::udp_and_tcp(ip)` for upstream config (port 53 only)
- `TokioResolver` = `Resolver<TokioRuntimeProvider>`, built via `Resolver::builder_with_config(config, TokioRuntimeProvider::default()).build()`

## File Structure

| File | Purpose |
|------|---------|
| `src/config.rs` | `UpstreamConfig` and `RewriteRule` structs only |
| `src/db.rs` | SQLite schema, CRUD, `seed_defaults()`, `fetch_source()`, `refresh_source()`, source management |
| `src/stats.rs` | `QueryLog`, `QueryEntry`, `LiveQuery`, batch writer, SSE broadcast |
| `src/lists.rs` | `DomainStore` (HashSet-based), `RewriteMap`, domain matching |
| `src/handler.rs` | `DnsBlockerHandler` implementing `RequestHandler` |
| `src/forwarder.rs` | `ParallelForwarder` racing upstream resolvers |
| `src/api.rs` | REST API endpoints (actix-web handlers) |
| `src/main.rs` | Server startup, CLI args (`--dns-port`, `--web-port`), DB init, auto-refresh scheduler, DNS + web server via `tokio::select!`, security headers |
| `static/index.html` | Web UI (TailwindCSS, vanilla JS) — embedded in binary |
| `static/input.css` | Tailwind CSS source (compile with `npm run build:css`) |
| `static/tailwind.min.css` | Compiled Tailwind CSS — embedded in binary via `include_str!` |
| `tailwind.config.js` | Tailwind purge config (scans `static/**/*.html`) |
| `package.json` | Node.js dev dependencies for CSS build |

## Rules

1. Always run `cargo fmt --all` before committing
2. Always run `cargo clippy --all-targets -- -D warnings` — zero warnings allowed
3. Always run `cargo test` — all tests must pass
4. Lock guards (`parking_lot::RwLockReadGuard`, `RwLockWriteGuard`) are not `Send` — drop them before `.await`
5. `build` method on `MessageResponseBuilder` borrows records — records must outlive the `send_response` call (bind to a `let` before building)
6. Wildcards stored with `*.` prefix in DB — strip prefix when loading into `DomainStore.wildcards`, keep prefix in `DomainStore.exact` if no prefix
7. Domain normalization: lowercase, strip trailing dot via `normalize_domain()`
8. `ResponseInfo` constructors: only `serve_failed` exists (pub(crate)) — use `send_response` to get `ResponseInfo` instead

## Release

- Tag with `v*` to trigger release workflow
- Builds: `x86_64-unknown-linux-musl` (Linux/Alpine), `x86_64-pc-windows-msvc` (Windows)
- Single binary, no file dependencies (web UI embedded)
