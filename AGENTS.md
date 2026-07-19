# AGENTS.md
## Before Changes
- Performance/optimization/resource work: if `cargo run --bin xtask -- mock-deploy` lacks claimed-gain metric, update it; capture baseline before edits; claim gains only with before/after same target/config.
## Verify
- MUST pass: `cargo fmt --all -- --check`; `cargo clippy --all-targets -- -D warnings`; `cargo test`.
- Fmt fail: run `cargo fmt --all`, recheck. Windows lock: `cargo test --target-dir target/codex-test`, report.
- CSS change (`static/index.html`, `static/input.css`): `npm run build:css`; `git diff --exit-code static/tailwind.min.css`.
- JS change (`static/app.js`): `node --check static/app.js`.
- Never commit failing checks.
## Runtime Proof
- Default proof: `cargo run --bin xtask -- mock-deploy`.
- Any implementation change MUST add/update `cargo run --bin xtask -- mock-deploy` proof.
- Proof MUST verify outcome and stress changed runtime path; performance/resource claims MUST measure.
- Unit tests never replace runtime proof.
- Any change MUST use full build/deploy proof; never use `--skip-build --skip-deploy`.
- Cloudflare/ACME/HTTPS off unless `.deployenv` enables them.
## Architecture
- UI embedded via `include_str!` / `include_bytes!`; no runtime UI files.
- DNS/API hot-reload uses shared `Arc<RwLock<DomainStore>>` / `Arc<RwLock<RewriteMap>>`.
- Never hold `parking_lot` guards across `.await`; clone/copy first.
- Async DB uses `tokio::task::spawn_blocking`.
## DNS
- Normalize via `normalize_domain()`.
- DB wildcards keep `*.`; runtime wildcards store suffix.
- `build()` borrows records; records outlive `send_response`.
- Prefer `send_response` for `ResponseInfo`; fallback uses `ResponseInfo::from(Header)`.
