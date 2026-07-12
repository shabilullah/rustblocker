#!/bin/bash
# RustBlocker deploy + mock test — agent-friendly mode.
# Sources .deployenv for credentials (gitignored). See .deployenv.example.
# Outputs JSON-lines: {"step":N,"name":"...","status":"ok|fail|skip","detail":"..."}
# Exit 0 = all steps pass, non-zero = at least one failure.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEPLOYENV="$SCRIPT_DIR/.deployenv"
SKIP_BUILD=false
SKIP_DEPLOY=false
TIMEOUT=30
ACME_POLL_ATTEMPTS="${ACME_POLL_ATTEMPTS:-30}"

for arg in "$@"; do
    case "$arg" in
        --skip-build)  SKIP_BUILD=true ;;
        --skip-deploy) SKIP_DEPLOY=true ;;
        --timeout=*)   TIMEOUT="${arg#*=}" ;;
        *) echo "Unknown arg: $arg"; exit 2 ;;
    esac
done

# --- Helpers ---
ok()   { printf '{"step":%s,"name":"%s","status":"ok","detail":"%s"}\n' "$1" "$2" "$3"; }
fail() { printf '{"step":%s,"name":"%s","status":"fail","detail":"%s"}\n' "$1" "$2" "$3"; FAILED=1; }
skip() { printf '{"step":%s,"name":"%s","status":"skip","detail":"%s"}\n' "$1" "$2" "$3"; }
shell_quote() { printf "'%s'" "$(printf "%s" "$1" | sed "s/'/'\\\\''/g")"; }
enabled() {
    case "${1:-false}" in
        true|TRUE|1|yes|YES|on|ON) return 0 ;;
        *) return 1 ;;
    esac
}
FAILED=0
STEP=0
step() { STEP=$((STEP+1)); }

# --- Load credentials ---
if [ ! -f "$DEPLOYENV" ]; then
    fail 0 "env" ".deployenv not found at $DEPLOYENV"
    echo "Create it from .deployenv.example and fill in your credentials."
    exit 1
fi
source "$DEPLOYENV"

: "${SSH_HOST:?}" "${SSH_USER:?}" "${SSH_PASSWORD:?}" "${WEBUI_PASSWORD:?}"
BINARY_NAME="rustblocker"
REMOTE_INSTALL_DIR="/usr/local/lib/rustblocker"
WEB_PORT="${WEB_PORT:-54}"
BASE_URL="http://${SSH_HOST}:${WEB_PORT}"
ENABLE_CLOUDFLARE_HTTPS="${ENABLE_CLOUDFLARE_HTTPS:-false}"
DB_CONCURRENCY_REQUESTS="${DB_CONCURRENCY_REQUESTS:-16}"
STATS_CONCURRENCY_REQUESTS="${STATS_CONCURRENCY_REQUESTS:-8}"
GIT_REV=$(git rev-parse --short=12 HEAD 2>/dev/null || echo "nogit")
MOCK_BUILD_ID="${MOCK_BUILD_ID:-mock-$(date +%Y%m%d%H%M%S)-${GIT_REV}}"

# SSH setup: prefer sshpass, fall back to SSH_ASKPASS (askpass.sh)
export SSHPASS="$SSH_PASSWORD"
if command -v sshpass &>/dev/null; then
    SSH=(sshpass -e ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10)
    SCP=(sshpass -e scp -o StrictHostKeyChecking=no -o ConnectTimeout=10)
elif [ -f "$SCRIPT_DIR/../askpass.bat" ]; then
    export SSH_ASKPASS="$SCRIPT_DIR/../askpass.bat"
    export DISPLAY=dummy
    export SSH_ASKPASS_REQUIRE=force
    SSH=(ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10)
    SCP=(scp -o StrictHostKeyChecking=no -o ConnectTimeout=10)
elif [ -f "$SCRIPT_DIR/../askpass.sh" ]; then
    export SSH_ASKPASS="$SCRIPT_DIR/../askpass.sh"
    export DISPLAY=dummy
    export SSH_ASKPASS_REQUIRE=force
    SSH=(ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10)
    SCP=(scp -o StrictHostKeyChecking=no -o ConnectTimeout=10)
else
    SSH=(ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10)
    SCP=(scp -o StrictHostKeyChecking=no -o ConnectTimeout=10)
fi
REMOTE="${SSH_USER}@${SSH_HOST}"
CURL=(curl -s --connect-timeout 5 --max-time "$TIMEOUT")

remote_dns_a() {
    local domain="$1"
    local quoted_domain
    quoted_domain=$(shell_quote "$domain")
    "${SSH[@]}" "$REMOTE" "domain=$quoted_domain; if command -v dig >/dev/null 2>&1; then dig @127.0.0.1 +time=2 +tries=1 +short A \"\$domain\"; elif command -v drill >/dev/null 2>&1; then drill @127.0.0.1 \"\$domain\" A | awk '/^[^;].*[[:space:]]A[[:space:]]/ { print \$NF }'; elif command -v nslookup >/dev/null 2>&1; then nslookup -type=A \"\$domain\" 127.0.0.1 | awk '/^Name:/ { answer=1 } answer && /^Address(es)?:/ { for (i=2; i<=NF; i++) if (\$i ~ /^[0-9.]+\$/) print \$i } answer && /^[[:space:]]+[0-9]+\\./ { print \$1 }'; else echo '__NO_DNS_TOOL__'; exit 3; fi"
}

target_dns_a() {
    local domain="$1"
    if command -v dig >/dev/null 2>&1; then
        dig @"$SSH_HOST" +time=2 +tries=1 +short A "$domain"
    elif command -v drill >/dev/null 2>&1; then
        drill @"$SSH_HOST" "$domain" A | awk '/^[^;].*[[:space:]]A[[:space:]]/ { print $NF }'
    elif command -v nslookup >/dev/null 2>&1; then
        nslookup -type=A "$domain" "$SSH_HOST" | awk '/^Name:/ { answer=1 } answer && /^Address(es)?:/ { for (i=2; i<=NF; i++) if ($i ~ /^[0-9.]+$/) print $i } answer && /^[[:space:]]+[0-9]+\./ { print $1 }'
    else
        remote_dns_a "$domain"
    fi
}

now_ms() {
    date +%s%3N 2>/dev/null || python3 - <<'PY'
import time
print(int(time.time() * 1000))
PY
}

json_number() {
    local key="$1"
    sed -n "s/.*\"$key\":\([0-9][0-9]*\).*/\1/p" | head -1
}

remote_root() {
    local command="$1"
    local quoted_command quoted_password
    quoted_command=$(shell_quote "$command")
    quoted_password=$(shell_quote "$SSH_PASSWORD")
    "${SSH[@]}" "$REMOTE" "if [ \"\$(id -u)\" -eq 0 ]; then sh -c $quoted_command; elif command -v sudo >/dev/null 2>&1; then printf '%s\n' $quoted_password | sudo -S sh -c $quoted_command; elif command -v doas >/dev/null 2>&1; then printf '%s\n' $quoted_password | doas sh -c $quoted_command; else echo 'root privileges required: install sudo/doas or deploy as root' >&2; exit 1; fi"
}

ensure_remote_service_defaults() {
    remote_root "if [ -f /etc/init.d/rustblocker ]; then sed -i 's#command_args=\"--dns-port 53 --db-path /var/lib/rustblocker/rustblocker.db --https --https-port 443\"#command_args=\"--dns-port 53 --db-path /var/lib/rustblocker/rustblocker.db\"#' /etc/init.d/rustblocker; elif [ -f /etc/systemd/system/rustblocker.service ]; then sed -i 's#ExecStart=/usr/local/bin/rustblocker --dns-port 53 --db-path /var/lib/rustblocker/rustblocker.db --https --https-port 443#ExecStart=/usr/local/bin/rustblocker --dns-port 53 --db-path /var/lib/rustblocker/rustblocker.db#' /etc/systemd/system/rustblocker.service; systemctl daemon-reload 2>/dev/null || true; fi"
}

REMOTE_ARCH=$("${SSH[@]}" "$REMOTE" "uname -m" 2>/dev/null || true)
case "$REMOTE_ARCH" in
    x86_64|amd64) DEPLOY_TARGET="${DEPLOY_TARGET:-x86_64-unknown-linux-musl}" ;;
    aarch64|arm64) DEPLOY_TARGET="${DEPLOY_TARGET:-aarch64-unknown-linux-musl}" ;;
    *)
        fail 0 "target" "unsupported or unknown remote architecture: ${REMOTE_ARCH:-unknown}"
        exit 1
        ;;
esac
BINARY_PATH="target/${DEPLOY_TARGET}/release/${BINARY_NAME}"

# --- Deploy ---
if [ "$SKIP_BUILD" != true ]; then
    step; ok "$STEP" "build" "building release binary with build id $MOCK_BUILD_ID..."
    if command -v cargo-zigbuild >/dev/null 2>&1; then
        BUILD_CMD=(cargo zigbuild --release --target "$DEPLOY_TARGET")
    else
        BUILD_CMD=(cargo build --release --target "$DEPLOY_TARGET")
    fi
    export RUSTBLOCKER_BUILD_ID="$MOCK_BUILD_ID"
    if ! "${BUILD_CMD[@]}" 2>&1; then
        fail "$STEP" "build" "cargo build failed"
        exit 1
    fi
    ok "$STEP" "build" "release binary built for $DEPLOY_TARGET with build id $MOCK_BUILD_ID"
else
    step; skip "$STEP" "build" "skipped"
fi

if [ ! -f "$BINARY_PATH" ]; then
    fail 0 "build" "missing binary: $BINARY_PATH"
    exit 1
fi

if [ "$SKIP_DEPLOY" != true ]; then
    step
    if remote_root "systemctl stop rustblocker 2>/dev/null || rc-service rustblocker stop 2>/dev/null || true"; then
        ok "$STEP" "deploy" "service stopped"
    else
        fail "$STEP" "deploy" "stop failed (non-fatal)"
    fi

    step
    REMOTE_TMP="/tmp/${BINARY_NAME}.$$"
    if "${SCP[@]}" "$BINARY_PATH" "${REMOTE}:${REMOTE_TMP}"; then
        ok "$STEP" "deploy" "binary uploaded"
    else
        fail "$STEP" "deploy" "scp failed"; exit 1
    fi

    step
    if remote_root "mkdir -p ${REMOTE_INSTALL_DIR} && cp ${REMOTE_TMP} ${REMOTE_INSTALL_DIR}/${BINARY_NAME} && chmod +x ${REMOTE_INSTALL_DIR}/${BINARY_NAME} && rm -f ${REMOTE_TMP}"; then
        ok "$STEP" "deploy" "binary installed"
    else
        fail "$STEP" "deploy" "install failed"; exit 1
    fi

    step
    if ensure_remote_service_defaults; then
        ok "$STEP" "deploy" "service configured for default HTTPS behavior"
    else
        fail "$STEP" "deploy" "failed to configure service defaults"; exit 1
    fi

    step
    if remote_root "systemctl start rustblocker 2>/dev/null || rc-service rustblocker start 2>/dev/null || true"; then
        ok "$STEP" "deploy" "service started"
    else
        fail "$STEP" "deploy" "start failed"; exit 1
    fi

    step
    HEALTHY=false
    for i in $(seq 1 10); do
        sleep 2
        if "${CURL[@]}" -o /dev/null -w "%{http_code}" "$BASE_URL/api/health" 2>/dev/null | grep -q '200'; then
            HEALTHY=true; break
        fi
    done
    if [ "$HEALTHY" = true ]; then
        ok "$STEP" "deploy" "health check passed (after $((i*2))s)"
    else
        fail "$STEP" "deploy" "health check failed — service did not start"
        "${SSH[@]}" "$REMOTE" "rc-service rustblocker status 2>/dev/null || systemctl status rustblocker --no-pager 2>/dev/null || true; tail -n 80 /var/log/rustblocker.log 2>/dev/null || true" >&2 || true
    fi
else
    step; skip "$STEP" "deploy" "skipped"
fi

COOKIE_JAR=$(mktemp)
trap 'rm -f "$COOKIE_JAR"' EXIT

# Step: Login
step
HTTP_CODE=$("${CURL[@]}" -o /dev/null -w "%{http_code}" -c "$COOKIE_JAR" \
    -X POST "$BASE_URL/api/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"password\":\"$WEBUI_PASSWORD\"}")
if [ "$HTTP_CODE" = "200" ]; then
    ok "$STEP" "login" "authenticated"
else
    fail "$STEP" "login" "HTTP $HTTP_CODE"
fi

# Step: Get current settings (sanity check)
step
SETTINGS=$("${CURL[@]}" -b "$COOKIE_JAR" "$BASE_URL/api/settings")
if echo "$SETTINGS" | grep -q '"'; then
    ok "$STEP" "settings" "settings endpoint reachable"
else
    fail "$STEP" "settings" "could not read settings"
fi

step
ORIGINAL_FORWARD_STRATEGY=$(echo "$SETTINGS" | sed -n 's/.*"forward_strategy":"\([^"]*\)".*/\1/p' | head -1)
ORIGINAL_FORWARD_STRATEGY="${ORIGINAL_FORWARD_STRATEGY:-adaptive}"
HTTP_CODE=$("${CURL[@]}" -o /dev/null -w "%{http_code}" -b "$COOKIE_JAR" \
    -X PUT "$BASE_URL/api/settings" \
    -H "Content-Type: application/json" \
    -d '{"key":"forward_strategy","value":"parallel"}')
SETTINGS_PARALLEL=$("${CURL[@]}" -b "$COOKIE_JAR" "$BASE_URL/api/settings")
HTTP_CODE_ADAPTIVE=$("${CURL[@]}" -o /dev/null -w "%{http_code}" -b "$COOKIE_JAR" \
    -X PUT "$BASE_URL/api/settings" \
    -H "Content-Type: application/json" \
    -d '{"key":"forward_strategy","value":"adaptive"}')
SETTINGS_ADAPTIVE=$("${CURL[@]}" -b "$COOKIE_JAR" "$BASE_URL/api/settings")
if [ "$ORIGINAL_FORWARD_STRATEGY" != "adaptive" ]; then
    "${CURL[@]}" -o /dev/null -w "%{http_code}" -b "$COOKIE_JAR" \
        -X PUT "$BASE_URL/api/settings" \
        -H "Content-Type: application/json" \
        -d "{\"key\":\"forward_strategy\",\"value\":\"$ORIGINAL_FORWARD_STRATEGY\"}" >/dev/null || true
fi
if [ "$HTTP_CODE" = "200" ] \
    && [ "$HTTP_CODE_ADAPTIVE" = "200" ] \
    && echo "$SETTINGS_PARALLEL" | grep -q '"forward_strategy":"parallel"' \
    && echo "$SETTINGS_ADAPTIVE" | grep -q '"forward_strategy":"adaptive"'; then
    ok "$STEP" "forward-strategy" "settings API switched parallel/adaptive and restored ${ORIGINAL_FORWARD_STRATEGY}"
else
    fail "$STEP" "forward-strategy" "forward strategy setting did not round-trip (parallel HTTP $HTTP_CODE, adaptive HTTP $HTTP_CODE_ADAPTIVE)"
fi

step
VERSION_JSON=$("${CURL[@]}" "$BASE_URL/api/version")
DEPLOYED_BUILD=$(echo "$VERSION_JSON" | sed -n 's/.*"build":"\([^"]*\)".*/\1/p' | head -1)
if [ "$SKIP_BUILD" != true ] && [ "$SKIP_DEPLOY" != true ] && [ "$DEPLOYED_BUILD" = "$MOCK_BUILD_ID" ]; then
    ok "$STEP" "version" "deployed mock build id matches $MOCK_BUILD_ID"
elif { [ "$SKIP_BUILD" = true ] || [ "$SKIP_DEPLOY" = true ]; } && [ -n "$DEPLOYED_BUILD" ]; then
    ok "$STEP" "version" "deployed build id is $DEPLOYED_BUILD"
else
    fail "$STEP" "version" "unexpected deployed build id '${DEPLOYED_BUILD:-missing}' (expected $MOCK_BUILD_ID; response: ${VERSION_JSON:-empty})"
fi

# Step: DB-backed API smoke checks.
step
STATS=$("${CURL[@]}" -b "$COOKIE_JAR" "$BASE_URL/api/stats")
if echo "$STATS" | grep -q '"total_queries"'; then
    ok "$STEP" "db-api" "stats endpoint reachable"
else
    fail "$STEP" "db-api" "could not read stats"
fi

step
SOURCES=$("${CURL[@]}" -b "$COOKIE_JAR" "$BASE_URL/api/sources")
if echo "$SOURCES" | grep -q '^\['; then
    ok "$STEP" "db-api" "sources endpoint reachable"
else
    fail "$STEP" "db-api" "could not read sources"
fi

# Step: Prove concurrent stats requests return complete summaries.
step
STATS_STARTED_MS=$(now_ms)
STATS_PIDS=()
STATS_OUTS=()
STATS_CODES=()
for i in $(seq 1 "$STATS_CONCURRENCY_REQUESTS"); do
    STATS_OUT=$(mktemp)
    STATS_CODE=$(mktemp)
    STATS_OUTS+=("$STATS_OUT")
    STATS_CODES+=("$STATS_CODE")
    ("${CURL[@]}" -b "$COOKIE_JAR" -o "$STATS_OUT" -w "%{http_code}" \
        "$BASE_URL/api/stats?limit=10" > "$STATS_CODE") &
    STATS_PIDS+=("$!")
done

STATS_OK=true
for pid in "${STATS_PIDS[@]}"; do
    wait "$pid" || STATS_OK=false
done

STATS_BYTES=0
for idx in "${!STATS_OUTS[@]}"; do
    STATS_HTTP_CODE=$(cat "${STATS_CODES[$idx]}" 2>/dev/null || true)
    if [ "$STATS_HTTP_CODE" != "200" ] || ! grep -q '"total_queries"' "${STATS_OUTS[$idx]}"; then
        STATS_OK=false
    fi
    BYTES=$(wc -c < "${STATS_OUTS[$idx]}" 2>/dev/null || echo 0)
    STATS_BYTES=$((STATS_BYTES + BYTES))
    rm -f "${STATS_OUTS[$idx]}" "${STATS_CODES[$idx]}"
done

if [ "$STATS_OK" = true ]; then
    STATS_ELAPSED_MS=$(( $(now_ms) - STATS_STARTED_MS ))
    ok "$STEP" "stats-concurrency" "${STATS_CONCURRENCY_REQUESTS} stats summaries completed (${STATS_BYTES} bytes, elapsed ${STATS_ELAPSED_MS}ms)"
else
    fail "$STEP" "stats-concurrency" "one or more concurrent stats summaries failed"
fi

# Step: Verify allowlist delete-by-ID path removes only the selected runtime entry.
ALLOWLIST_DELETE_DOMAIN="mock-allow-delete-$(date +%s)-$$.rustblocker.test"
ALLOWLIST_RESPONSE_FILE=$(mktemp)

step
HTTP_CODE=$("${CURL[@]}" -o "$ALLOWLIST_RESPONSE_FILE" -w "%{http_code}" -b "$COOKIE_JAR" \
    -X POST "$BASE_URL/api/allowlist" \
    -H "Content-Type: application/json" \
    -d "{\"domain\":\"$ALLOWLIST_DELETE_DOMAIN\"}")
ALLOWLIST_RESPONSE=$(cat "$ALLOWLIST_RESPONSE_FILE")
rm -f "$ALLOWLIST_RESPONSE_FILE"
ALLOWLIST_ID=$(echo "$ALLOWLIST_RESPONSE" | grep -o '"id":[0-9]*' | head -1 | cut -d: -f2)
if [ "$HTTP_CODE" = "201" ] && [ -n "$ALLOWLIST_ID" ]; then
    ok "$STEP" "allowlist-delete" "added temporary allowlist entry $ALLOWLIST_DELETE_DOMAIN (id=$ALLOWLIST_ID)"
else
    fail "$STEP" "allowlist-delete" "failed to add $ALLOWLIST_DELETE_DOMAIN (HTTP $HTTP_CODE, response: ${ALLOWLIST_RESPONSE:-empty})"
fi

step
if [ -n "${ALLOWLIST_ID:-}" ]; then
    HTTP_CODE=$("${CURL[@]}" -o /dev/null -w "%{http_code}" -b "$COOKIE_JAR" \
        -X DELETE "$BASE_URL/api/allowlist/$ALLOWLIST_ID")
    ALLOWLIST_SEARCH=$("${CURL[@]}" -b "$COOKIE_JAR" "$BASE_URL/api/allowlist?search=$ALLOWLIST_DELETE_DOMAIN&limit=5")
    if [ "$HTTP_CODE" = "200" ] && echo "$ALLOWLIST_SEARCH" | grep -q '"domains":\[\]'; then
        ok "$STEP" "allowlist-delete" "removed temporary allowlist entry id=$ALLOWLIST_ID"
    else
        fail "$STEP" "allowlist-delete" "failed to remove temporary allowlist entry id=$ALLOWLIST_ID (HTTP $HTTP_CODE, search: ${ALLOWLIST_SEARCH:-empty})"
    fi
else
    skip "$STEP" "allowlist-delete" "delete skipped because temporary entry was not created"
fi

# Step: Verify allowlisted DNS hits are persisted as allowed actions.
ALLOWLIST_STATS_DOMAIN="mock-allow-stats-$(date +%s)-$$.example.com"
ALLOWLIST_STATS_ID=""
ALLOWLIST_STATS_RESPONSE_FILE=$(mktemp)

step
STATS_BEFORE_ALLOW=$("${CURL[@]}" -b "$COOKIE_JAR" "$BASE_URL/api/stats")
ALLOWED_BEFORE=$(printf '%s\n' "$STATS_BEFORE_ALLOW" | json_number "allowed")
HTTP_CODE=$("${CURL[@]}" -o "$ALLOWLIST_STATS_RESPONSE_FILE" -w "%{http_code}" -b "$COOKIE_JAR" \
    -X POST "$BASE_URL/api/allowlist" \
    -H "Content-Type: application/json" \
    -d "{\"domain\":\"$ALLOWLIST_STATS_DOMAIN\"}")
ALLOWLIST_STATS_RESPONSE=$(cat "$ALLOWLIST_STATS_RESPONSE_FILE")
rm -f "$ALLOWLIST_STATS_RESPONSE_FILE"
ALLOWLIST_STATS_ID=$(echo "$ALLOWLIST_STATS_RESPONSE" | grep -o '"id":[0-9]*' | head -1 | cut -d: -f2)
if [ "$HTTP_CODE" = "201" ] && [ -n "$ALLOWLIST_STATS_ID" ] && [ -n "$ALLOWED_BEFORE" ]; then
    ok "$STEP" "allowlist-stats" "added temporary allowlist entry $ALLOWLIST_STATS_DOMAIN (id=$ALLOWLIST_STATS_ID, allowed before=$ALLOWED_BEFORE)"
else
    fail "$STEP" "allowlist-stats" "failed to prepare allowlist stats check (HTTP $HTTP_CODE, allowed before=${ALLOWED_BEFORE:-missing}, response: ${ALLOWLIST_STATS_RESPONSE:-empty})"
fi

step
if [ -n "${ALLOWLIST_STATS_ID:-}" ] && [ -n "${ALLOWED_BEFORE:-}" ]; then
    target_dns_a "$ALLOWLIST_STATS_DOMAIN" >/dev/null 2>&1 || true
    ALLOWLIST_STATS_OK=false
    for _ in $(seq 1 8); do
        sleep 1
        STATS_AFTER_ALLOW=$("${CURL[@]}" -b "$COOKIE_JAR" "$BASE_URL/api/stats")
        ALLOWED_AFTER=$(printf '%s\n' "$STATS_AFTER_ALLOW" | json_number "allowed")
        QUERY_LOG_AFTER=$("${CURL[@]}" -b "$COOKIE_JAR" "$BASE_URL/api/stats/queries?limit=20")
        if [ -n "$ALLOWED_AFTER" ] \
            && [ "$ALLOWED_AFTER" -gt "$ALLOWED_BEFORE" ] \
            && printf '%s\n' "$QUERY_LOG_AFTER" | tr '{' '\n' | grep -F "\"domain\":\"$ALLOWLIST_STATS_DOMAIN\"" | grep -Fq '"action":"allowed"'; then
            ALLOWLIST_STATS_OK=true
            break
        fi
    done
    if [ "$ALLOWLIST_STATS_OK" = true ]; then
        ok "$STEP" "allowlist-stats" "DNS allowlist hit persisted as allowed (allowed ${ALLOWED_BEFORE}->${ALLOWED_AFTER})"
    else
        fail "$STEP" "allowlist-stats" "allowlist DNS hit was not persisted as allowed (allowed before=${ALLOWED_BEFORE:-missing}, after=${ALLOWED_AFTER:-missing}, queries: ${QUERY_LOG_AFTER:-empty})"
    fi
    "${CURL[@]}" -o /dev/null -w "%{http_code}" -b "$COOKIE_JAR" \
        -X DELETE "$BASE_URL/api/allowlist/$ALLOWLIST_STATS_ID" >/dev/null || true
else
    skip "$STEP" "allowlist-stats" "stats check skipped because temporary entry was not created"
fi

# Step: Prove DB-heavy requests do not block Actix/Tokio progress.
step
SNAPSHOT_STARTED_MS=$(now_ms)
SNAPSHOT_PIDS=()
SNAPSHOT_OUTS=()
SNAPSHOT_CODES=()
PROBE_LOG=$(mktemp)
PROBE_STOP=$(mktemp)
rm -f "$PROBE_STOP"
(
    while [ ! -f "$PROBE_STOP" ]; do
        START_MS=$(now_ms)
        HEALTH_CODE=$(curl -s --connect-timeout 1 --max-time 2 -o /dev/null -w "%{http_code}" "$BASE_URL/api/health" 2>/dev/null || true)
        END_MS=$(now_ms)
        printf '%s %s\n' "$HEALTH_CODE" "$((END_MS - START_MS))" >> "$PROBE_LOG"
        sleep 0.05
    done
) &
PROBE_PID=$!

for i in $(seq 1 "$DB_CONCURRENCY_REQUESTS"); do
    SNAPSHOT_OUT=$(mktemp)
    SNAPSHOT_CODE=$(mktemp)
    SNAPSHOT_OUTS+=("$SNAPSHOT_OUT")
    SNAPSHOT_CODES+=("$SNAPSHOT_CODE")
    ("${CURL[@]}" -b "$COOKIE_JAR" -o "$SNAPSHOT_OUT" -w "%{http_code}" \
        "$BASE_URL/api/sync/snapshot/blocklist" > "$SNAPSHOT_CODE") &
    SNAPSHOT_PIDS+=("$!")
done

CONCURRENCY_OK=true
DNS_PROBES=0
PROBE_OVERLAPPED=false
DNS_PROBE_OUT=$(mktemp)
target_dns_a "example.com" > "$DNS_PROBE_OUT" 2>/dev/null &
DNS_PROBE_PID=$!

for i in $(seq 1 20); do
    SNAPSHOT_RUNNING=false
    for pid in "${SNAPSHOT_PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            SNAPSHOT_RUNNING=true
            break
        fi
    done
    if [ "$SNAPSHOT_RUNNING" != true ]; then
        break
    fi
    PROBE_OVERLAPPED=true
    sleep 0.05
done

for pid in "${SNAPSHOT_PIDS[@]}"; do
    wait "$pid" || CONCURRENCY_OK=false
done
touch "$PROBE_STOP"
wait "$PROBE_PID" || true
if wait "$DNS_PROBE_PID"; then
    DNS_PROBES=1
else
    CONCURRENCY_OK=false
fi
rm -f "$DNS_PROBE_OUT"

SNAPSHOT_HTTP_OK=true
SNAPSHOT_BYTES=0
for idx in "${!SNAPSHOT_OUTS[@]}"; do
    SNAPSHOT_HTTP_CODE=$(cat "${SNAPSHOT_CODES[$idx]}" 2>/dev/null || true)
    if [ "$SNAPSHOT_HTTP_CODE" != "200" ]; then
        SNAPSHOT_HTTP_OK=false
    fi
    BYTES=$(wc -c < "${SNAPSHOT_OUTS[$idx]}" 2>/dev/null || echo 0)
    SNAPSHOT_BYTES=$((SNAPSHOT_BYTES + BYTES))
    rm -f "${SNAPSHOT_OUTS[$idx]}" "${SNAPSHOT_CODES[$idx]}"
done

HEALTH_PROBES=0
MAX_HEALTH_MS=0
HEALTH_FAILURES=0
while read -r code latency; do
    [ -z "${code:-}" ] && continue
    HEALTH_PROBES=$((HEALTH_PROBES + 1))
    if [ "${latency:-0}" -gt "$MAX_HEALTH_MS" ]; then
        MAX_HEALTH_MS="$latency"
    fi
    if [ "$code" != "200" ] || [ "${latency:-0}" -gt 2000 ]; then
        HEALTH_FAILURES=$((HEALTH_FAILURES + 1))
    fi
done < "$PROBE_LOG"
rm -f "$PROBE_LOG" "$PROBE_STOP"

if [ "$HEALTH_FAILURES" -gt 0 ]; then
    CONCURRENCY_OK=false
fi

if [ "$SNAPSHOT_HTTP_OK" != true ]; then
    fail "$STEP" "db-concurrency" "one or more blocklist snapshots returned non-200"
elif [ "$PROBE_OVERLAPPED" != true ]; then
    skip "$STEP" "db-concurrency" "blocklist snapshot completed too quickly to prove concurrent responsiveness"
elif [ "$CONCURRENCY_OK" = true ]; then
    ELAPSED_MS=$(( $(now_ms) - SNAPSHOT_STARTED_MS ))
    ok "$STEP" "db-concurrency" "health/DNS responsive during ${DB_CONCURRENCY_REQUESTS} blocklist snapshots (${SNAPSHOT_BYTES} bytes, ${HEALTH_PROBES} health probes, ${DNS_PROBES} DNS probes, max health ${MAX_HEALTH_MS}ms, elapsed ${ELAPSED_MS}ms)"
else
    fail "$STEP" "db-concurrency" "health/DNS degraded during ${DB_CONCURRENCY_REQUESTS} blocklist snapshots (${HEALTH_PROBES} health probes, ${DNS_PROBES} DNS probes, max health ${MAX_HEALTH_MS}ms)"
fi

# Step: Verify bulk import hot-reloads the in-memory blocklist without restart.
SINKHOLE_IPV4=$(echo "$SETTINGS" | sed -n 's/.*"sinkhole_ipv4":"\([^"]*\)".*/\1/p' | head -1)
SINKHOLE_IPV4="${SINKHOLE_IPV4:-0.0.0.0}"
IMPORT_BASE="mock-import-$(date +%s)-$$.rustblocker.test"
IMPORT_EXACT="exact.${IMPORT_BASE}"
IMPORT_WILDCARD_BASE="wild.${IMPORT_BASE}"
IMPORT_WILDCARD_SUBDOMAIN="sub.${IMPORT_WILDCARD_BASE}"
IMPORT_RESPONSE_FILE=$(mktemp)

step
HTTP_CODE=$("${CURL[@]}" -o "$IMPORT_RESPONSE_FILE" -w "%{http_code}" -b "$COOKIE_JAR" \
    -X POST "$BASE_URL/api/blocklist/import" \
    -H "Content-Type: application/json" \
    -d "{\"content\":\"0.0.0.0 $IMPORT_EXACT\\n*.$IMPORT_WILDCARD_BASE\\n\"}")
IMPORT_RESPONSE=$(cat "$IMPORT_RESPONSE_FILE")
rm -f "$IMPORT_RESPONSE_FILE"
IMPORTED_COUNT=$(echo "$IMPORT_RESPONSE" | grep -o '"imported":[0-9]*' | head -1 | cut -d: -f2)
if [ "$HTTP_CODE" = "200" ] && [ "${IMPORTED_COUNT:-0}" -ge 2 ]; then
    ok "$STEP" "import-hot-reload" "imported temporary blocklist entries for $IMPORT_BASE"
else
    fail "$STEP" "import-hot-reload" "bulk import failed for $IMPORT_BASE (HTTP $HTTP_CODE, response: ${IMPORT_RESPONSE:-empty})"
fi

step
IMPORT_EXACT_DNS=$(target_dns_a "$IMPORT_EXACT" 2>/dev/null || true)
IMPORT_WILDCARD_DNS=$(target_dns_a "$IMPORT_WILDCARD_SUBDOMAIN" 2>/dev/null || true)
if echo "$IMPORT_EXACT_DNS" | grep -Fxq "$SINKHOLE_IPV4" \
    && echo "$IMPORT_WILDCARD_DNS" | grep -Fxq "$SINKHOLE_IPV4"; then
    ok "$STEP" "import-hot-reload" "bulk imported exact and wildcard domains resolved to sinkhole $SINKHOLE_IPV4"
else
    fail "$STEP" "import-hot-reload" "bulk imported domains were not sinkholed (exact: ${IMPORT_EXACT_DNS:-empty}; wildcard: ${IMPORT_WILDCARD_DNS:-empty})"
fi

step
LIVE_QUERY_OUT=$(mktemp)
("${CURL[@]}" --no-buffer --max-time 6 -b "$COOKIE_JAR" "$BASE_URL/api/stats/live" > "$LIVE_QUERY_OUT" 2>/dev/null || true) &
LIVE_QUERY_PID=$!
sleep 0.5
target_dns_a "$IMPORT_EXACT" >/dev/null 2>&1 || true
wait "$LIVE_QUERY_PID" || true
if grep -q "\"domain\":\"$IMPORT_EXACT\"" "$LIVE_QUERY_OUT"; then
    ok "$STEP" "query-log-live" "live SSE emitted query event for $IMPORT_EXACT"
else
    LIVE_QUERY_SAMPLE=$(head -c 200 "$LIVE_QUERY_OUT" 2>/dev/null || true)
    fail "$STEP" "query-log-live" "live SSE did not emit query event for $IMPORT_EXACT; output: ${LIVE_QUERY_SAMPLE:-empty}"
fi
rm -f "$LIVE_QUERY_OUT"

step
CLEANUP_JSON=$("${CURL[@]}" -b "$COOKIE_JAR" "$BASE_URL/api/blocklist?search=$IMPORT_BASE&limit=20")
CLEANUP_IDS=$(echo "$CLEANUP_JSON" | grep -o '"id":[0-9]*' | cut -d: -f2 || true)
CLEANUP_COUNT=0
for id in $CLEANUP_IDS; do
    HTTP_CODE=$("${CURL[@]}" -o /dev/null -w "%{http_code}" -b "$COOKIE_JAR" \
        -X DELETE "$BASE_URL/api/blocklist/$id")
    if [ "$HTTP_CODE" = "200" ]; then
        CLEANUP_COUNT=$((CLEANUP_COUNT + 1))
    fi
done
if [ "$CLEANUP_COUNT" -ge 2 ]; then
    ok "$STEP" "import-hot-reload" "removed $CLEANUP_COUNT temporary imported entries"
else
    fail "$STEP" "import-hot-reload" "cleanup removed $CLEANUP_COUNT temporary imported entries"
fi

# Step: Verify rewrite IPs are applied from the parsed runtime map.
REWRITE_DOMAIN="mock-rewrite-$(date +%s)-$$.rustblocker.test"
REWRITE_IPV4="192.0.2.123"
REWRITE_RESPONSE_FILE=$(mktemp)

step
HTTP_CODE=$("${CURL[@]}" -o "$REWRITE_RESPONSE_FILE" -w "%{http_code}" -b "$COOKIE_JAR" \
    -X POST "$BASE_URL/api/rewrites" \
    -H "Content-Type: application/json" \
    -d "{\"domain\":\"$REWRITE_DOMAIN\",\"ipv4\":\"$REWRITE_IPV4\",\"ipv6\":null}")
REWRITE_RESPONSE=$(cat "$REWRITE_RESPONSE_FILE")
rm -f "$REWRITE_RESPONSE_FILE"
REWRITE_ID=$(echo "$REWRITE_RESPONSE" | grep -o '"id":[0-9]*' | head -1 | cut -d: -f2)
if [ "$HTTP_CODE" = "201" ] && [ -n "$REWRITE_ID" ]; then
    ok "$STEP" "dns-rewrite" "added temporary rewrite $REWRITE_DOMAIN -> $REWRITE_IPV4 (id=$REWRITE_ID)"
else
    fail "$STEP" "dns-rewrite" "failed to add rewrite $REWRITE_DOMAIN (HTTP $HTTP_CODE, response: ${REWRITE_RESPONSE:-empty})"
fi

step
REWRITE_DNS=$(target_dns_a "$REWRITE_DOMAIN" 2>/dev/null || true)
if echo "$REWRITE_DNS" | grep -Fxq "$REWRITE_IPV4"; then
    ok "$STEP" "dns-rewrite" "$REWRITE_DOMAIN resolved to rewrite IP $REWRITE_IPV4"
else
    fail "$STEP" "dns-rewrite" "$REWRITE_DOMAIN did not resolve to $REWRITE_IPV4; output: ${REWRITE_DNS:-empty}"
fi

step
if [ -n "${REWRITE_ID:-}" ]; then
    HTTP_CODE=$("${CURL[@]}" -o /dev/null -w "%{http_code}" -b "$COOKIE_JAR" \
        -X DELETE "$BASE_URL/api/rewrites/$REWRITE_ID")
    if [ "$HTTP_CODE" = "200" ]; then
        ok "$STEP" "dns-rewrite" "removed temporary rewrite id=$REWRITE_ID"
    else
        fail "$STEP" "dns-rewrite" "failed to remove temporary rewrite id=$REWRITE_ID (HTTP $HTTP_CODE)"
    fi
else
    skip "$STEP" "dns-rewrite" "cleanup skipped because temporary rewrite was not created"
fi

# Step: Verify wildcard blocklist matching through the deployed DNS handler.
WILDCARD_BASE="mock-wildcard-$(date +%s)-$$.rustblocker.test"
WILDCARD_ENTRY="*.${WILDCARD_BASE}"
WILDCARD_SUBDOMAIN="sub.${WILDCARD_BASE}"
WILDCARD_RESPONSE_FILE=$(mktemp)

step
HTTP_CODE=$("${CURL[@]}" -o "$WILDCARD_RESPONSE_FILE" -w "%{http_code}" -b "$COOKIE_JAR" \
    -X POST "$BASE_URL/api/blocklist" \
    -H "Content-Type: application/json" \
    -d "{\"domain\":\"$WILDCARD_ENTRY\"}")
WILDCARD_RESPONSE=$(cat "$WILDCARD_RESPONSE_FILE")
rm -f "$WILDCARD_RESPONSE_FILE"
WILDCARD_BLOCK_ID=$(echo "$WILDCARD_RESPONSE" | grep -o '"id":[0-9]*' | head -1 | cut -d: -f2)
if [ "$HTTP_CODE" = "201" ] && [ -n "$WILDCARD_BLOCK_ID" ]; then
    ok "$STEP" "dns-wildcard" "added temporary blocklist entry $WILDCARD_ENTRY (id=$WILDCARD_BLOCK_ID)"
else
    fail "$STEP" "dns-wildcard" "failed to add $WILDCARD_ENTRY (HTTP $HTTP_CODE)"
fi

step
if DNS_SUBDOMAIN=$(remote_dns_a "$WILDCARD_SUBDOMAIN" 2>/dev/null); then
    if echo "$DNS_SUBDOMAIN" | grep -Fxq "__NO_DNS_TOOL__"; then
        fail "$STEP" "dns-wildcard" "remote host has no dig/drill/nslookup for DNS smoke test"
    elif echo "$DNS_SUBDOMAIN" | grep -Fxq "$SINKHOLE_IPV4"; then
        ok "$STEP" "dns-wildcard" "$WILDCARD_SUBDOMAIN resolved to sinkhole $SINKHOLE_IPV4"
    else
        fail "$STEP" "dns-wildcard" "$WILDCARD_SUBDOMAIN did not resolve to $SINKHOLE_IPV4; output: ${DNS_SUBDOMAIN:-empty}"
    fi
else
    fail "$STEP" "dns-wildcard" "DNS query failed for $WILDCARD_SUBDOMAIN"
fi

step
if DNS_BARE=$(remote_dns_a "$WILDCARD_BASE" 2>/dev/null); then
    if echo "$DNS_BARE" | grep -Fxq "$SINKHOLE_IPV4"; then
        fail "$STEP" "dns-wildcard" "bare wildcard base $WILDCARD_BASE incorrectly resolved to sinkhole $SINKHOLE_IPV4"
    else
        ok "$STEP" "dns-wildcard" "bare wildcard base $WILDCARD_BASE was not sinkholed"
    fi
else
    ok "$STEP" "dns-wildcard" "bare wildcard base $WILDCARD_BASE was not sinkholed (query returned no A answer)"
fi

step
if [ -n "${WILDCARD_BLOCK_ID:-}" ]; then
    HTTP_CODE=$("${CURL[@]}" -o /dev/null -w "%{http_code}" -b "$COOKIE_JAR" \
        -X DELETE "$BASE_URL/api/blocklist/$WILDCARD_BLOCK_ID")
    if [ "$HTTP_CODE" = "200" ]; then
        ok "$STEP" "dns-wildcard" "removed temporary blocklist entry id=$WILDCARD_BLOCK_ID"
    else
        fail "$STEP" "dns-wildcard" "failed to remove temporary blocklist entry id=$WILDCARD_BLOCK_ID (HTTP $HTTP_CODE)"
    fi
else
    skip "$STEP" "dns-wildcard" "cleanup skipped because temporary entry was not created"
fi

# Optional Cloudflare + HTTPS integration checks. Disabled by default because
# they require a real domain, ACME account, and Cloudflare token permissions.
if enabled "$ENABLE_CLOUDFLARE_HTTPS"; then
    # Step: Configure HTTPS settings (only if provided)
    for pair in "domain=${DOMAIN:-}" "acme_email=${ACME_EMAIL:-}" "cloudflare_api_token=${CF_TOKEN:-}" "wildcard_cert=${WILDCARD:-false}"; do
        key="${pair%%=*}"
        value="${pair#*=}"
        if [ -z "$value" ]; then
            step; skip "$STEP" "configure" "$key not set"
            continue
        fi
        step
        HTTP_CODE=$("${CURL[@]}" -o /dev/null -w "%{http_code}" -b "$COOKIE_JAR" \
            -X PUT "$BASE_URL/api/settings" \
            -H "Content-Type: application/json" \
            -d "{\"key\":\"$key\",\"value\":\"$value\"}")
        if [ "$HTTP_CODE" = "200" ]; then
            masked="${value}"
            [ ${#masked} -gt 20 ] && masked="${value:0:4}...${value: -4}"
            ok "$STEP" "configure" "$key = $masked"
        else
            fail "$STEP" "configure" "$key -> HTTP $HTTP_CODE"
        fi
    done

    # Step: Test Cloudflare connection
    if [ -n "${CF_TOKEN:-}" ]; then
        step
        RESP=$("${CURL[@]}" -b "$COOKIE_JAR" -X POST "$BASE_URL/api/cloudflare/test" \
            -H "Content-Type: application/json" \
            -d "{\"api_token\":\"$CF_TOKEN\"}")
        if echo "$RESP" | grep -q '"ok":true'; then
            ok "$STEP" "cf-test" "token valid"
        else
            ERR=$(echo "$RESP" | grep -o '"error":"[^"]*"' | head -1 | cut -d'"' -f4)
            fail "$STEP" "cf-test" "${ERR:-invalid token}"
        fi
    else
        step; skip "$STEP" "cf-test" "CF_TOKEN not set"
    fi

    # Step: Request certificate
    if [ -n "${DOMAIN:-}" ]; then
        BEFORE_CERT_PID=$("${SSH[@]}" "$REMOTE" "pgrep -f '/usr/local/lib/rustblocker/rustblocker' | head -1" 2>/dev/null || true)
        BEFORE_CERT_STATUS=$("${CURL[@]}" -b "$COOKIE_JAR" "$BASE_URL/api/acme/status" 2>/dev/null || true)
        BEFORE_CERT_RENEWED=$(echo "$BEFORE_CERT_STATUS" | grep -o '"last_renewed":[0-9]*' | cut -d: -f2)
        BEFORE_CERT_DAYS=$(echo "$BEFORE_CERT_STATUS" | grep -o '"days_remaining":[0-9]*' | cut -d: -f2)
        RENEWAL_THRESHOLD=$(echo "$BEFORE_CERT_STATUS" | grep -o '"auto_renewal_threshold_days":[0-9]*' | cut -d: -f2)
        RENEWAL_THRESHOLD="${RENEWAL_THRESHOLD:-7}"
        GOT_CERT=false
        POLL_FAILED=false
        EXPECT_RESTART=true

        if echo "$BEFORE_CERT_STATUS" | grep -q '"has_certificate":true' \
            && [ -n "$BEFORE_CERT_DAYS" ] \
            && [ "$BEFORE_CERT_DAYS" -gt "$RENEWAL_THRESHOLD" ] \
            && [ "${FORCE_ACME:-false}" != "true" ]; then
            step
            skip "$STEP" "acme-request" "valid certificate already present (${BEFORE_CERT_DAYS}d remaining); set FORCE_ACME=true to request a fresh cert"
            GOT_CERT=true
            EXPECT_RESTART=false
        else
            step
            RESP=$("${CURL[@]}" -b "$COOKIE_JAR" -X POST "$BASE_URL/api/acme/request" \
                -H "Content-Type: application/json" \
                -d "{\"domain\":\"$DOMAIN\",\"wildcard\":${WILDCARD:-false}}")
            OP_ID=$(echo "$RESP" | grep -o '"op_id":"[^"]*"' | cut -d'"' -f4)
            if [ -n "$OP_ID" ]; then
                ok "$STEP" "acme-request" "accepted op_id=$OP_ID"
            else
                fail "$STEP" "acme-request" "request rejected"
                exit 1
            fi

            # Step: Poll for certificate (default max 30 attempts = 300s)
            step
            ok "$STEP" "acme-poll" "polling for certificate (op_id=$OP_ID)..."
            for i in $(seq 1 "$ACME_POLL_ATTEMPTS"); do
                sleep 10
                STATUS=$("${CURL[@]}" -b "$COOKIE_JAR" "$BASE_URL/api/acme/status")
                if echo "$STATUS" | grep -q '"has_certificate":true'; then
                    CURRENT_RENEWED=$(echo "$STATUS" | grep -o '"last_renewed":[0-9]*' | cut -d: -f2)
                    if [ -z "$BEFORE_CERT_RENEWED" ] || { [ -n "$CURRENT_RENEWED" ] && [ "$CURRENT_RENEWED" != "$BEFORE_CERT_RENEWED" ]; }; then
                        DAYS=$(echo "$STATUS" | grep -o '"days_remaining":[0-9]*' | cut -d: -f2)
                        ok "$STEP" "acme-poll" "certificate obtained (${DAYS:-?}d remaining) after $((i*10))s"
                        GOT_CERT=true
                        break
                    fi
                fi
                if echo "$STATUS" | grep -q '"acme_error":"'; then
                    ERR=$(echo "$STATUS" | sed -n 's/.*"acme_error":"\([^"]*\)".*/\1/p' | head -1)
                    fail "$STEP" "acme-poll" "${ERR:-ACME request failed}"
                    POLL_FAILED=true
                    break
                fi
                # Log intermediate poll as info in detail
                ok "$STEP" "acme-poll" "still waiting ($((i*10))s)..." >&2
            done
            if [ "$GOT_CERT" != true ] && [ "$POLL_FAILED" != true ]; then
                fail "$STEP" "acme-poll" "timeout after $((ACME_POLL_ATTEMPTS*10))s — check Activity Log in web UI"
                "${SSH[@]}" "$REMOTE" "tail -n 120 /var/log/rustblocker.log 2>/dev/null || true" >&2 || true
            fi
        fi
        if [ "$GOT_CERT" = true ]; then
            if [ "$EXPECT_RESTART" = true ]; then
                step
                RESTARTED=false
                AFTER_CERT_PID=""
                for i in $(seq 1 20); do
                    sleep 1
                    AFTER_CERT_PID=$("${SSH[@]}" "$REMOTE" "pgrep -f '/usr/local/lib/rustblocker/rustblocker' | head -1" 2>/dev/null || true)
                    if [ -n "$BEFORE_CERT_PID" ] && [ -n "$AFTER_CERT_PID" ] && [ "$BEFORE_CERT_PID" != "$AFTER_CERT_PID" ]; then
                        RESTARTED=true; break
                    fi
                done
                if [ "$RESTARTED" = true ]; then
                    ok "$STEP" "https" "automatic restart observed (${BEFORE_CERT_PID} -> ${AFTER_CERT_PID})"
                else
                    fail "$STEP" "https" "automatic restart was not observed"
                fi
            else
                step
                skip "$STEP" "https" "automatic restart not required for existing valid certificate"
            fi

            step
            HTTPS_URL="https://${DOMAIN}/api/health"
            HTTPS_OK=false
            for i in $(seq 1 20); do
                sleep 2
                if "${CURL[@]}" -k -o /dev/null -w "%{http_code}" "$HTTPS_URL" 2>/dev/null | grep -q '200'; then
                    HTTPS_OK=true; break
                fi
            done
            if [ "$HTTPS_OK" = true ]; then
                if [ "$EXPECT_RESTART" = true ]; then
                    ok "$STEP" "https" "HTTPS health check passed after automatic restart (after $((i*2))s)"
                else
                    ok "$STEP" "https" "HTTPS health check passed (after $((i*2))s)"
                fi
            else
                fail "$STEP" "https" "HTTPS health check failed"
                "${SSH[@]}" "$REMOTE" "rc-service rustblocker status 2>/dev/null || systemctl status rustblocker --no-pager 2>/dev/null || true; tail -n 80 /var/log/rustblocker.log 2>/dev/null || true" >&2 || true
            fi
        fi
    else
        step; skip "$STEP" "acme" "DOMAIN not set"
    fi
else
    step; skip "$STEP" "cloudflare-https" "disabled; set ENABLE_CLOUDFLARE_HTTPS=true in .deployenv to run Cloudflare, ACME, and HTTPS checks"
fi

# --- Summary ---
echo ""
if [ "$FAILED" -eq 0 ]; then
    ok 99 "summary" "ALL STEPS PASSED"
else
    fail 99 "summary" "SOME STEPS FAILED — see above"
fi

exit $FAILED
