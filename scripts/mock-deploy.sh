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
DNS_BURST_REQUESTS="${DNS_BURST_REQUESTS:-96}"
DNS_BURST_MAX_MS="${DNS_BURST_MAX_MS:-8000}"
DNS_BURST_MAX_FAILURES="${DNS_BURST_MAX_FAILURES:-0}"
HOT_RELOAD_DNS_REQUESTS="${HOT_RELOAD_DNS_REQUESTS:-60}"
FORWARD_PROBE_DOMAIN="${FORWARD_PROBE_DOMAIN:-example.com}"
MEMORY_IMPORT_LOOPS="${MEMORY_IMPORT_LOOPS:-3}"
MEMORY_IMPORT_DOMAINS="${MEMORY_IMPORT_DOMAINS:-100}"
MEMORY_RSS_MAX_KB="${MEMORY_RSS_MAX_KB:-262144}"
MEMORY_RSS_GROWTH_MAX_KB="${MEMORY_RSS_GROWTH_MAX_KB:-65536}"
PROCESS_FD_MAX="${PROCESS_FD_MAX:-1024}"
PROCESS_THREADS_MAX="${PROCESS_THREADS_MAX:-128}"
REMOTE_DB_PATH="${REMOTE_DB_PATH:-/var/lib/rustblocker/rustblocker.db}"
MOCK_DOMAINSTORE_BASELINE="${MOCK_DOMAINSTORE_BASELINE:-true}"
DOMAINSTORE_BASELINE_DOMAINS="${DOMAINSTORE_BASELINE_DOMAINS:-10000}"
DOMAINSTORE_BASELINE_BATCH="${DOMAINSTORE_BASELINE_BATCH:-1000}"
DOMAINSTORE_BASELINE_FILE="${DOMAINSTORE_BASELINE_FILE:-target/mock-domainstore-memory-baseline.json}"
DOMAINSTORE_BASELINE_BYTES_PER_DOMAIN_MAX="${DOMAINSTORE_BASELINE_BYTES_PER_DOMAIN_MAX:-0}"
DOMAINSTORE_BASELINE_RSS_GROWTH_MAX_KB="${DOMAINSTORE_BASELINE_RSS_GROWTH_MAX_KB:-0}"
DOMAINSTORE_BASELINE_DNS_SAMPLES="${DOMAINSTORE_BASELINE_DNS_SAMPLES:-24}"
DOMAINSTORE_BASELINE_DNS_MAX_FAILURES="${DOMAINSTORE_BASELINE_DNS_MAX_FAILURES:-0}"
DOMAINSTORE_BASELINE_SETTLE_SECS="${DOMAINSTORE_BASELINE_SETTLE_SECS:-2}"
DOMAINSTORE_BASELINE_CLEANUP_METHOD="unknown"
DOMAINSTORE_BASELINE_BYTES_PER_DOMAIN=0
DOMAINSTORE_BASELINE_RSS_BEFORE_KB=0
DOMAINSTORE_BASELINE_RSS_AFTER_KB=0
DOMAINSTORE_BASELINE_RSS_GROWTH_KB=0
DOMAINSTORE_BASELINE_STATUS="not_started"
DOMAINSTORE_BASELINE_IMPORTED=0
DOMAINSTORE_BASELINE_DNS_FAILURES=0
DOMAINSTORE_BASELINE_DNS_P95_MS=0
DOMAINSTORE_BASELINE_DNS_MAX_MS=0
DOMAINSTORE_BASELINE_DNS_AVG_MS=0
DOMAINSTORE_BASELINE_DNS_SAMPLES_RUN=0
DOMAINSTORE_BASELINE_NOTE=""

MOCK_STICKY_BASELINE="${MOCK_STICKY_BASELINE:-true}"
STICKY_BASELINE_DOMAINS="${STICKY_BASELINE_DOMAINS:-5000}"
STICKY_BASELINE_KEEP="${STICKY_BASELINE_KEEP:-2500}"
STICKY_BASELINE_FILE="${STICKY_BASELINE_FILE:-target/mock-sticky-domain-baseline.json}"
STICKY_BASELINE_SETTLE_SECS="${STICKY_BASELINE_SETTLE_SECS:-2}"
STICKY_BASELINE_STATUS="not_started"
STICKY_BASELINE_NOTE=""
STICKY_BASELINE_SOURCE_ID=""
STICKY_BASELINE_RSS_BEFORE_KB=0
STICKY_BASELINE_RSS_FULL_KB=0
STICKY_BASELINE_RSS_SHRINK_KB=0
STICKY_BASELINE_RSS_RECLAIM_KB=0
STICKY_BASELINE_STICKY_DNS=0
STICKY_BASELINE_KEEP_DNS_OK=0
STICKY_BASELINE_FULL_DNS_OK=0
STICKY_BASELINE_REMOVED_DOMAIN=""
STICKY_BASELINE_KEEP_DOMAIN=""
STICKY_FULL_COUNT=0
STICKY_SHRINK_COUNT=0

# DomainStore::remove (finding 4): always-on agent smoke.
# Proves API DELETE unsticks DNS (removed/wild) while keep stays sinkholed, and
# insert/delete churn leaves no residue. Arena reclaim is unit-tested in lists.rs
# (remote smoke cannot see arena.len()). RSS is observational only.
MOCK_REMOVE_COMPACT_BASELINE=true
REMOVE_COMPACT_DOMAINS=100
REMOVE_COMPACT_KEEP=10
REMOVE_COMPACT_CHURN=40
REMOVE_COMPACT_SETTLE_SECS=1
REMOVE_COMPACT_BASELINE_FILE="target/mock-remove-compact-baseline.json"
REMOVE_COMPACT_STATUS="not_started"
REMOVE_COMPACT_NOTE=""
REMOVE_COMPACT_RSS_BEFORE_KB=0
REMOVE_COMPACT_RSS_FULL_KB=0
REMOVE_COMPACT_RSS_AFTER_DELETE_KB=0
REMOVE_COMPACT_RSS_AFTER_CHURN_KB=0
REMOVE_COMPACT_RSS_CHURN_GROWTH_KB=0
REMOVE_COMPACT_IMPORTED=0
REMOVE_COMPACT_DELETED=0
REMOVE_COMPACT_CHURN_OK=0
REMOVE_COMPACT_STICKY_DNS=0
REMOVE_COMPACT_KEEP_DNS_OK=0
REMOVE_COMPACT_REMOVED_DOMAIN=""
REMOVE_COMPACT_KEEP_DOMAIN=""

# Sync apply_domains replace_with (finding 5): always-on agent smoke.
# Spawns a temp slave against the deployed master; master shrinks blocklist;
# slave must drop removed domains from DNS (apply path uses replace_with).
MOCK_SYNC_APPLY_BASELINE=true
SYNC_APPLY_DOMAINS=80
SYNC_APPLY_KEEP=15
SYNC_APPLY_INTERVAL_SECS=2
SYNC_APPLY_SETTLE_SECS=3
SYNC_APPLY_WAIT_ATTEMPTS=20
SYNC_APPLY_SLAVE_DNS_PORT=1853
SYNC_APPLY_SLAVE_WEB_PORT=1854
SYNC_APPLY_BASELINE_FILE="target/mock-sync-apply-domains-baseline.json"
SYNC_APPLY_STATUS="not_started"
SYNC_APPLY_NOTE=""
SYNC_APPLY_SLAVE_PID=""
SYNC_APPLY_SLAVE_DB=""
SYNC_APPLY_IMPORTED=0
SYNC_APPLY_DELETED=0
SYNC_APPLY_STICKY_DNS=0
SYNC_APPLY_KEEP_DNS_OK=0
SYNC_APPLY_FULL_DNS_OK=0
SYNC_APPLY_REMOVED_DOMAIN=""
SYNC_APPLY_KEEP_DOMAIN=""
# Resolver cache floor (finding 6): always-on agent smoke + measurements.
# Measures:
#   1) hit-rate proxy: warm-pass p95 vs first-pass p95 on same domain set
#   2) heavy unique-domain p95 (many one-shot names → forced misses)
#   3) RSS before/after unique fill (observational; allocator may keep pages)
# Gates fail on SERVFAIL, absolute p95, warm slower than cold, or hit-proxy collapse.
# Unit test locks DEFAULT_CACHE_SIZE=32768; /api/version exposes it.
MOCK_RESOLVER_CACHE_BASELINE=true
RESOLVER_CACHE_BASELINE_FILE="target/mock-resolver-cache-baseline.json"
RESOLVER_CACHE_BASELINE_UNIQUE_SAMPLES=200
RESOLVER_CACHE_BASELINE_WARM_SAMPLES=48
RESOLVER_CACHE_BASELINE_HIT_ROUNDS=3
# Absolute p95 gates (ms).
RESOLVER_CACHE_P95_MAX_MS=300
RESOLVER_CACHE_WARM_P95_MAX_MS=150
RESOLVER_CACHE_HEAVY_P95_MAX_MS=350
# Warm p95 must stay at/under first-pass p95 + climb budget (hit-rate proxy).
RESOLVER_CACHE_P95_CLIMB_MAX_MS=50
# Hit proxy: warm_p95 / first_p95 must be <= this ratio (lower = more hit benefit).
# 1.0 means warm no worse than first; allow small noise via climb budget instead.
RESOLVER_CACHE_HIT_RATIO_MAX_PCT=110
RESOLVER_CACHE_BASELINE_STATUS="not_started"
RESOLVER_CACHE_BASELINE_NOTE=""
RESOLVER_CACHE_BASELINE_COLD_P95_MS=0
RESOLVER_CACHE_BASELINE_WARM_P95_MS=0
RESOLVER_CACHE_BASELINE_FIRST_P95_MS=0
RESOLVER_CACHE_BASELINE_HEAVY_P95_MS=0
RESOLVER_CACHE_BASELINE_P95_MS=0
RESOLVER_CACHE_BASELINE_MAX_MS=0
RESOLVER_CACHE_BASELINE_PREV_P95_MS=""
RESOLVER_CACHE_BASELINE_HIT_RATIO_PCT=0
RESOLVER_CACHE_BASELINE_RSS_BEFORE_KB=0
RESOLVER_CACHE_BASELINE_RSS_AFTER_HEAVY_KB=0
RESOLVER_CACHE_BASELINE_RSS_DELTA_KB=0


MOCK_STRESS_BLOCKLIST="${MOCK_STRESS_BLOCKLIST:-false}"
STRESS_INSTALL_SQLITE3="${STRESS_INSTALL_SQLITE3:-true}"
STRESS_BLOCKLIST_TIERS="${STRESS_BLOCKLIST_TIERS:-auto}"
STRESS_AUTO_START_DOMAINS="${STRESS_AUTO_START_DOMAINS:-10000}"
STRESS_AUTO_MULTIPLIER="${STRESS_AUTO_MULTIPLIER:-2}"
STRESS_AUTO_PASSES="${STRESS_AUTO_PASSES:-1}"
STRESS_AUTO_MAX_DOMAINS="${STRESS_AUTO_MAX_DOMAINS:-0}"
STRESS_BLOCKLIST_BATCH="${STRESS_BLOCKLIST_BATCH:-1000}"
STRESS_DNS_SAMPLES="${STRESS_DNS_SAMPLES:-120}"
STRESS_DNS_P95_MAX_MS="${STRESS_DNS_P95_MAX_MS:-250}"
STRESS_DNS_MAX_MS="${STRESS_DNS_MAX_MS:-1000}"
STRESS_DNS_MAX_FAILURES="${STRESS_DNS_MAX_FAILURES:-0}"
STRESS_RSS_GROWTH_MAX_KB="${STRESS_RSS_GROWTH_MAX_KB:-131072}"
STRESS_BASELINE_MIN_DOMAINS="${STRESS_BASELINE_MIN_DOMAINS:-0}"
STRESS_BASELINE_FILE="${STRESS_BASELINE_FILE:-target/mock-blocklist-stress-baseline.json}"
STRESS_API_CLEANUP_MAX_DOMAINS="${STRESS_API_CLEANUP_MAX_DOMAINS:-10000}"
STRESS_API_CLEANUP_PAGE_SIZE="${STRESS_API_CLEANUP_PAGE_SIZE:-250}"
STRESS_CLEANUP_METHOD="unknown"
STRESS_RESOLVED_TIERS="$STRESS_BLOCKLIST_TIERS"
GIT_REV=$(git rev-parse --short=12 HEAD 2>/dev/null || echo "nogit")
MOCK_BUILD_ID="${MOCK_BUILD_ID:-mock-$(date +%Y%m%d%H%M%S)-${GIT_REV}}"
RUN_TAG="mock-$(date +%s)-$$"

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

json_ids() {
    grep -o '"id":[0-9]*' | cut -d: -f2
}

has_ipv4_answer() {
    grep -Eq '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'
}

api_cleanup_blocklist_prefix() {
    local prefix="$1"
    local page_size="${2:-250}"
    local max_passes="${3:-40}"
    local cleanup_json cleanup_ids id http_code
    API_CLEANUP_DELETED=0
    for _ in $(seq 1 "$max_passes"); do
        cleanup_json=$("${CURL[@]}" -b "$COOKIE_JAR" "$BASE_URL/api/blocklist?search=$prefix&limit=$page_size")
        if printf '%s\n' "$cleanup_json" | grep -q '"domains":\[\]'; then
            return 0
        fi
        cleanup_ids=$(printf '%s\n' "$cleanup_json" | json_ids || true)
        [ -z "$cleanup_ids" ] && return 1
        for id in $cleanup_ids; do
            http_code=$("${CURL[@]}" -o /dev/null -w "%{http_code}" -b "$COOKIE_JAR" \
                -X DELETE "$BASE_URL/api/blocklist/$id")
            [ "$http_code" = "200" ] || return 1
            API_CLEANUP_DELETED=$((API_CLEANUP_DELETED + 1))
        done
    done
    return 1
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

remote_resource_snapshot() {
    local command
    command='pid=$(pidof rustblocker 2>/dev/null | awk "{print \$1}"); [ -n "$pid" ] || pid=$(pgrep -x rustblocker 2>/dev/null | head -1); [ -n "$pid" ] || exit 1; rss=$(awk "/^VmRSS:/ {print \$2}" /proc/$pid/status 2>/dev/null); threads=$(awk "/^Threads:/ {print \$2}" /proc/$pid/status 2>/dev/null); fds=$(ls /proc/$pid/fd 2>/dev/null | wc -l); printf "%s %s %s %s\n" "$pid" "${rss:-0}" "${threads:-0}" "${fds:-0}"'
    RESOURCE_SNAPSHOT=$(remote_root "$command" 2>/dev/null) || return 1
    RESOURCE_PID=$(echo "$RESOURCE_SNAPSHOT" | awk '{print $1}')
    RESOURCE_RSS_KB=$(echo "$RESOURCE_SNAPSHOT" | awk '{print $2}')
    RESOURCE_THREADS=$(echo "$RESOURCE_SNAPSHOT" | awk '{print $3}')
    RESOURCE_FDS=$(echo "$RESOURCE_SNAPSHOT" | awk '{print $4}')
}

check_resource_snapshot() {
    local label="$1"
    local base_rss="${2:-}"
    if ! remote_resource_snapshot; then
        fail "$STEP" "$label" "could not read rustblocker process resources"
        return
    fi
    local growth=0
    if [ -n "$base_rss" ]; then
        growth=$((RESOURCE_RSS_KB - base_rss))
        [ "$growth" -lt 0 ] && growth=0
    fi
    if [ "$RESOURCE_RSS_KB" -gt "$MEMORY_RSS_MAX_KB" ]; then
        fail "$STEP" "$label" "RSS ${RESOURCE_RSS_KB}KB exceeded max ${MEMORY_RSS_MAX_KB}KB (pid=$RESOURCE_PID, threads=$RESOURCE_THREADS, fds=$RESOURCE_FDS)"
    elif [ -n "$base_rss" ] && [ "$growth" -gt "$MEMORY_RSS_GROWTH_MAX_KB" ]; then
        fail "$STEP" "$label" "RSS grew ${growth}KB from baseline ${base_rss}KB, max growth ${MEMORY_RSS_GROWTH_MAX_KB}KB (rss=${RESOURCE_RSS_KB}KB)"
    elif [ "$RESOURCE_FDS" -gt "$PROCESS_FD_MAX" ]; then
        fail "$STEP" "$label" "open FDs ${RESOURCE_FDS} exceeded max ${PROCESS_FD_MAX} (pid=$RESOURCE_PID, rss=${RESOURCE_RSS_KB}KB)"
    elif [ "$RESOURCE_THREADS" -gt "$PROCESS_THREADS_MAX" ]; then
        fail "$STEP" "$label" "threads ${RESOURCE_THREADS} exceeded max ${PROCESS_THREADS_MAX} (pid=$RESOURCE_PID, rss=${RESOURCE_RSS_KB}KB)"
    else
        ok "$STEP" "$label" "pid=$RESOURCE_PID rss=${RESOURCE_RSS_KB}KB growth=${growth}KB threads=$RESOURCE_THREADS fds=$RESOURCE_FDS"
    fi
}

wait_for_health() {
    local attempts="${1:-10}"
    local delay="${2:-2}"
    local i
    for i in $(seq 1 "$attempts"); do
        if "${CURL[@]}" -o /dev/null -w "%{http_code}" "$BASE_URL/api/health" 2>/dev/null | grep -q '200'; then
            return 0
        fi
        sleep "$delay"
    done
    return 1
}

restart_remote_service() {
    remote_root "systemctl restart rustblocker 2>/dev/null || rc-service rustblocker restart 2>/dev/null"
}

stress_cleanup_blocklist() {
    local prefix="$1"
    local quoted_db quoted_prefix
    if [ "$STRESS_CLEANUP_METHOD" = "sqlite" ]; then
        quoted_db=$(shell_quote "$REMOTE_DB_PATH")
        quoted_prefix=$(shell_quote "%$prefix%")
        if remote_root "sqlite3 $quoted_db \"DELETE FROM blocklist_domains WHERE domain LIKE $quoted_prefix;\""; then
            if restart_remote_service && wait_for_health 15 2; then
                return 0
            fi
        fi
        return 1
    fi

    local deleted_total=0
    local cleanup_json cleanup_ids id http_code
    for _ in $(seq 1 200); do
        cleanup_json=$("${CURL[@]}" -b "$COOKIE_JAR" "$BASE_URL/api/blocklist?search=$prefix&limit=$STRESS_API_CLEANUP_PAGE_SIZE")
        if printf '%s\n' "$cleanup_json" | grep -q '"domains":\[\]'; then
            if restart_remote_service && wait_for_health 15 2; then
                return 0
            fi
            return 1
        fi
        cleanup_ids=$(printf '%s\n' "$cleanup_json" | json_ids || true)
        [ -z "$cleanup_ids" ] && return 1
        for id in $cleanup_ids; do
            http_code=$("${CURL[@]}" -o /dev/null -w "%{http_code}" -b "$COOKIE_JAR" \
                -X DELETE "$BASE_URL/api/blocklist/$id")
            [ "$http_code" = "200" ] || return 1
            deleted_total=$((deleted_total + 1))
            if [ "$deleted_total" -gt "$STRESS_API_CLEANUP_MAX_DOMAINS" ]; then
                return 1
            fi
        done
    done
    return 1
}

stress_max_tier() {
    local max=0 tier
    for tier in $STRESS_RESOLVED_TIERS; do
        [ "$tier" -gt "$max" ] && max="$tier"
    done
    printf '%s\n' "$max"
}

stress_baseline_last_accepted() {
    if [ -f "$STRESS_BASELINE_FILE" ]; then
        sed -n 's/.*"last_accepted_domains":[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$STRESS_BASELINE_FILE" | head -1
    fi
}

stress_resolve_tiers() {
    local current next pass tiers max
    if [ "$STRESS_BLOCKLIST_TIERS" != "auto" ]; then
        STRESS_RESOLVED_TIERS="$STRESS_BLOCKLIST_TIERS"
        return
    fi

    current=$(stress_baseline_last_accepted)
    current="${current:-0}"
    tiers=""
    max="$STRESS_AUTO_MAX_DOMAINS"
    for pass in $(seq 1 "$STRESS_AUTO_PASSES"); do
        if [ "$current" -gt 0 ]; then
            next=$((current * STRESS_AUTO_MULTIPLIER))
        else
            next="$STRESS_AUTO_START_DOMAINS"
        fi
        if [ "$max" -gt 0 ] && [ "$next" -gt "$max" ]; then
            next="$max"
        fi
        if [ "$next" -le "$current" ]; then
            break
        fi
        tiers="${tiers}${tiers:+ }$next"
        current="$next"
    done
    STRESS_RESOLVED_TIERS="${tiers:-$STRESS_AUTO_START_DOMAINS}"
}

stress_install_sqlite3() {
    remote_root "if command -v sqlite3 >/dev/null 2>&1; then exit 0; elif command -v apk >/dev/null 2>&1; then apk add --no-cache sqlite; elif command -v apt-get >/dev/null 2>&1; then DEBIAN_FRONTEND=noninteractive apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y sqlite3; elif command -v dnf >/dev/null 2>&1; then dnf install -y sqlite; elif command -v yum >/dev/null 2>&1; then yum install -y sqlite; else exit 2; fi; command -v sqlite3 >/dev/null 2>&1"
}

stress_select_cleanup_method() {
    local max_tier
    if remote_root "command -v sqlite3 >/dev/null 2>&1" >/dev/null 2>&1; then
        STRESS_CLEANUP_METHOD="sqlite"
        return 0
    fi
    if enabled "$STRESS_INSTALL_SQLITE3" && stress_install_sqlite3 >/dev/null 2>&1; then
        STRESS_CLEANUP_METHOD="sqlite"
        return 0
    fi
    max_tier=$(stress_max_tier)
    if [ "$max_tier" -le "$STRESS_API_CLEANUP_MAX_DOMAINS" ]; then
        STRESS_CLEANUP_METHOD="api"
        return 0
    fi
    STRESS_CLEANUP_METHOD="none"
    return 1
}

stress_import_blocklist_batch() {
    local base="$1"
    local start="$2"
    local count="$3"
    local payload_file response_file http_code body imported i
    payload_file=$(mktemp)
    response_file=$(mktemp)
    printf '{"content":"' > "$payload_file"
    for i in $(seq "$start" $((start + count - 1))); do
        printf '0.0.0.0 stress-%s.%s\\n' "$i" "$base" >> "$payload_file"
    done
    printf '"}' >> "$payload_file"
    http_code=$("${CURL[@]}" -o "$response_file" -w "%{http_code}" -b "$COOKIE_JAR" \
        -X POST "$BASE_URL/api/blocklist/import" \
        -H "Content-Type: application/json" \
        --data-binary "@$payload_file")
    body=$(cat "$response_file")
    rm -f "$payload_file" "$response_file"
    imported=$(printf '%s\n' "$body" | json_number "imported")
    if [ "$http_code" = "200" ] && [ "${imported:-0}" -ge "$count" ]; then
        STRESS_IMPORTED_BATCH="$imported"
        return 0
    fi
    STRESS_IMPORTED_BATCH="${imported:-0}"
    STRESS_IMPORT_ERROR="HTTP $http_code response: ${body:-empty}"
    return 1
}

stress_ensure_blocklist_size() {
    local base="$1"
    local expected="$2"
    local search total
    search=$("${CURL[@]}" -b "$COOKIE_JAR" "$BASE_URL/api/blocklist?search=$base&limit=1")
    total=$(printf '%s\n' "$search" | json_number "total")
    [ "${total:-0}" -ge "$expected" ]
}

stress_measure_dns_latency() {
    local base="$1"
    local domain_count="$2"
    local samples="$3"
    local latencies_file failures_file sorted_file sample_count i index domain start_ms end_ms elapsed answer failures
    latencies_file=$(mktemp)
    failures_file=$(mktemp)
    sorted_file=$(mktemp)
    sample_count="$samples"
    [ "$sample_count" -gt "$domain_count" ] && sample_count="$domain_count"
    [ "$sample_count" -lt 1 ] && sample_count=1
    for i in $(seq 1 "$sample_count"); do
        index=$(( ((i - 1) * domain_count / sample_count) + 1 ))
        domain="stress-${index}.${base}"
        start_ms=$(now_ms)
        answer=$(target_dns_a "$domain" 2>/dev/null || true)
        end_ms=$(now_ms)
        elapsed=$((end_ms - start_ms))
        printf '%s\n' "$elapsed" >> "$latencies_file"
        if ! printf '%s\n' "$answer" | grep -Fxq "$SINKHOLE_IPV4"; then
            printf '%s expected=%s got=%s\n' "$domain" "$SINKHOLE_IPV4" "${answer:-empty}" >> "$failures_file"
        fi
    done
    sort -n "$latencies_file" > "$sorted_file"
    failures=$(wc -l < "$failures_file" 2>/dev/null || echo 0)
    STRESS_DNS_SAMPLE_COUNT="$sample_count"
    STRESS_DNS_FAILURES="$failures"
    STRESS_DNS_MIN_MS=$(head -1 "$sorted_file" 2>/dev/null || echo 0)
    STRESS_DNS_MAX_OBSERVED_MS=$(tail -1 "$sorted_file" 2>/dev/null || echo 0)
    STRESS_DNS_AVG_MS=$(awk '{sum += $1; count += 1} END {if (count > 0) printf "%d", sum / count; else print 0}' "$latencies_file")
    STRESS_DNS_P95_MS=$(awk -v total="$sample_count" 'BEGIN {idx = int((total * 95 + 99) / 100); if (idx < 1) idx = 1} NR == idx {print; found=1} END {if (!found) print 0}' "$sorted_file")
    STRESS_DNS_FAILURE_SAMPLE=$(head -1 "$failures_file" 2>/dev/null || true)
    rm -f "$latencies_file" "$failures_file" "$sorted_file"
}

write_stress_baseline() {
    local status="$1"
    local last_ok="$2"
    local first_bad="$3"
    local rss_growth="$4"
    local dir
    dir=$(dirname "$STRESS_BASELINE_FILE")
    mkdir -p "$dir"
    cat > "$STRESS_BASELINE_FILE" <<EOF
{
  "status": "$status",
  "git_rev": "$GIT_REV",
  "target": "$SSH_HOST",
  "tier_mode": "$STRESS_BLOCKLIST_TIERS",
  "tiers": "$STRESS_RESOLVED_TIERS",
  "last_accepted_domains": $last_ok,
  "first_rejected_domains": $first_bad,
  "dns_samples": ${STRESS_DNS_SAMPLE_COUNT:-0},
  "dns_p95_ms": ${STRESS_DNS_P95_MS:-0},
  "dns_max_ms": ${STRESS_DNS_MAX_OBSERVED_MS:-0},
  "dns_failures": ${STRESS_DNS_FAILURES:-0},
  "rss_growth_kb": $rss_growth,
  "rss_kb": ${RESOURCE_RSS_KB:-0},
  "threads": ${RESOURCE_THREADS:-0},
  "fds": ${RESOURCE_FDS:-0},
  "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
}

write_domainstore_baseline() {
    local dir note_escaped
    dir=$(dirname "$DOMAINSTORE_BASELINE_FILE")
    mkdir -p "$dir"
    note_escaped=$(printf '%s' "$DOMAINSTORE_BASELINE_NOTE" | sed 's/\\/\\\\/g; s/"/\\"/g')
    cat > "$DOMAINSTORE_BASELINE_FILE" <<EOF
{
  "status": "$DOMAINSTORE_BASELINE_STATUS",
  "build_id": "$MOCK_BUILD_ID",
  "git_rev": "$GIT_REV",
  "domains": $DOMAINSTORE_BASELINE_DOMAINS,
  "imported": $DOMAINSTORE_BASELINE_IMPORTED,
  "rss_before_kb": $DOMAINSTORE_BASELINE_RSS_BEFORE_KB,
  "rss_after_kb": $DOMAINSTORE_BASELINE_RSS_AFTER_KB,
  "rss_growth_kb": $DOMAINSTORE_BASELINE_RSS_GROWTH_KB,
  "bytes_per_domain": $DOMAINSTORE_BASELINE_BYTES_PER_DOMAIN,
  "dns_samples": $DOMAINSTORE_BASELINE_DNS_SAMPLES_RUN,
  "dns_failures": $DOMAINSTORE_BASELINE_DNS_FAILURES,
  "dns_p95_ms": $DOMAINSTORE_BASELINE_DNS_P95_MS,
  "dns_max_ms": $DOMAINSTORE_BASELINE_DNS_MAX_MS,
  "dns_avg_ms": $DOMAINSTORE_BASELINE_DNS_AVG_MS,
  "cleanup_method": "$DOMAINSTORE_BASELINE_CLEANUP_METHOD",
  "note": "$note_escaped",
  "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
}

domainstore_select_cleanup_method() {
    # Prefer sqlite for large imports; fall back to API only when domain count fits the API cleanup cap.
    # Intentionally does NOT use stress_max_tier / STRESS_RESOLVED_TIERS (those stay "auto" until the stress block).
    if remote_root "command -v sqlite3 >/dev/null 2>&1" >/dev/null 2>&1; then
        DOMAINSTORE_BASELINE_CLEANUP_METHOD="sqlite"
        return 0
    fi
    if enabled "$STRESS_INSTALL_SQLITE3" && stress_install_sqlite3 >/dev/null 2>&1; then
        DOMAINSTORE_BASELINE_CLEANUP_METHOD="sqlite"
        return 0
    fi
    if [ "$DOMAINSTORE_BASELINE_DOMAINS" -le "$STRESS_API_CLEANUP_MAX_DOMAINS" ]; then
        DOMAINSTORE_BASELINE_CLEANUP_METHOD="api"
        return 0
    fi
    DOMAINSTORE_BASELINE_CLEANUP_METHOD="unknown"
    return 1
}

domainstore_baseline_cleanup() {
    local prefix="$1"
    STRESS_CLEANUP_METHOD="$DOMAINSTORE_BASELINE_CLEANUP_METHOD"
    stress_cleanup_blocklist "$prefix"
}

write_sticky_baseline() {
    local dir note_escaped
    dir=$(dirname "$STICKY_BASELINE_FILE")
    mkdir -p "$dir"
    note_escaped=$(printf '%s' "$STICKY_BASELINE_NOTE" | sed 's/\\/\\\\/g; s/"/\\"/g')
    cat > "$STICKY_BASELINE_FILE" <<EOF
{
  "status": "$STICKY_BASELINE_STATUS",
  "build_id": "$MOCK_BUILD_ID",
  "git_rev": "$GIT_REV",
  "domains_full": $STICKY_BASELINE_DOMAINS,
  "domains_keep": $STICKY_BASELINE_KEEP,
  "rss_before_kb": $STICKY_BASELINE_RSS_BEFORE_KB,
  "rss_full_kb": $STICKY_BASELINE_RSS_FULL_KB,
  "rss_shrink_kb": $STICKY_BASELINE_RSS_SHRINK_KB,
  "rss_reclaim_kb": $STICKY_BASELINE_RSS_RECLAIM_KB,
  "sticky_dns": $STICKY_BASELINE_STICKY_DNS,
  "full_dns_ok": $STICKY_BASELINE_FULL_DNS_OK,
  "keep_dns_ok": $STICKY_BASELINE_KEEP_DNS_OK,
  "removed_domain": "$STICKY_BASELINE_REMOVED_DOMAIN",
  "keep_domain": "$STICKY_BASELINE_KEEP_DOMAIN",
  "note": "$note_escaped",
  "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
}

sticky_write_remote_list() {
    local remote_path="$1"
    local start="$2"
    local end="$3"
    local prefix="$4"
    local quoted_path quoted_prefix
    quoted_path=$(shell_quote "$remote_path")
    quoted_prefix=$(shell_quote "$prefix")
    # shell loop is slower than python but avoids quoting traps over SSH.
    remote_root "i=$start; end=$end; path=$quoted_path; prefix=$quoted_prefix; : > \"\$path\"; while [ \"\$i\" -le \"\$end\" ]; do printf '0.0.0.0 sticky-%s.%s\\n' \"\$i\" \"\$prefix\" >> \"\$path\"; i=\$((i + 1)); done; wc -l < \"\$path\""
}

sticky_relogin() {
    # Cold restarts clear in-memory session validity for some deploy modes; always re-auth.
    rm -f "$COOKIE_JAR"
    COOKIE_JAR=$(mktemp)
    HTTP_CODE=$("${CURL[@]}" -o /dev/null -w "%{http_code}" -c "$COOKIE_JAR" \
        -X POST "$BASE_URL/api/auth/login" \
        -H "Content-Type: application/json" \
        -d "{\"password\":\"$WEBUI_PASSWORD\"}")
    [ "$HTTP_CODE" = "200" ]
}

sticky_cleanup() {
    local prefix="$1"
    local source_id="$2"
    if [ -n "$source_id" ]; then
        "${CURL[@]}" -o /dev/null -b "$COOKIE_JAR" -X DELETE "$BASE_URL/api/sources/$source_id" || true
    fi
    STRESS_CLEANUP_METHOD="sqlite"
    if remote_root "command -v sqlite3 >/dev/null 2>&1" >/dev/null 2>&1 \
        || (enabled "$STRESS_INSTALL_SQLITE3" && stress_install_sqlite3 >/dev/null 2>&1); then
        stress_cleanup_blocklist "$prefix" || true
    else
        api_cleanup_blocklist_prefix "$prefix" 250 40 || true
        restart_remote_service || true
        wait_for_health 15 2 || true
    fi
    remote_root "rm -f /tmp/${prefix}-full.list /tmp/${prefix}-shrink.list" || true
}

write_remove_compact_baseline() {
    local dir note_escaped
    dir=$(dirname "$REMOVE_COMPACT_BASELINE_FILE")
    mkdir -p "$dir"
    note_escaped=$(printf '%s' "$REMOVE_COMPACT_NOTE" | sed 's/\\/\\\\/g; s/"/\\"/g')
    cat > "$REMOVE_COMPACT_BASELINE_FILE" <<EOF
{
  "status": "$REMOVE_COMPACT_STATUS",
  "build_id": "$MOCK_BUILD_ID",
  "git_rev": "$GIT_REV",
  "domains": $REMOVE_COMPACT_DOMAINS,
  "keep": $REMOVE_COMPACT_KEEP,
  "churn": $REMOVE_COMPACT_CHURN,
  "imported": $REMOVE_COMPACT_IMPORTED,
  "deleted": $REMOVE_COMPACT_DELETED,
  "churn_ok": $REMOVE_COMPACT_CHURN_OK,
  "sticky_dns": $REMOVE_COMPACT_STICKY_DNS,
  "keep_dns_ok": $REMOVE_COMPACT_KEEP_DNS_OK,
  "removed_domain": "$REMOVE_COMPACT_REMOVED_DOMAIN",
  "keep_domain": "$REMOVE_COMPACT_KEEP_DOMAIN",
  "rss_before_kb": $REMOVE_COMPACT_RSS_BEFORE_KB,
  "rss_full_kb": $REMOVE_COMPACT_RSS_FULL_KB,
  "rss_after_delete_kb": $REMOVE_COMPACT_RSS_AFTER_DELETE_KB,
  "rss_after_churn_kb": $REMOVE_COMPACT_RSS_AFTER_CHURN_KB,
  "rss_churn_growth_kb": $REMOVE_COMPACT_RSS_CHURN_GROWTH_KB,
  "note": "$note_escaped",
  "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
}

remove_compact_cleanup() {
    local prefix="$1"
    if remote_root "command -v sqlite3 >/dev/null 2>&1" >/dev/null 2>&1 \
        || (enabled "$STRESS_INSTALL_SQLITE3" && stress_install_sqlite3 >/dev/null 2>&1); then
        STRESS_CLEANUP_METHOD="sqlite"
        stress_cleanup_blocklist "$prefix" || true
    else
        api_cleanup_blocklist_prefix "$prefix" 250 40 || true
    fi
}

write_sync_apply_baseline() {
    local dir note_escaped
    dir=$(dirname "$SYNC_APPLY_BASELINE_FILE")
    mkdir -p "$dir"
    note_escaped=$(printf '%s' "$SYNC_APPLY_NOTE" | sed 's/\\/\\\\/g; s/"/\\"/g')
    cat > "$SYNC_APPLY_BASELINE_FILE" <<EOF
{
  "status": "$SYNC_APPLY_STATUS",
  "build_id": "$MOCK_BUILD_ID",
  "git_rev": "$GIT_REV",
  "domains": $SYNC_APPLY_DOMAINS,
  "keep": $SYNC_APPLY_KEEP,
  "imported": $SYNC_APPLY_IMPORTED,
  "deleted": $SYNC_APPLY_DELETED,
  "sticky_dns": $SYNC_APPLY_STICKY_DNS,
  "keep_dns_ok": $SYNC_APPLY_KEEP_DNS_OK,
  "full_dns_ok": $SYNC_APPLY_FULL_DNS_OK,
  "removed_domain": "$SYNC_APPLY_REMOVED_DOMAIN",
  "keep_domain": "$SYNC_APPLY_KEEP_DOMAIN",
  "slave_dns_port": $SYNC_APPLY_SLAVE_DNS_PORT,
  "note": "$note_escaped",
  "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
}

sync_apply_cleanup_slave() {
    local pid="${SYNC_APPLY_SLAVE_PID:-}"
    local db="${SYNC_APPLY_SLAVE_DB:-}"
    if [ -n "$pid" ]; then
        remote_root "kill $pid 2>/dev/null || true; sleep 1; kill -9 $pid 2>/dev/null || true" || true
    fi
    # Reap by cmdline/port if PID lost.
    remote_root "pkill -f 'rustblocker.*--dns-port ${SYNC_APPLY_SLAVE_DNS_PORT}' 2>/dev/null || true; fuser -k ${SYNC_APPLY_SLAVE_DNS_PORT}/udp ${SYNC_APPLY_SLAVE_DNS_PORT}/tcp ${SYNC_APPLY_SLAVE_WEB_PORT}/tcp 2>/dev/null || true" || true
    if [ -n "$db" ]; then
        remote_root "rm -f $(shell_quote "$db") $(shell_quote "${db}-wal") $(shell_quote "${db}-shm") /tmp/rb-sync-apply-slave.log" || true
    fi
    SYNC_APPLY_SLAVE_PID=""
}

remote_dns_a_port() {
    local domain="$1"
    local port="$2"
    local quoted_domain
    quoted_domain=$(shell_quote "$domain")
    "${SSH[@]}" "$REMOTE" "domain=$quoted_domain; port=$port; if command -v dig >/dev/null 2>&1; then dig @127.0.0.1 -p \"\$port\" +time=2 +tries=1 +short A \"\$domain\"; elif command -v drill >/dev/null 2>&1; then drill -p \"\$port\" @127.0.0.1 \"\$domain\" A | awk '/^[^;].*[[:space:]]A[[:space:]]/ { print \$NF }'; elif command -v nslookup >/dev/null 2>&1; then nslookup -type=A -port=\$port \"\$domain\" 127.0.0.1 | awk '/^Name:/ { answer=1 } answer && /^Address(es)?:/ { for (i=2; i<=NF; i++) if (\$i ~ /^[0-9.]+\$/) print \$i } answer && /^[[:space:]]+[0-9]+\\./ { print \$1 }'; else echo '__NO_DNS_TOOL__'; exit 3; fi"
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
RESOURCE_BASE_RSS_KB=0
if remote_resource_snapshot; then
    RESOURCE_BASE_RSS_KB="$RESOURCE_RSS_KB"
    check_resource_snapshot "resource-baseline"
else
    fail "$STEP" "resource-baseline" "could not read rustblocker process resources"
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
HTTP_CODE_PARALLEL=$("${CURL[@]}" -o /dev/null -w "%{http_code}" -b "$COOKIE_JAR" \
    -X PUT "$BASE_URL/api/settings" \
    -H "Content-Type: application/json" \
    -d '{"key":"forward_strategy","value":"parallel"}')
PARALLEL_DNS=$(target_dns_a "$FORWARD_PROBE_DOMAIN" 2>/dev/null || true)
HTTP_CODE_ADAPTIVE=$("${CURL[@]}" -o /dev/null -w "%{http_code}" -b "$COOKIE_JAR" \
    -X PUT "$BASE_URL/api/settings" \
    -H "Content-Type: application/json" \
    -d '{"key":"forward_strategy","value":"adaptive"}')
ADAPTIVE_DNS=$(target_dns_a "$FORWARD_PROBE_DOMAIN" 2>/dev/null || true)
if [ "$ORIGINAL_FORWARD_STRATEGY" != "adaptive" ]; then
    "${CURL[@]}" -o /dev/null -w "%{http_code}" -b "$COOKIE_JAR" \
        -X PUT "$BASE_URL/api/settings" \
        -H "Content-Type: application/json" \
        -d "{\"key\":\"forward_strategy\",\"value\":\"$ORIGINAL_FORWARD_STRATEGY\"}" >/dev/null || true
fi
if [ "$HTTP_CODE_PARALLEL" = "200" ] \
    && [ "$HTTP_CODE_ADAPTIVE" = "200" ] \
    && printf '%s\n' "$PARALLEL_DNS" | has_ipv4_answer \
    && printf '%s\n' "$ADAPTIVE_DNS" | has_ipv4_answer; then
    ok "$STEP" "forward-strategy-dns" "parallel/adaptive both resolved $FORWARD_PROBE_DOMAIN"
else
    fail "$STEP" "forward-strategy-dns" "parallel/adaptive DNS probe failed for $FORWARD_PROBE_DOMAIN (parallel HTTP $HTTP_CODE_PARALLEL: ${PARALLEL_DNS:-empty}; adaptive HTTP $HTTP_CODE_ADAPTIVE: ${ADAPTIVE_DNS:-empty})"
fi

step
VERSION_JSON=$("${CURL[@]}" "$BASE_URL/api/version")
DEPLOYED_BUILD=$(echo "$VERSION_JSON" | sed -n 's/.*"build":"\([^"]*\)".*/\1/p' | head -1)
DEPLOYED_CACHE_SIZE=$(echo "$VERSION_JSON" | sed -n 's/.*"resolver_cache_size":\([0-9][0-9]*\).*/\1/p' | head -1)
if [ "$SKIP_BUILD" != true ] && [ "$SKIP_DEPLOY" != true ] && [ "$DEPLOYED_BUILD" = "$MOCK_BUILD_ID" ] \
    && [ "${DEPLOYED_CACHE_SIZE:-0}" = "32768" ]; then
    ok "$STEP" "version" "deployed mock build id matches $MOCK_BUILD_ID resolver_cache_size=$DEPLOYED_CACHE_SIZE"
elif { [ "$SKIP_BUILD" = true ] || [ "$SKIP_DEPLOY" = true ]; } && [ -n "$DEPLOYED_BUILD" ] \
    && [ -n "$DEPLOYED_CACHE_SIZE" ]; then
    ok "$STEP" "version" "deployed build id is $DEPLOYED_BUILD resolver_cache_size=$DEPLOYED_CACHE_SIZE"
else
    fail "$STEP" "version" "unexpected version payload build='${DEPLOYED_BUILD:-missing}' cache='${DEPLOYED_CACHE_SIZE:-missing}' (expected build=$MOCK_BUILD_ID cache=32768; response: ${VERSION_JSON:-empty})"
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
if api_cleanup_blocklist_prefix "$IMPORT_BASE" 250 20; then
    ok "$STEP" "import-hot-reload" "removed temporary imported entries for $IMPORT_BASE (${API_CLEANUP_DELETED} delete confirmations)"
else
    fail "$STEP" "import-hot-reload" "failed to remove temporary imported entries for $IMPORT_BASE (${API_CLEANUP_DELETED} delete confirmations)"
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

step
check_resource_snapshot "resource-after-functional" "$RESOURCE_BASE_RSS_KB"

# Step: Run a concurrent DNS burst over local hot-path actions.
BURST_BASE="${RUN_TAG}-burst.rustblocker.test"
BURST_EXACT="exact.${BURST_BASE}"
BURST_WILDCARD_BASE="wild.${BURST_BASE}"
BURST_WILDCARD_ENTRY="*.${BURST_WILDCARD_BASE}"
BURST_WILDCARD_SUBDOMAIN="sub.${BURST_WILDCARD_BASE}"
BURST_REWRITE="rewrite.${BURST_BASE}"
BURST_REWRITE_IPV4="192.0.2.124"
BURST_EXACT_ID=""
BURST_WILDCARD_ID=""
BURST_REWRITE_ID=""

step
BURST_EXACT_RESPONSE=$("${CURL[@]}" -w "\n%{http_code}" -b "$COOKIE_JAR" \
    -X POST "$BASE_URL/api/blocklist" \
    -H "Content-Type: application/json" \
    -d "{\"domain\":\"$BURST_EXACT\"}")
BURST_EXACT_HTTP=$(printf '%s\n' "$BURST_EXACT_RESPONSE" | tail -1)
BURST_EXACT_BODY=$(printf '%s\n' "$BURST_EXACT_RESPONSE" | sed '$d')
BURST_EXACT_ID=$(printf '%s\n' "$BURST_EXACT_BODY" | json_ids | head -1)
BURST_WILDCARD_RESPONSE=$("${CURL[@]}" -w "\n%{http_code}" -b "$COOKIE_JAR" \
    -X POST "$BASE_URL/api/blocklist" \
    -H "Content-Type: application/json" \
    -d "{\"domain\":\"$BURST_WILDCARD_ENTRY\"}")
BURST_WILDCARD_HTTP=$(printf '%s\n' "$BURST_WILDCARD_RESPONSE" | tail -1)
BURST_WILDCARD_BODY=$(printf '%s\n' "$BURST_WILDCARD_RESPONSE" | sed '$d')
BURST_WILDCARD_ID=$(printf '%s\n' "$BURST_WILDCARD_BODY" | json_ids | head -1)
BURST_REWRITE_RESPONSE=$("${CURL[@]}" -w "\n%{http_code}" -b "$COOKIE_JAR" \
    -X POST "$BASE_URL/api/rewrites" \
    -H "Content-Type: application/json" \
    -d "{\"domain\":\"$BURST_REWRITE\",\"ipv4\":\"$BURST_REWRITE_IPV4\",\"ipv6\":null}")
BURST_REWRITE_HTTP=$(printf '%s\n' "$BURST_REWRITE_RESPONSE" | tail -1)
BURST_REWRITE_BODY=$(printf '%s\n' "$BURST_REWRITE_RESPONSE" | sed '$d')
BURST_REWRITE_ID=$(printf '%s\n' "$BURST_REWRITE_BODY" | json_ids | head -1)
if [ "$BURST_EXACT_HTTP" = "201" ] && [ -n "$BURST_EXACT_ID" ] \
    && [ "$BURST_WILDCARD_HTTP" = "201" ] && [ -n "$BURST_WILDCARD_ID" ] \
    && [ "$BURST_REWRITE_HTTP" = "201" ] && [ -n "$BURST_REWRITE_ID" ]; then
    ok "$STEP" "dns-burst-setup" "created exact, wildcard, and rewrite entries for $BURST_BASE"
else
    fail "$STEP" "dns-burst-setup" "failed to prepare DNS burst entries (exact HTTP $BURST_EXACT_HTTP id=${BURST_EXACT_ID:-missing}; wildcard HTTP $BURST_WILDCARD_HTTP id=${BURST_WILDCARD_ID:-missing}; rewrite HTTP $BURST_REWRITE_HTTP id=${BURST_REWRITE_ID:-missing})"
fi

step
if [ -n "${BURST_EXACT_ID:-}" ] && [ -n "${BURST_WILDCARD_ID:-}" ] && [ -n "${BURST_REWRITE_ID:-}" ]; then
    BURST_READY=false
    for _ in $(seq 1 10); do
        BURST_EXACT_READY=$(target_dns_a "$BURST_EXACT" 2>/dev/null || true)
        BURST_WILDCARD_READY=$(target_dns_a "$BURST_WILDCARD_SUBDOMAIN" 2>/dev/null || true)
        BURST_REWRITE_READY=$(target_dns_a "$BURST_REWRITE" 2>/dev/null || true)
        if printf '%s\n' "$BURST_EXACT_READY" | grep -Fxq "$SINKHOLE_IPV4" \
            && printf '%s\n' "$BURST_WILDCARD_READY" | grep -Fxq "$SINKHOLE_IPV4" \
            && printf '%s\n' "$BURST_REWRITE_READY" | grep -Fxq "$BURST_REWRITE_IPV4"; then
            BURST_READY=true
            break
        fi
        sleep 0.2
    done

    if [ "$BURST_READY" != true ]; then
        fail "$STEP" "dns-burst" "burst entries were not visible before concurrent test (exact=${BURST_EXACT_READY:-empty}, wildcard=${BURST_WILDCARD_READY:-empty}, rewrite=${BURST_REWRITE_READY:-empty})"
    else
    BURST_FAILURES_FILE=$(mktemp)
    BURST_STARTED_MS=$(now_ms)
    BURST_PIDS=()
    for i in $(seq 1 "$DNS_BURST_REQUESTS"); do
        case $((i % 3)) in
            0) BURST_DOMAIN="$BURST_EXACT"; BURST_EXPECT="$SINKHOLE_IPV4" ;;
            1) BURST_DOMAIN="$BURST_WILDCARD_SUBDOMAIN"; BURST_EXPECT="$SINKHOLE_IPV4" ;;
            *) BURST_DOMAIN="$BURST_REWRITE"; BURST_EXPECT="$BURST_REWRITE_IPV4" ;;
        esac
        (
            BURST_DNS=$(target_dns_a "$BURST_DOMAIN" 2>/dev/null || true)
            if ! printf '%s\n' "$BURST_DNS" | grep -Fxq "$BURST_EXPECT"; then
                printf '%s expected=%s got=%s\n' "$BURST_DOMAIN" "$BURST_EXPECT" "${BURST_DNS:-empty}" >> "$BURST_FAILURES_FILE"
            fi
        ) &
        BURST_PIDS+=("$!")
    done
    for pid in "${BURST_PIDS[@]}"; do
        wait "$pid" || true
    done
    BURST_ELAPSED_MS=$(( $(now_ms) - BURST_STARTED_MS ))
    BURST_FAILURES=$(wc -l < "$BURST_FAILURES_FILE" 2>/dev/null || echo 0)
    BURST_SAMPLE=$(head -1 "$BURST_FAILURES_FILE" 2>/dev/null || true)
    rm -f "$BURST_FAILURES_FILE"
    if [ "$BURST_FAILURES" -le "$DNS_BURST_MAX_FAILURES" ] && [ "$BURST_ELAPSED_MS" -le "$DNS_BURST_MAX_MS" ]; then
        ok "$STEP" "dns-burst" "${DNS_BURST_REQUESTS} hot-path queries completed in ${BURST_ELAPSED_MS}ms with ${BURST_FAILURES} failures"
    else
        fail "$STEP" "dns-burst" "${DNS_BURST_REQUESTS} hot-path queries had ${BURST_FAILURES} failures in ${BURST_ELAPSED_MS}ms (max failures ${DNS_BURST_MAX_FAILURES}, max ${DNS_BURST_MAX_MS}ms, sample: ${BURST_SAMPLE:-none})"
    fi
    fi
else
    skip "$STEP" "dns-burst" "burst skipped because setup failed"
fi

step
BURST_CLEANUP_OK=true
if ! api_cleanup_blocklist_prefix "$BURST_BASE" 250 10; then
    BURST_CLEANUP_OK=false
fi
if [ -n "${BURST_REWRITE_ID:-}" ]; then
    HTTP_CODE=$("${CURL[@]}" -o /dev/null -w "%{http_code}" -b "$COOKIE_JAR" \
        -X DELETE "$BASE_URL/api/rewrites/$BURST_REWRITE_ID")
    [ "$HTTP_CODE" = "200" ] || true
fi
BURST_BLOCKLIST_LEFT=$("${CURL[@]}" -b "$COOKIE_JAR" "$BASE_URL/api/blocklist?search=$BURST_BASE&limit=1")
BURST_REWRITE_LEFT=$("${CURL[@]}" -b "$COOKIE_JAR" "$BASE_URL/api/rewrites")
if ! printf '%s\n' "$BURST_BLOCKLIST_LEFT" | grep -q '"domains":\[\]' \
    || printf '%s\n' "$BURST_REWRITE_LEFT" | grep -q "$BURST_BASE"; then
    BURST_CLEANUP_OK=false
fi
if [ "$BURST_CLEANUP_OK" = true ]; then
    ok "$STEP" "dns-burst-cleanup" "removed DNS burst entries"
else
    fail "$STEP" "dns-burst-cleanup" "failed to remove one or more DNS burst entries"
fi

# Step: Prove DNS and API hot-reload remain responsive under concurrent queries.
HOT_RELOAD_DOMAIN="${RUN_TAG}-hot-reload.rustblocker.test"
HOT_RELOAD_ID=""

step
HOT_RELOAD_DNS_LOG=$(mktemp)
(
    for _ in $(seq 1 "$HOT_RELOAD_DNS_REQUESTS"); do
        target_dns_a "$HOT_RELOAD_DOMAIN" >> "$HOT_RELOAD_DNS_LOG" 2>/dev/null || true
        sleep 0.02
    done
) &
HOT_RELOAD_PID=$!
sleep 0.2
HOT_RELOAD_RESPONSE=$("${CURL[@]}" -w "\n%{http_code}" -b "$COOKIE_JAR" \
    -X POST "$BASE_URL/api/blocklist" \
    -H "Content-Type: application/json" \
    -d "{\"domain\":\"$HOT_RELOAD_DOMAIN\"}")
HOT_RELOAD_HTTP=$(printf '%s\n' "$HOT_RELOAD_RESPONSE" | tail -1)
HOT_RELOAD_BODY=$(printf '%s\n' "$HOT_RELOAD_RESPONSE" | sed '$d')
HOT_RELOAD_ID=$(printf '%s\n' "$HOT_RELOAD_BODY" | json_ids | head -1)
HOT_RELOAD_BLOCKED_DNS=$(target_dns_a "$HOT_RELOAD_DOMAIN" 2>/dev/null || true)
if [ "$HOT_RELOAD_HTTP" = "201" ] && [ -n "$HOT_RELOAD_ID" ] \
    && printf '%s\n' "$HOT_RELOAD_BLOCKED_DNS" | grep -Fxq "$SINKHOLE_IPV4"; then
    ok "$STEP" "hot-reload-under-load" "blocklist add hot-reloaded while ${HOT_RELOAD_DNS_REQUESTS} DNS probes were active"
else
    fail "$STEP" "hot-reload-under-load" "blocklist add did not hot-reload under DNS load (HTTP $HOT_RELOAD_HTTP, id=${HOT_RELOAD_ID:-missing}, dns=${HOT_RELOAD_BLOCKED_DNS:-empty})"
fi

step
if [ -n "${HOT_RELOAD_ID:-}" ]; then
    HTTP_CODE=$("${CURL[@]}" -o /dev/null -w "%{http_code}" -b "$COOKIE_JAR" \
        -X DELETE "$BASE_URL/api/blocklist/$HOT_RELOAD_ID")
    HOT_RELOAD_AFTER_DELETE_DNS=$(target_dns_a "$HOT_RELOAD_DOMAIN" 2>/dev/null || true)
    wait "$HOT_RELOAD_PID" || true
    HOT_RELOAD_BACKGROUND_COUNT=$(wc -l < "$HOT_RELOAD_DNS_LOG" 2>/dev/null || echo 0)
    rm -f "$HOT_RELOAD_DNS_LOG"
    if [ "$HTTP_CODE" = "200" ] && ! printf '%s\n' "$HOT_RELOAD_AFTER_DELETE_DNS" | grep -Fxq "$SINKHOLE_IPV4"; then
        ok "$STEP" "hot-reload-under-load" "blocklist delete hot-reloaded after ${HOT_RELOAD_BACKGROUND_COUNT} background DNS probes"
    else
        fail "$STEP" "hot-reload-under-load" "blocklist delete did not hot-reload (HTTP $HTTP_CODE, dns=${HOT_RELOAD_AFTER_DELETE_DNS:-empty})"
    fi
else
    wait "$HOT_RELOAD_PID" || true
    rm -f "$HOT_RELOAD_DNS_LOG"
    skip "$STEP" "hot-reload-under-load" "delete skipped because temporary entry was not created"
fi

# Step: Repeated imports must not cause unbounded RSS growth or stale entries.
step
MEMORY_BASE_RSS_KB="$RESOURCE_BASE_RSS_KB"
if remote_resource_snapshot; then
    MEMORY_BASE_RSS_KB="$RESOURCE_RSS_KB"
fi
MEMORY_IMPORT_OK=true
MEMORY_IMPORTED_TOTAL=0
MEMORY_CLEANED_TOTAL=0
for loop in $(seq 1 "$MEMORY_IMPORT_LOOPS"); do
    MEMORY_BASE="${RUN_TAG}-mem-${loop}.rustblocker.test"
    MEMORY_CONTENT=""
    for i in $(seq 1 "$MEMORY_IMPORT_DOMAINS"); do
        MEMORY_CONTENT="${MEMORY_CONTENT}0.0.0.0 mem-${i}.${MEMORY_BASE}\\n"
    done
    MEMORY_RESPONSE=$("${CURL[@]}" -w "\n%{http_code}" -b "$COOKIE_JAR" \
        -X POST "$BASE_URL/api/blocklist/import" \
        -H "Content-Type: application/json" \
        -d "{\"content\":\"$MEMORY_CONTENT\"}")
    MEMORY_HTTP=$(printf '%s\n' "$MEMORY_RESPONSE" | tail -1)
    MEMORY_BODY=$(printf '%s\n' "$MEMORY_RESPONSE" | sed '$d')
    MEMORY_IMPORTED=$(printf '%s\n' "$MEMORY_BODY" | json_number "imported")
    if [ "$MEMORY_HTTP" != "200" ] || [ "${MEMORY_IMPORTED:-0}" -lt "$MEMORY_IMPORT_DOMAINS" ]; then
        MEMORY_IMPORT_OK=false
    fi
    MEMORY_IMPORTED_TOTAL=$((MEMORY_IMPORTED_TOTAL + ${MEMORY_IMPORTED:-0}))
    MEMORY_SEARCH_LIMIT=$((MEMORY_IMPORT_DOMAINS + 25))
    MEMORY_LOOP_CLEAN=false
    for _ in $(seq 1 20); do
        MEMORY_SEARCH=$("${CURL[@]}" -b "$COOKIE_JAR" "$BASE_URL/api/blocklist?search=$MEMORY_BASE&limit=$MEMORY_SEARCH_LIMIT")
        if printf '%s\n' "$MEMORY_SEARCH" | grep -q '"domains":\[\]'; then
            MEMORY_LOOP_CLEAN=true
            break
        fi
        MEMORY_IDS=$(printf '%s\n' "$MEMORY_SEARCH" | json_ids || true)
        if [ -z "$MEMORY_IDS" ]; then
            MEMORY_IMPORT_OK=false
            break
        fi
        for id in $MEMORY_IDS; do
            HTTP_CODE=$("${CURL[@]}" -o /dev/null -w "%{http_code}" -b "$COOKIE_JAR" \
                -X DELETE "$BASE_URL/api/blocklist/$id")
            if [ "$HTTP_CODE" = "200" ]; then
                MEMORY_CLEANED_TOTAL=$((MEMORY_CLEANED_TOTAL + 1))
            fi
        done
        sleep 0.1
    done
    if [ "$MEMORY_LOOP_CLEAN" != true ]; then
        MEMORY_IMPORT_OK=false
    fi
done
sleep 2
if [ "$MEMORY_IMPORT_OK" = true ]; then
    ok "$STEP" "import-memory-loop" "${MEMORY_IMPORT_LOOPS} imports inserted ${MEMORY_IMPORTED_TOTAL} entries; prefix cleanup verified (${MEMORY_CLEANED_TOTAL} delete confirmations)"
else
    fail "$STEP" "import-memory-loop" "repeated import cleanup incomplete (inserted ${MEMORY_IMPORTED_TOTAL}, ${MEMORY_CLEANED_TOTAL} delete confirmations)"
fi

step
check_resource_snapshot "resource-after-import-loop" "$MEMORY_BASE_RSS_KB"

step
CLEANUP_LEAKS=0
for endpoint in blocklist allowlist; do
    CLEANUP_JSON=$("${CURL[@]}" -b "$COOKIE_JAR" "$BASE_URL/api/$endpoint?search=$RUN_TAG&limit=5")
    if ! printf '%s\n' "$CLEANUP_JSON" | grep -q '"domains":\[\]'; then
        CLEANUP_LEAKS=$((CLEANUP_LEAKS + 1))
    fi
done
REWRITE_CLEANUP_JSON=$("${CURL[@]}" -b "$COOKIE_JAR" "$BASE_URL/api/rewrites")
if printf '%s\n' "$REWRITE_CLEANUP_JSON" | grep -q "$RUN_TAG"; then
    CLEANUP_LEAKS=$((CLEANUP_LEAKS + 1))
fi
if [ "$CLEANUP_LEAKS" -eq 0 ]; then
    ok "$STEP" "cleanup-audit" "no temporary entries remain for $RUN_TAG"
else
    fail "$STEP" "cleanup-audit" "found temporary entries remaining for $RUN_TAG"
fi

step
check_resource_snapshot "resource-final" "$RESOURCE_BASE_RSS_KB"

# DomainStore memory baseline: import a fixed domain count, measure RSS growth
# attributable to the in-memory DomainStore representation, verify DNS matching,
# then clean up. Writes target/mock-domainstore-memory-baseline.json for comparisons.
if enabled "$MOCK_DOMAINSTORE_BASELINE"; then
    DOMAINSTORE_BASE="${RUN_TAG}-domainstore-baseline.rustblocker.test"
    DOMAINSTORE_BASELINE_STATUS="running"
    DOMAINSTORE_BASELINE_NOTE="post-fix packed-arena DomainStore"

    step
    if domainstore_select_cleanup_method; then
        ok "$STEP" "domainstore-baseline-prereq" "cleanup method=$DOMAINSTORE_BASELINE_CLEANUP_METHOD domains=$DOMAINSTORE_BASELINE_DOMAINS"
    else
        DOMAINSTORE_BASELINE_STATUS="cleanup_unavailable"
        fail "$STEP" "domainstore-baseline-prereq" "no safe cleanup method: install sqlite3 on target or keep DOMAINSTORE_BASELINE_DOMAINS <= STRESS_API_CLEANUP_MAX_DOMAINS ($STRESS_API_CLEANUP_MAX_DOMAINS)"
    fi
    step
    if [ "$DOMAINSTORE_BASELINE_STATUS" = "running" ] && remote_resource_snapshot; then
        DOMAINSTORE_BASELINE_RSS_BEFORE_KB="$RESOURCE_RSS_KB"
        ok "$STEP" "domainstore-baseline-before" "rss=${DOMAINSTORE_BASELINE_RSS_BEFORE_KB}KB base=$DOMAINSTORE_BASE"
    elif [ "$DOMAINSTORE_BASELINE_STATUS" = "running" ]; then
        DOMAINSTORE_BASELINE_STATUS="resource_failed"
        fail "$STEP" "domainstore-baseline-before" "could not read process resources before import"
    else
        skip "$STEP" "domainstore-baseline-before" "skipped because prerequisite failed"
    fi

    step
    if [ "$DOMAINSTORE_BASELINE_STATUS" = "running" ]; then
        DOMAINSTORE_IMPORT_OK=true
        DOMAINSTORE_IMPORTED_TOTAL=0
        DOMAINSTORE_IMPORT_STARTED_MS=$(now_ms)
        while [ "$DOMAINSTORE_IMPORTED_TOTAL" -lt "$DOMAINSTORE_BASELINE_DOMAINS" ]; do
            remaining=$((DOMAINSTORE_BASELINE_DOMAINS - DOMAINSTORE_IMPORTED_TOTAL))
            batch="$DOMAINSTORE_BASELINE_BATCH"
            [ "$batch" -gt "$remaining" ] && batch="$remaining"
            if stress_import_blocklist_batch "$DOMAINSTORE_BASE" $((DOMAINSTORE_IMPORTED_TOTAL + 1)) "$batch"; then
                DOMAINSTORE_IMPORTED_TOTAL=$((DOMAINSTORE_IMPORTED_TOTAL + STRESS_IMPORTED_BATCH))
            else
                DOMAINSTORE_IMPORT_OK=false
                break
            fi
        done
        DOMAINSTORE_IMPORT_MS=$(( $(now_ms) - DOMAINSTORE_IMPORT_STARTED_MS ))
        DOMAINSTORE_BASELINE_IMPORTED="$DOMAINSTORE_IMPORTED_TOTAL"

        if [ "$DOMAINSTORE_IMPORT_OK" = true ] && stress_ensure_blocklist_size "$DOMAINSTORE_BASE" "$DOMAINSTORE_BASELINE_DOMAINS"; then
            ok "$STEP" "domainstore-baseline-import" "imported ${DOMAINSTORE_BASELINE_IMPORTED} domains in ${DOMAINSTORE_IMPORT_MS}ms"
        else
            DOMAINSTORE_BASELINE_STATUS="import_failed"
            fail "$STEP" "domainstore-baseline-import" "import incomplete after ${DOMAINSTORE_IMPORT_MS}ms (imported=${DOMAINSTORE_BASELINE_IMPORTED}/${DOMAINSTORE_BASELINE_DOMAINS}, error=${STRESS_IMPORT_ERROR:-none})"
        fi
    else
        skip "$STEP" "domainstore-baseline-import" "skipped because prerequisite failed"
    fi

    step
    if [ "$DOMAINSTORE_BASELINE_STATUS" = "running" ]; then
        sleep "$DOMAINSTORE_BASELINE_SETTLE_SECS"
        stress_measure_dns_latency "$DOMAINSTORE_BASE" "$DOMAINSTORE_BASELINE_DOMAINS" "$DOMAINSTORE_BASELINE_DNS_SAMPLES"
        DOMAINSTORE_BASELINE_DNS_SAMPLES_RUN="$STRESS_DNS_SAMPLE_COUNT"
        DOMAINSTORE_BASELINE_DNS_FAILURES="$STRESS_DNS_FAILURES"
        DOMAINSTORE_BASELINE_DNS_P95_MS="$STRESS_DNS_P95_MS"
        DOMAINSTORE_BASELINE_DNS_MAX_MS="$STRESS_DNS_MAX_OBSERVED_MS"
        DOMAINSTORE_BASELINE_DNS_AVG_MS="$STRESS_DNS_AVG_MS"

        if ! remote_resource_snapshot; then
            DOMAINSTORE_BASELINE_STATUS="resource_failed"
            fail "$STEP" "domainstore-baseline-after" "could not read process resources after import"
        else
            DOMAINSTORE_BASELINE_RSS_AFTER_KB="$RESOURCE_RSS_KB"
            DOMAINSTORE_BASELINE_RSS_GROWTH_KB=$((DOMAINSTORE_BASELINE_RSS_AFTER_KB - DOMAINSTORE_BASELINE_RSS_BEFORE_KB))
            [ "$DOMAINSTORE_BASELINE_RSS_GROWTH_KB" -lt 0 ] && DOMAINSTORE_BASELINE_RSS_GROWTH_KB=0
            if [ "$DOMAINSTORE_BASELINE_IMPORTED" -gt 0 ]; then
                DOMAINSTORE_BASELINE_BYTES_PER_DOMAIN=$(( DOMAINSTORE_BASELINE_RSS_GROWTH_KB * 1024 / DOMAINSTORE_BASELINE_IMPORTED ))
            else
                DOMAINSTORE_BASELINE_BYTES_PER_DOMAIN=0
            fi

            if [ "$DOMAINSTORE_BASELINE_DNS_FAILURES" -gt "$DOMAINSTORE_BASELINE_DNS_MAX_FAILURES" ]; then
                DOMAINSTORE_BASELINE_STATUS="dns_failed"
                fail "$STEP" "domainstore-baseline-after" "dns failures=${DOMAINSTORE_BASELINE_DNS_FAILURES} p95=${DOMAINSTORE_BASELINE_DNS_P95_MS}ms (sample=${STRESS_DNS_FAILURE_SAMPLE:-none})"
            elif [ "$DOMAINSTORE_BASELINE_RSS_GROWTH_MAX_KB" -gt 0 ] && [ "$DOMAINSTORE_BASELINE_RSS_GROWTH_KB" -gt "$DOMAINSTORE_BASELINE_RSS_GROWTH_MAX_KB" ]; then
                DOMAINSTORE_BASELINE_STATUS="rss_exceeded"
                fail "$STEP" "domainstore-baseline-after" "rss growth ${DOMAINSTORE_BASELINE_RSS_GROWTH_KB}KB exceeded max ${DOMAINSTORE_BASELINE_RSS_GROWTH_MAX_KB}KB (before=${DOMAINSTORE_BASELINE_RSS_BEFORE_KB}KB after=${DOMAINSTORE_BASELINE_RSS_AFTER_KB}KB)"
            elif [ "$DOMAINSTORE_BASELINE_BYTES_PER_DOMAIN_MAX" -gt 0 ] && [ "$DOMAINSTORE_BASELINE_BYTES_PER_DOMAIN" -gt "$DOMAINSTORE_BASELINE_BYTES_PER_DOMAIN_MAX" ]; then
                DOMAINSTORE_BASELINE_STATUS="bytes_per_domain_exceeded"
                fail "$STEP" "domainstore-baseline-after" "bytes/domain ${DOMAINSTORE_BASELINE_BYTES_PER_DOMAIN} exceeded max ${DOMAINSTORE_BASELINE_BYTES_PER_DOMAIN_MAX} (growth=${DOMAINSTORE_BASELINE_RSS_GROWTH_KB}KB)"
            else
                DOMAINSTORE_BASELINE_STATUS="passed"
                ok "$STEP" "domainstore-baseline-after" "rss_before=${DOMAINSTORE_BASELINE_RSS_BEFORE_KB}KB rss_after=${DOMAINSTORE_BASELINE_RSS_AFTER_KB}KB growth=${DOMAINSTORE_BASELINE_RSS_GROWTH_KB}KB bytes/domain=${DOMAINSTORE_BASELINE_BYTES_PER_DOMAIN} dns_p95=${DOMAINSTORE_BASELINE_DNS_P95_MS}ms failures=${DOMAINSTORE_BASELINE_DNS_FAILURES}"
            fi
        fi
    else
        skip "$STEP" "domainstore-baseline-after" "skipped because import did not complete"
    fi

    step
    if [ "$DOMAINSTORE_BASELINE_IMPORTED" -gt 0 ]; then
        if domainstore_baseline_cleanup "$DOMAINSTORE_BASE"; then
            DOMAINSTORE_LEFTOVER=$("${CURL[@]}" -b "$COOKIE_JAR" "$BASE_URL/api/blocklist?search=$DOMAINSTORE_BASE&limit=1")
            if printf '%s\n' "$DOMAINSTORE_LEFTOVER" | grep -q '"domains":\[\]'; then
                ok "$STEP" "domainstore-baseline-cleanup" "removed baseline prefix and restarted service"
            else
                fail "$STEP" "domainstore-baseline-cleanup" "cleanup left residual entries (search=${DOMAINSTORE_LEFTOVER:-empty})"
            fi
        else
            fail "$STEP" "domainstore-baseline-cleanup" "failed to clean baseline prefix $DOMAINSTORE_BASE"
        fi
    else
        skip "$STEP" "domainstore-baseline-cleanup" "no baseline entries were imported"
    fi

    step
    write_domainstore_baseline
    if [ "$DOMAINSTORE_BASELINE_STATUS" = "passed" ]; then
        ok "$STEP" "domainstore-baseline-report" "wrote $DOMAINSTORE_BASELINE_FILE (domains=$DOMAINSTORE_BASELINE_IMPORTED growth=${DOMAINSTORE_BASELINE_RSS_GROWTH_KB}KB bytes/domain=${DOMAINSTORE_BASELINE_BYTES_PER_DOMAIN})"
    else
        ok "$STEP" "domainstore-baseline-report" "wrote $DOMAINSTORE_BASELINE_FILE with status=$DOMAINSTORE_BASELINE_STATUS"
    fi
else
    step
    skip "$STEP" "domainstore-baseline" "disabled; set MOCK_DOMAINSTORE_BASELINE=true to measure DomainStore RSS"
fi

# Resolver cache floor (finding 6): DEFAULT_CACHE_SIZE=32_768 per upstream.
# Measures hit-rate proxy, heavy unique p95, RSS delta; gates on climb/SERVFAIL.
if enabled "$MOCK_RESOLVER_CACHE_BASELINE"; then
    step
    RESOLVER_CACHE_BASELINE_STATUS="running"
    RESOLVER_CACHE_BASELINE_SERVFAIL=0
    RESOLVER_CACHE_BASELINE_EMPTY=0
    RESOLVER_CACHE_BASELINE_UPSTREAM=0
    RESOLVER_CACHE_HEAVY_LAT=()
    RESOLVER_CACHE_FIRST_LAT=()
    RESOLVER_CACHE_WARM_LAT=()
    RESOLVER_CACHE_ALL_LAT=()

    RESOLVER_CACHE_BASELINE_PREV_P95_MS=""
    if [ -f "$RESOLVER_CACHE_BASELINE_FILE" ]; then
        # Prefer prior warm p95 when present (new schema); else overall.
        RESOLVER_CACHE_BASELINE_PREV_P95_MS=$(sed -n 's/.*"dns_warm_p95_ms":[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$RESOLVER_CACHE_BASELINE_FILE" | head -1)
        if [ -z "$RESOLVER_CACHE_BASELINE_PREV_P95_MS" ]; then
            RESOLVER_CACHE_BASELINE_PREV_P95_MS=$(sed -n 's/.*"dns_p95_ms":[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$RESOLVER_CACHE_BASELINE_FILE" | head -1)
        fi
    fi

    p95_of() {
        local sorted count idx
        sorted=$(sort -n)
        count=$(printf '%s\n' "$sorted" | grep -c . || true)
        [ "${count:-0}" -lt 1 ] && { echo 0; return; }
        idx=$(( (count * 95 + 99) / 100 ))
        [ "$idx" -lt 1 ] && idx=1
        printf '%s\n' "$sorted" | sed -n "${idx}p"
    }
    max_of() { sort -n | tail -1; }

    # RSS before heavy unique fill.
    if remote_resource_snapshot; then
        RESOLVER_CACHE_BASELINE_RSS_BEFORE_KB="$RESOURCE_RSS_KB"
    else
        RESOLVER_CACHE_BASELINE_RSS_BEFORE_KB=0
    fi

    # --- Heavy unique miss path (forced upstream / NXDOMAIN). ---
    for i in $(seq 1 "$RESOLVER_CACHE_BASELINE_UNIQUE_SAMPLES"); do
        DOMAIN="rb-cache-heavy-${RUN_TAG}-${i}.example.com"
        START_MS=$(now_ms)
        RESULT=$(target_dns_a "$DOMAIN" 2>/dev/null || true)
        END_MS=$(now_ms)
        LATENCY=$((END_MS - START_MS))
        RESOLVER_CACHE_HEAVY_LAT+=("$LATENCY")
        RESOLVER_CACHE_ALL_LAT+=("$LATENCY")
        if echo "$RESULT" | grep -qi "servfail\|error\|connection refused\|timed out"; then
            RESOLVER_CACHE_BASELINE_SERVFAIL=$((RESOLVER_CACHE_BASELINE_SERVFAIL + 1))
        else
            # dig +short silent on NXDOMAIN → empty is success for unique cold names.
            RESOLVER_CACHE_BASELINE_UPSTREAM=$((RESOLVER_CACHE_BASELINE_UPSTREAM + 1))
        fi
    done

    if remote_resource_snapshot; then
        RESOLVER_CACHE_BASELINE_RSS_AFTER_HEAVY_KB="$RESOURCE_RSS_KB"
        RESOLVER_CACHE_BASELINE_RSS_DELTA_KB=$((RESOLVER_CACHE_BASELINE_RSS_AFTER_HEAVY_KB - RESOLVER_CACHE_BASELINE_RSS_BEFORE_KB))
        [ "$RESOLVER_CACHE_BASELINE_RSS_DELTA_KB" -lt 0 ] && RESOLVER_CACHE_BASELINE_RSS_DELTA_KB=0
    else
        RESOLVER_CACHE_BASELINE_RSS_AFTER_HEAVY_KB=0
        RESOLVER_CACHE_BASELINE_RSS_DELTA_KB=0
    fi

    # --- Hit-rate proxy on real domains: first pass (miss/fill) then warm rounds. ---
    REAL_DOMAINS=(example.com cloudflare.com google.com github.com mozilla.org rust-lang.org wikipedia.org amazon.com microsoft.com apple.com)
    REAL_N=${#REAL_DOMAINS[@]}

    # First pass over the set (populate cache).
    for idx in $(seq 0 $((REAL_N - 1))); do
        DOMAIN="${REAL_DOMAINS[$idx]}"
        START_MS=$(now_ms)
        RESULT=$(target_dns_a "$DOMAIN" 2>/dev/null || true)
        END_MS=$(now_ms)
        LATENCY=$((END_MS - START_MS))
        RESOLVER_CACHE_FIRST_LAT+=("$LATENCY")
        RESOLVER_CACHE_ALL_LAT+=("$LATENCY")
        if [ -z "$RESULT" ]; then
            RESOLVER_CACHE_BASELINE_EMPTY=$((RESOLVER_CACHE_BASELINE_EMPTY + 1))
        elif echo "$RESULT" | grep -qi "servfail\|error\|connection refused\|timed out"; then
            RESOLVER_CACHE_BASELINE_SERVFAIL=$((RESOLVER_CACHE_BASELINE_SERVFAIL + 1))
        else
            RESOLVER_CACHE_BASELINE_UPSTREAM=$((RESOLVER_CACHE_BASELINE_UPSTREAM + 1))
        fi
    done

    # Warm rounds: repeats should hit LRU (latency should not climb).
    for r in $(seq 1 "$RESOLVER_CACHE_BASELINE_HIT_ROUNDS"); do
        for i in $(seq 1 "$RESOLVER_CACHE_BASELINE_WARM_SAMPLES"); do
            DOMAIN_IDX=$(( (i - 1) % REAL_N ))
            DOMAIN="${REAL_DOMAINS[$DOMAIN_IDX]}"
            START_MS=$(now_ms)
            RESULT=$(target_dns_a "$DOMAIN" 2>/dev/null || true)
            END_MS=$(now_ms)
            LATENCY=$((END_MS - START_MS))
            RESOLVER_CACHE_WARM_LAT+=("$LATENCY")
            RESOLVER_CACHE_ALL_LAT+=("$LATENCY")
            if [ -z "$RESULT" ]; then
                RESOLVER_CACHE_BASELINE_EMPTY=$((RESOLVER_CACHE_BASELINE_EMPTY + 1))
            elif echo "$RESULT" | grep -qi "servfail\|error\|connection refused\|timed out"; then
                RESOLVER_CACHE_BASELINE_SERVFAIL=$((RESOLVER_CACHE_BASELINE_SERVFAIL + 1))
            else
                RESOLVER_CACHE_BASELINE_UPSTREAM=$((RESOLVER_CACHE_BASELINE_UPSTREAM + 1))
            fi
        done
    done

    RESOLVER_CACHE_BASELINE_HEAVY_P95_MS=$(printf '%s\n' "${RESOLVER_CACHE_HEAVY_LAT[@]}" | p95_of)
    RESOLVER_CACHE_BASELINE_FIRST_P95_MS=$(printf '%s\n' "${RESOLVER_CACHE_FIRST_LAT[@]}" | p95_of)
    RESOLVER_CACHE_BASELINE_WARM_P95_MS=$(printf '%s\n' "${RESOLVER_CACHE_WARM_LAT[@]}" | p95_of)
    RESOLVER_CACHE_BASELINE_P95_MS=$(printf '%s\n' "${RESOLVER_CACHE_ALL_LAT[@]}" | p95_of)
    RESOLVER_CACHE_BASELINE_MAX_MS=$(printf '%s\n' "${RESOLVER_CACHE_ALL_LAT[@]}" | max_of)
    RESOLVER_CACHE_BASELINE_HEAVY_P95_MS=${RESOLVER_CACHE_BASELINE_HEAVY_P95_MS:-0}
    RESOLVER_CACHE_BASELINE_FIRST_P95_MS=${RESOLVER_CACHE_BASELINE_FIRST_P95_MS:-0}
    RESOLVER_CACHE_BASELINE_WARM_P95_MS=${RESOLVER_CACHE_BASELINE_WARM_P95_MS:-0}
    RESOLVER_CACHE_BASELINE_P95_MS=${RESOLVER_CACHE_BASELINE_P95_MS:-0}
    RESOLVER_CACHE_BASELINE_MAX_MS=${RESOLVER_CACHE_BASELINE_MAX_MS:-0}
    # Alias cold=heavy for gates/compat with prior field names.
    RESOLVER_CACHE_BASELINE_COLD_P95_MS=$RESOLVER_CACHE_BASELINE_HEAVY_P95_MS

    if [ "$RESOLVER_CACHE_BASELINE_FIRST_P95_MS" -gt 0 ]; then
        RESOLVER_CACHE_BASELINE_HIT_RATIO_PCT=$(( RESOLVER_CACHE_BASELINE_WARM_P95_MS * 100 / RESOLVER_CACHE_BASELINE_FIRST_P95_MS ))
    else
        RESOLVER_CACHE_BASELINE_HIT_RATIO_PCT=0
    fi

    RESOLVER_CACHE_BASELINE_NOTE="cache_size=32768 heavy_unique=${RESOLVER_CACHE_BASELINE_UNIQUE_SAMPLES} warm_rounds=${RESOLVER_CACHE_BASELINE_HIT_ROUNDS}x${RESOLVER_CACHE_BASELINE_WARM_SAMPLES}"
    RESOLVER_CACHE_BASELINE_TOTAL_FAIL=$((RESOLVER_CACHE_BASELINE_SERVFAIL + RESOLVER_CACHE_BASELINE_EMPTY))
    RESOLVER_CACHE_BASELINE_QUERY_COUNT=$((RESOLVER_CACHE_BASELINE_UPSTREAM + RESOLVER_CACHE_BASELINE_SERVFAIL + RESOLVER_CACHE_BASELINE_EMPTY))

    FAIL_DETAIL=""
    if [ "$RESOLVER_CACHE_BASELINE_TOTAL_FAIL" -ne 0 ]; then
        FAIL_DETAIL="failures empty=${RESOLVER_CACHE_BASELINE_EMPTY} servfail=${RESOLVER_CACHE_BASELINE_SERVFAIL}"
    elif [ "$RESOLVER_CACHE_BASELINE_HEAVY_P95_MS" -gt "$RESOLVER_CACHE_HEAVY_P95_MAX_MS" ]; then
        FAIL_DETAIL="heavy_unique_p95=${RESOLVER_CACHE_BASELINE_HEAVY_P95_MS}ms exceeded max ${RESOLVER_CACHE_HEAVY_P95_MAX_MS}ms"
    elif [ "$RESOLVER_CACHE_BASELINE_WARM_P95_MS" -gt "$RESOLVER_CACHE_WARM_P95_MAX_MS" ]; then
        FAIL_DETAIL="warm_p95=${RESOLVER_CACHE_BASELINE_WARM_P95_MS}ms exceeded max ${RESOLVER_CACHE_WARM_P95_MAX_MS}ms"
    elif [ "$RESOLVER_CACHE_BASELINE_WARM_P95_MS" -gt $((RESOLVER_CACHE_BASELINE_FIRST_P95_MS + RESOLVER_CACHE_P95_CLIMB_MAX_MS)) ]; then
        FAIL_DETAIL="warm_p95=${RESOLVER_CACHE_BASELINE_WARM_P95_MS}ms climbed above first_p95=${RESOLVER_CACHE_BASELINE_FIRST_P95_MS}ms + ${RESOLVER_CACHE_P95_CLIMB_MAX_MS}ms (hit proxy collapsed)"
    elif [ "$RESOLVER_CACHE_BASELINE_HIT_RATIO_PCT" -gt "$RESOLVER_CACHE_HIT_RATIO_MAX_PCT" ]; then
        FAIL_DETAIL="hit_ratio_pct=${RESOLVER_CACHE_BASELINE_HIT_RATIO_PCT} (warm/first) exceeded max ${RESOLVER_CACHE_HIT_RATIO_MAX_PCT}"
    elif [ -n "$RESOLVER_CACHE_BASELINE_PREV_P95_MS" ] \
        && [ "$RESOLVER_CACHE_BASELINE_WARM_P95_MS" -gt $((RESOLVER_CACHE_BASELINE_PREV_P95_MS + RESOLVER_CACHE_P95_CLIMB_MAX_MS)) ]; then
        FAIL_DETAIL="warm_p95=${RESOLVER_CACHE_BASELINE_WARM_P95_MS}ms climbed from prior ${RESOLVER_CACHE_BASELINE_PREV_P95_MS}ms by more than ${RESOLVER_CACHE_P95_CLIMB_MAX_MS}ms"
    fi

    if [ -z "$FAIL_DETAIL" ]; then
        RESOLVER_CACHE_BASELINE_STATUS="passed"
        ok "$STEP" "resolver-cache-baseline" "ok q=${RESOLVER_CACHE_BASELINE_QUERY_COUNT} heavy_p95=${RESOLVER_CACHE_BASELINE_HEAVY_P95_MS}ms first_p95=${RESOLVER_CACHE_BASELINE_FIRST_P95_MS}ms warm_p95=${RESOLVER_CACHE_BASELINE_WARM_P95_MS}ms hit_ratio=${RESOLVER_CACHE_BASELINE_HIT_RATIO_PCT}% rss_delta=${RESOLVER_CACHE_BASELINE_RSS_DELTA_KB}KB prev_warm=${RESOLVER_CACHE_BASELINE_PREV_P95_MS:-none}"
    else
        RESOLVER_CACHE_BASELINE_STATUS="failed"
        fail "$STEP" "resolver-cache-baseline" "$FAIL_DETAIL (heavy=${RESOLVER_CACHE_BASELINE_HEAVY_P95_MS} first=${RESOLVER_CACHE_BASELINE_FIRST_P95_MS} warm=${RESOLVER_CACHE_BASELINE_WARM_P95_MS} hit_ratio=${RESOLVER_CACHE_BASELINE_HIT_RATIO_PCT}% rss_delta=${RESOLVER_CACHE_BASELINE_RSS_DELTA_KB}KB)"
    fi

    cat > "$RESOLVER_CACHE_BASELINE_FILE" <<JSONEOF
{
  "status": "$RESOLVER_CACHE_BASELINE_STATUS",
  "build_id": "$MOCK_BUILD_ID",
  "git_rev": "$GIT_REV",
  "cache_size_per_resolver": 32768,
  "query_count": $RESOLVER_CACHE_BASELINE_QUERY_COUNT,
  "upstream_success": $RESOLVER_CACHE_BASELINE_UPSTREAM,
  "servfail": $RESOLVER_CACHE_BASELINE_SERVFAIL,
  "empty": $RESOLVER_CACHE_BASELINE_EMPTY,
  "heavy_unique_samples": $RESOLVER_CACHE_BASELINE_UNIQUE_SAMPLES,
  "warm_repeat_samples": $((RESOLVER_CACHE_BASELINE_WARM_SAMPLES * RESOLVER_CACHE_BASELINE_HIT_ROUNDS)),
  "first_pass_samples": $REAL_N,
  "dns_heavy_unique_p95_ms": $RESOLVER_CACHE_BASELINE_HEAVY_P95_MS,
  "dns_first_p95_ms": $RESOLVER_CACHE_BASELINE_FIRST_P95_MS,
  "dns_warm_p95_ms": $RESOLVER_CACHE_BASELINE_WARM_P95_MS,
  "dns_cold_p95_ms": $RESOLVER_CACHE_BASELINE_COLD_P95_MS,
  "dns_p95_ms": $RESOLVER_CACHE_BASELINE_P95_MS,
  "dns_max_ms": $RESOLVER_CACHE_BASELINE_MAX_MS,
  "hit_ratio_pct": $RESOLVER_CACHE_BASELINE_HIT_RATIO_PCT,
  "rss_before_kb": $RESOLVER_CACHE_BASELINE_RSS_BEFORE_KB,
  "rss_after_heavy_kb": $RESOLVER_CACHE_BASELINE_RSS_AFTER_HEAVY_KB,
  "rss_delta_kb": $RESOLVER_CACHE_BASELINE_RSS_DELTA_KB,
  "prev_dns_p95_ms": ${RESOLVER_CACHE_BASELINE_PREV_P95_MS:-null},
  "heavy_p95_max_ms": $RESOLVER_CACHE_HEAVY_P95_MAX_MS,
  "warm_p95_max_ms": $RESOLVER_CACHE_WARM_P95_MAX_MS,
  "p95_climb_max_ms": $RESOLVER_CACHE_P95_CLIMB_MAX_MS,
  "hit_ratio_max_pct": $RESOLVER_CACHE_HIT_RATIO_MAX_PCT,
  "note": "$RESOLVER_CACHE_BASELINE_NOTE",
  "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSONEOF
    echo "wrote $RESOLVER_CACHE_BASELINE_FILE status=$RESOLVER_CACHE_BASELINE_STATUS heavy_p95=${RESOLVER_CACHE_BASELINE_HEAVY_P95_MS} first_p95=${RESOLVER_CACHE_BASELINE_FIRST_P95_MS} warm_p95=${RESOLVER_CACHE_BASELINE_WARM_P95_MS} hit_ratio=${RESOLVER_CACHE_BASELINE_HIT_RATIO_PCT}% rss_delta=${RESOLVER_CACHE_BASELINE_RSS_DELTA_KB}KB"
else
    step
    skip "$STEP" "resolver-cache-baseline" "hardcoded off (MOCK_RESOLVER_CACHE_BASELINE=false)"
fi

# Sticky-domain baseline (issue 1b): source refresh that shrinks a list must drop
# removed domains from DNS matching and reclaim RAM. sticky_dns=1 means the bug.
if enabled "$MOCK_STICKY_BASELINE"; then
    STICKY_PREFIX="${RUN_TAG}-sticky.rustblocker.test"
    STICKY_FULL_PATH="/tmp/${STICKY_PREFIX}-full.list"
    STICKY_SHRINK_PATH="/tmp/${STICKY_PREFIX}-shrink.list"
    STICKY_BASELINE_STATUS="running"
    STICKY_BASELINE_NOTE="post-fix sticky source refresh (provenance rebuild)"
    STICKY_BASELINE_REMOVED_DOMAIN="sticky-${STICKY_BASELINE_DOMAINS}.${STICKY_PREFIX}"
    STICKY_BASELINE_KEEP_DOMAIN="sticky-1.${STICKY_PREFIX}"

    if [ "$STICKY_BASELINE_KEEP" -ge "$STICKY_BASELINE_DOMAINS" ]; then
        step
        fail "$STEP" "sticky-baseline-prereq" "STICKY_BASELINE_KEEP ($STICKY_BASELINE_KEEP) must be < STICKY_BASELINE_DOMAINS ($STICKY_BASELINE_DOMAINS)"
        STICKY_BASELINE_STATUS="invalid_config"
    fi

    step
    if [ "$STICKY_BASELINE_STATUS" = "running" ] && sticky_write_remote_list "$STICKY_FULL_PATH" 1 "$STICKY_BASELINE_DOMAINS" "$STICKY_PREFIX" >/dev/null; then
        sticky_write_remote_list "$STICKY_SHRINK_PATH" 1 "$STICKY_BASELINE_KEEP" "$STICKY_PREFIX" >/dev/null || true
        ok "$STEP" "sticky-baseline-files" "wrote remote lists full=$STICKY_BASELINE_DOMAINS keep=$STICKY_BASELINE_KEEP"
    elif [ "$STICKY_BASELINE_STATUS" = "running" ]; then
        STICKY_BASELINE_STATUS="file_failed"
        fail "$STEP" "sticky-baseline-files" "failed to write remote source list files"
    else
        skip "$STEP" "sticky-baseline-files" "skipped because prerequisite failed"
    fi

    step
    if [ "$STICKY_BASELINE_STATUS" = "running" ] && remote_resource_snapshot; then
        STICKY_BASELINE_RSS_BEFORE_KB="$RESOURCE_RSS_KB"
        ok "$STEP" "sticky-baseline-before" "rss=${STICKY_BASELINE_RSS_BEFORE_KB}KB"
    elif [ "$STICKY_BASELINE_STATUS" = "running" ]; then
        STICKY_BASELINE_STATUS="resource_failed"
        fail "$STEP" "sticky-baseline-before" "could not read process resources before source import"
    else
        skip "$STEP" "sticky-baseline-before" "skipped because prerequisite failed"
    fi

    step
    if [ "$STICKY_BASELINE_STATUS" = "running" ]; then
        STICKY_ADD_RESP=$("${CURL[@]}" -w "\n%{http_code}" -b "$COOKIE_JAR" \
            -X POST "$BASE_URL/api/sources" \
            -H "Content-Type: application/json" \
            -d "{\"url\":\"$STICKY_FULL_PATH\",\"list_type\":\"blocklist\",\"update_interval_hours\":24}")
        STICKY_ADD_HTTP=$(printf '%s\n' "$STICKY_ADD_RESP" | tail -1)
        STICKY_ADD_BODY=$(printf '%s\n' "$STICKY_ADD_RESP" | sed '$d')
        STICKY_BASELINE_SOURCE_ID=$(printf '%s\n' "$STICKY_ADD_BODY" | json_number "id")
        STICKY_ADD_STATUS=$(printf '%s\n' "$STICKY_ADD_BODY" | sed -n 's/.*"status":"\([^"]*\)".*/\1/p' | head -1)
        if [ "$STICKY_ADD_HTTP" = "201" ] && [ -n "$STICKY_BASELINE_SOURCE_ID" ]; then
            ok "$STEP" "sticky-baseline-import" "source id=$STICKY_BASELINE_SOURCE_ID status=${STICKY_ADD_STATUS:-unknown}"
        else
            STICKY_BASELINE_STATUS="import_failed"
            fail "$STEP" "sticky-baseline-import" "add source failed HTTP=$STICKY_ADD_HTTP body=${STICKY_ADD_BODY:-empty}"
        fi
    else
        skip "$STEP" "sticky-baseline-import" "skipped because prerequisite failed"
    fi

    step
    if [ "$STICKY_BASELINE_STATUS" = "running" ]; then
        sleep "$STICKY_BASELINE_SETTLE_SECS"
        STICKY_FULL_DNS=$(target_dns_a "$STICKY_BASELINE_REMOVED_DOMAIN" 2>/dev/null || true)
        STICKY_KEEP_DNS=$(target_dns_a "$STICKY_BASELINE_KEEP_DOMAIN" 2>/dev/null || true)
        if echo "$STICKY_FULL_DNS" | grep -Fxq "$SINKHOLE_IPV4" \
            && echo "$STICKY_KEEP_DNS" | grep -Fxq "$SINKHOLE_IPV4"; then
            STICKY_BASELINE_FULL_DNS_OK=1
            if remote_resource_snapshot; then STICKY_BASELINE_RSS_FULL_KB="$RESOURCE_RSS_KB"; fi
            STICKY_FULL_TOTAL=$("${CURL[@]}" -b "$COOKIE_JAR" "$BASE_URL/api/blocklist?search=$STICKY_PREFIX&limit=1")
            STICKY_FULL_COUNT=$(printf '%s\n' "$STICKY_FULL_TOTAL" | json_number "total")
            ok "$STEP" "sticky-baseline-full-dns" "full list sinkholed count=${STICKY_FULL_COUNT:-?} keep=$STICKY_BASELINE_KEEP_DOMAIN removed=$STICKY_BASELINE_REMOVED_DOMAIN"
        else
            STICKY_BASELINE_STATUS="dns_failed"
            fail "$STEP" "sticky-baseline-full-dns" "expected sinkhole $SINKHOLE_IPV4; keep=${STICKY_KEEP_DNS:-empty} removed=${STICKY_FULL_DNS:-empty}"
        fi
    else
        skip "$STEP" "sticky-baseline-full-dns" "skipped because import did not complete"
    fi


    step
    if [ "$STICKY_BASELINE_STATUS" = "running" ]; then
        remote_root "cp -f $(shell_quote "$STICKY_SHRINK_PATH") $(shell_quote "$STICKY_FULL_PATH")" >/dev/null
        STICKY_SHRINK_LINES=$(remote_root "wc -l < $(shell_quote "$STICKY_FULL_PATH")" 2>/dev/null | tr -d '[:space:]')
        STICKY_REFRESH=$(curl -s --connect-timeout 5 --max-time 120 -w "\n%{http_code}" -b "$COOKIE_JAR" -X POST "$BASE_URL/api/sources/$STICKY_BASELINE_SOURCE_ID/refresh")
        STICKY_REFRESH_HTTP=$(printf '%s\n' "$STICKY_REFRESH" | tail -1)
        STICKY_REFRESH_BODY=$(printf '%s\n' "$STICKY_REFRESH" | sed '$d')
        STICKY_REFRESH_STATUS=$(printf '%s\n' "$STICKY_REFRESH_BODY" | sed -n 's/.*"status":"\([^"]*\)".*/\1/p' | head -1)
        if [ "$STICKY_REFRESH_HTTP" = "200" ] && printf '%s' "$STICKY_REFRESH_BODY" | grep -q "ok: $STICKY_BASELINE_KEEP domains"; then
            ok "$STEP" "sticky-baseline-shrink-refresh" "refreshed sources after shrink (lines=${STICKY_SHRINK_LINES:-?}, status=${STICKY_REFRESH_STATUS:-unknown})"
        else
            STICKY_BASELINE_STATUS="refresh_failed"
            fail "$STEP" "sticky-baseline-shrink-refresh" "refresh failed HTTP=$STICKY_REFRESH_HTTP lines=${STICKY_SHRINK_LINES:-?} body=${STICKY_REFRESH_BODY:-empty}"
        fi
    else
        skip "$STEP" "sticky-baseline-shrink-refresh" "skipped because full import did not complete"
    fi

    step
    if [ "$STICKY_BASELINE_STATUS" = "running" ]; then
        STICKY_BASELINE_KEEP_DNS_OK=0
        STICKY_BASELINE_STICKY_DNS=0
        STICKY_REMOVED_DNS=""
        STICKY_KEEP_DNS2=""
        for _try in 1 2 3 4 5; do
            sleep "$STICKY_BASELINE_SETTLE_SECS"
            STICKY_REMOVED_DNS=$(target_dns_a "$STICKY_BASELINE_REMOVED_DOMAIN" 2>/dev/null || true)
            STICKY_KEEP_DNS2=$(target_dns_a "$STICKY_BASELINE_KEEP_DOMAIN" 2>/dev/null || true)
            if echo "$STICKY_KEEP_DNS2" | grep -Fxq "$SINKHOLE_IPV4"; then
                STICKY_BASELINE_KEEP_DNS_OK=1
            fi
            if echo "$STICKY_REMOVED_DNS" | grep -Fxq "$SINKHOLE_IPV4"; then
                STICKY_BASELINE_STICKY_DNS=1
            else
                STICKY_BASELINE_STICKY_DNS=0
            fi
            # Success path for post-fix: keep sinkholed, removed not sinkholed.
            if [ "$STICKY_BASELINE_KEEP_DNS_OK" -eq 1 ] && [ "$STICKY_BASELINE_STICKY_DNS" -eq 0 ]; then
                break
            fi
            # Pre-fix sticky path: both sinkholed — no need to retry forever.
            if [ "$STICKY_BASELINE_KEEP_DNS_OK" -eq 1 ] && [ "$STICKY_BASELINE_STICKY_DNS" -eq 1 ]; then
                break
            fi
        done
        STICKY_SEARCH=$("${CURL[@]}" -b "$COOKIE_JAR" "$BASE_URL/api/blocklist?search=$STICKY_BASELINE_KEEP_DOMAIN&limit=5")
        STICKY_SEARCH_TOTAL=$(printf '%s\n' "$STICKY_SEARCH" | json_number "total")

        # Hot RSS after shrink (same mode as rss_full) so reclaim is comparable.
        if remote_resource_snapshot; then
            STICKY_BASELINE_RSS_SHRINK_KB="$RESOURCE_RSS_KB"
            STICKY_BASELINE_RSS_RECLAIM_KB=$((STICKY_BASELINE_RSS_FULL_KB - STICKY_BASELINE_RSS_SHRINK_KB))
            [ "$STICKY_BASELINE_RSS_RECLAIM_KB" -lt 0 ] && STICKY_BASELINE_RSS_RECLAIM_KB=0
        fi

        if [ "$STICKY_BASELINE_KEEP_DNS_OK" -ne 1 ]; then
            STICKY_BASELINE_STATUS="dns_failed"
            fail "$STEP" "sticky-baseline-after-shrink" "kept domain no longer sinkholed (got=${STICKY_KEEP_DNS2:-empty}, search_total=${STICKY_SEARCH_TOTAL:-?}, refresh=${STICKY_REFRESH_STATUS:-?})"
        elif [ "$STICKY_BASELINE_STICKY_DNS" -ne 0 ]; then
            STICKY_BASELINE_STATUS="sticky_dns"
            fail "$STEP" "sticky-baseline-after-shrink" "removed domain still sinkholed (sticky_dns=1, removed_dns=${STICKY_REMOVED_DNS:-empty})"
        else
            # Optional cold persistence check (DNS only; RSS stays hot/hot).
            if restart_remote_service && wait_for_health 15 2 && sticky_relogin; then
                STICKY_REMOVED_COLD=$(target_dns_a "$STICKY_BASELINE_REMOVED_DOMAIN" 2>/dev/null || true)
                STICKY_KEEP_COLD=$(target_dns_a "$STICKY_BASELINE_KEEP_DOMAIN" 2>/dev/null || true)
                if ! echo "$STICKY_KEEP_COLD" | grep -Fxq "$SINKHOLE_IPV4"; then
                    STICKY_BASELINE_STATUS="dns_failed"
                    fail "$STEP" "sticky-baseline-after-shrink" "cold restart lost keep domain (got=${STICKY_KEEP_COLD:-empty})"
                elif echo "$STICKY_REMOVED_COLD" | grep -Fxq "$SINKHOLE_IPV4"; then
                    STICKY_BASELINE_STATUS="sticky_dns"
                    fail "$STEP" "sticky-baseline-after-shrink" "cold restart still sinkholes removed domain"
                else
                    STICKY_BASELINE_STATUS="passed"
                    STICKY_SHRINK_TOTAL=$("${CURL[@]}" -b "$COOKIE_JAR" "$BASE_URL/api/blocklist?search=$STICKY_PREFIX&limit=1")
                    STICKY_SHRINK_COUNT=$(printf '%s\n' "$STICKY_SHRINK_TOTAL" | json_number "total")
                    ok "$STEP" "sticky-baseline-after-shrink" "sticky_dns=0 keep_ok=1 cold_ok=1 count_full=${STICKY_FULL_COUNT:-?} count_shrink=${STICKY_SHRINK_COUNT:-?} rss_full=${STICKY_BASELINE_RSS_FULL_KB}KB rss_shrink=${STICKY_BASELINE_RSS_SHRINK_KB}KB reclaim=${STICKY_BASELINE_RSS_RECLAIM_KB}KB removed_dns=${STICKY_REMOVED_DNS:-empty}"
                fi
            else
                STICKY_BASELINE_STATUS="passed"
                STICKY_SHRINK_TOTAL=$("${CURL[@]}" -b "$COOKIE_JAR" "$BASE_URL/api/blocklist?search=$STICKY_PREFIX&limit=1")
                STICKY_SHRINK_COUNT=$(printf '%s\n' "$STICKY_SHRINK_TOTAL" | json_number "total")
                ok "$STEP" "sticky-baseline-after-shrink" "sticky_dns=0 keep_ok=1 count_full=${STICKY_FULL_COUNT:-?} count_shrink=${STICKY_SHRINK_COUNT:-?} rss_full=${STICKY_BASELINE_RSS_FULL_KB}KB rss_shrink=${STICKY_BASELINE_RSS_SHRINK_KB}KB reclaim=${STICKY_BASELINE_RSS_RECLAIM_KB}KB removed_dns=${STICKY_REMOVED_DNS:-empty} (cold check skipped)"
            fi
        fi
    else
        skip "$STEP" "sticky-baseline-after-shrink" "skipped because shrink refresh did not complete"
    fi

    step
    sticky_cleanup "$STICKY_PREFIX" "$STICKY_BASELINE_SOURCE_ID"
    ok "$STEP" "sticky-baseline-cleanup" "removed sticky source/domains for $STICKY_PREFIX"

    step
    write_sticky_baseline
    ok "$STEP" "sticky-baseline-report" "wrote $STICKY_BASELINE_FILE status=$STICKY_BASELINE_STATUS sticky_dns=$STICKY_BASELINE_STICKY_DNS reclaim=${STICKY_BASELINE_RSS_RECLAIM_KB}KB"
else
    step
    skip "$STEP" "sticky-baseline" "disabled; set MOCK_STICKY_BASELINE=true to measure sticky source refresh"
fi

# DomainStore::remove (finding 4): API DELETE drops DNS match for removed/wild
# domains; keep stays sinkholed; insert/delete churn leaves no residue.
# Arena reclaim verified by unit tests, not this remote smoke.
if enabled "$MOCK_REMOVE_COMPACT_BASELINE"; then
    REMOVE_COMPACT_PREFIX="${RUN_TAG}-rmcompact.rustblocker.test"
    REMOVE_COMPACT_STATUS="running"
    REMOVE_COMPACT_NOTE="post-fix DomainStore::remove compact via API DELETE"
    REMOVE_COMPACT_KEEP_DOMAIN="rmc-1.${REMOVE_COMPACT_PREFIX}"
    REMOVE_COMPACT_REMOVED_DOMAIN="rmc-${REMOVE_COMPACT_DOMAINS}.${REMOVE_COMPACT_PREFIX}"

    if [ "$REMOVE_COMPACT_KEEP" -ge "$REMOVE_COMPACT_DOMAINS" ]; then
        step
        fail "$STEP" "remove-compact-prereq" "REMOVE_COMPACT_KEEP ($REMOVE_COMPACT_KEEP) must be < REMOVE_COMPACT_DOMAINS ($REMOVE_COMPACT_DOMAINS)"
        REMOVE_COMPACT_STATUS="invalid_config"
    fi

    step
    if [ "$REMOVE_COMPACT_STATUS" = "running" ] && remote_resource_snapshot; then
        REMOVE_COMPACT_RSS_BEFORE_KB="$RESOURCE_RSS_KB"
        ok "$STEP" "remove-compact-before" "rss=${REMOVE_COMPACT_RSS_BEFORE_KB}KB domains=$REMOVE_COMPACT_DOMAINS keep=$REMOVE_COMPACT_KEEP churn=$REMOVE_COMPACT_CHURN"
    elif [ "$REMOVE_COMPACT_STATUS" = "running" ]; then
        REMOVE_COMPACT_STATUS="resource_failed"
        fail "$STEP" "remove-compact-before" "could not read process resources before import"
    else
        skip "$STEP" "remove-compact-before" "skipped because prerequisite failed"
    fi

    step
    if [ "$REMOVE_COMPACT_STATUS" = "running" ]; then
        REMOVE_COMPACT_CONTENT=""
        for i in $(seq 1 "$REMOVE_COMPACT_DOMAINS"); do
            REMOVE_COMPACT_CONTENT="${REMOVE_COMPACT_CONTENT}0.0.0.0 rmc-${i}.${REMOVE_COMPACT_PREFIX}\\n"
        done
        # Also exercise wildcard remove path.
        REMOVE_COMPACT_CONTENT="${REMOVE_COMPACT_CONTENT}*.wild.${REMOVE_COMPACT_PREFIX}\\n"
        REMOVE_COMPACT_IMPORT=$("${CURL[@]}" -w "\n%{http_code}" -b "$COOKIE_JAR" \
            -X POST "$BASE_URL/api/blocklist/import" \
            -H "Content-Type: application/json" \
            -d "{\"content\":\"$REMOVE_COMPACT_CONTENT\"}")
        REMOVE_COMPACT_IMPORT_HTTP=$(printf '%s\n' "$REMOVE_COMPACT_IMPORT" | tail -1)
        REMOVE_COMPACT_IMPORT_BODY=$(printf '%s\n' "$REMOVE_COMPACT_IMPORT" | sed '$d')
        REMOVE_COMPACT_IMPORTED=$(printf '%s\n' "$REMOVE_COMPACT_IMPORT_BODY" | json_number "imported")
        if [ "$REMOVE_COMPACT_IMPORT_HTTP" = "200" ] && [ "${REMOVE_COMPACT_IMPORTED:-0}" -ge "$REMOVE_COMPACT_DOMAINS" ]; then
            sleep "$REMOVE_COMPACT_SETTLE_SECS"
            if remote_resource_snapshot; then
                REMOVE_COMPACT_RSS_FULL_KB="$RESOURCE_RSS_KB"
            fi
            ok "$STEP" "remove-compact-import" "imported ${REMOVE_COMPACT_IMPORTED} entries rss_full=${REMOVE_COMPACT_RSS_FULL_KB}KB"
        else
            REMOVE_COMPACT_STATUS="import_failed"
            fail "$STEP" "remove-compact-import" "import failed HTTP=$REMOVE_COMPACT_IMPORT_HTTP body=${REMOVE_COMPACT_IMPORT_BODY:-empty}"
        fi
    else
        skip "$STEP" "remove-compact-import" "skipped because prerequisite failed"
    fi

    step
    if [ "$REMOVE_COMPACT_STATUS" = "running" ]; then
        REMOVE_COMPACT_FULL_DNS=$(target_dns_a "$REMOVE_COMPACT_REMOVED_DOMAIN" 2>/dev/null || true)
        REMOVE_COMPACT_KEEP_DNS=$(target_dns_a "$REMOVE_COMPACT_KEEP_DOMAIN" 2>/dev/null || true)
        REMOVE_COMPACT_WILD_DNS=$(target_dns_a "sub.wild.${REMOVE_COMPACT_PREFIX}" 2>/dev/null || true)
        if echo "$REMOVE_COMPACT_FULL_DNS" | grep -Fxq "$SINKHOLE_IPV4" \
            && echo "$REMOVE_COMPACT_KEEP_DNS" | grep -Fxq "$SINKHOLE_IPV4" \
            && echo "$REMOVE_COMPACT_WILD_DNS" | grep -Fxq "$SINKHOLE_IPV4"; then
            ok "$STEP" "remove-compact-full-dns" "keep/removed/wildcard all sinkholed before delete"
        else
            REMOVE_COMPACT_STATUS="dns_failed"
            fail "$STEP" "remove-compact-full-dns" "expected sinkhole $SINKHOLE_IPV4; keep=${REMOVE_COMPACT_KEEP_DNS:-empty} removed=${REMOVE_COMPACT_FULL_DNS:-empty} wild=${REMOVE_COMPACT_WILD_DNS:-empty}"
        fi
    else
        skip "$STEP" "remove-compact-full-dns" "skipped because import did not complete"
    fi

    step
    if [ "$REMOVE_COMPACT_STATUS" = "running" ]; then
        REMOVE_COMPACT_DELETED=0
        REMOVE_COMPACT_DELETE_OK=true
        # Page prefix and DELETE every non-keep entry (exact + wildcard).
        # Lazy compact in DomainStore makes bulk DELETE cheap enough for default curl timeout.
        for _pass in $(seq 1 40); do
            page=$("${CURL[@]}" -b "$COOKIE_JAR" \
                "$BASE_URL/api/blocklist?search=$REMOVE_COMPACT_PREFIX&limit=250")
            if printf '%s\n' "$page" | grep -q '"domains":\[\]'; then
                break
            fi
            deleted_this_pass=0
            while IFS= read -r obj; do
                [ -z "$obj" ] && continue
                domain=$(printf '%s\n' "$obj" | sed -n 's/.*"domain":"\([^"]*\)".*/\1/p' | head -1)
                id=$(printf '%s\n' "$obj" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p' | head -1)
                [ -n "$domain" ] && [ -n "$id" ] || continue
                # Keep rmc-1..KEEP.<prefix> only.
                case "$domain" in
                    rmc-*.${REMOVE_COMPACT_PREFIX})
                        n=${domain#rmc-}
                        n=${n%%.*}
                        if [ "$n" -ge 1 ] 2>/dev/null && [ "$n" -le "$REMOVE_COMPACT_KEEP" ] 2>/dev/null; then
                            continue
                        fi
                        ;;
                esac
                http_code=$("${CURL[@]}" --max-time 30 -o /dev/null -w "%{http_code}" -b "$COOKIE_JAR" \
                    -X DELETE "$BASE_URL/api/blocklist/$id")
                if [ "$http_code" = "200" ]; then
                    REMOVE_COMPACT_DELETED=$((REMOVE_COMPACT_DELETED + 1))
                    deleted_this_pass=$((deleted_this_pass + 1))
                else
                    REMOVE_COMPACT_DELETE_OK=false
                fi
            done < <(printf '%s\n' "$page" | tr '{' '\n' | grep -F '"domain":' || true)

            leftover_non_keep=0
            check_page=$("${CURL[@]}" -b "$COOKIE_JAR" \
                "$BASE_URL/api/blocklist?search=$REMOVE_COMPACT_PREFIX&limit=250")
            while IFS= read -r obj; do
                [ -z "$obj" ] && continue
                domain=$(printf '%s\n' "$obj" | sed -n 's/.*"domain":"\([^"]*\)".*/\1/p' | head -1)
                [ -n "$domain" ] || continue
                case "$domain" in
                    rmc-*.${REMOVE_COMPACT_PREFIX})
                        n=${domain#rmc-}
                        n=${n%%.*}
                        if [ "$n" -ge 1 ] 2>/dev/null && [ "$n" -le "$REMOVE_COMPACT_KEEP" ] 2>/dev/null; then
                            continue
                        fi
                        ;;
                esac
                leftover_non_keep=$((leftover_non_keep + 1))
            done < <(printf '%s\n' "$check_page" | tr '{' '\n' | grep -F '"domain":' || true)
            if [ "$leftover_non_keep" -eq 0 ]; then
                break
            fi
            if [ "$deleted_this_pass" -eq 0 ]; then
                REMOVE_COMPACT_DELETE_OK=false
                break
            fi
        done
        sleep "$REMOVE_COMPACT_SETTLE_SECS"
        if remote_resource_snapshot; then
            REMOVE_COMPACT_RSS_AFTER_DELETE_KB="$RESOURCE_RSS_KB"
        fi
        expected_deleted=$((REMOVE_COMPACT_DOMAINS - REMOVE_COMPACT_KEEP + 1))
        if [ "$REMOVE_COMPACT_DELETE_OK" = true ] && [ "$REMOVE_COMPACT_DELETED" -ge "$expected_deleted" ]; then
            ok "$STEP" "remove-compact-delete" "deleted ${REMOVE_COMPACT_DELETED} entries via API (expected>=${expected_deleted}) rss_after=${REMOVE_COMPACT_RSS_AFTER_DELETE_KB}KB"
        else
            REMOVE_COMPACT_STATUS="delete_failed"
            fail "$STEP" "remove-compact-delete" "delete incomplete deleted=${REMOVE_COMPACT_DELETED} expected>=${expected_deleted} ok=$REMOVE_COMPACT_DELETE_OK"
        fi
    else
        skip "$STEP" "remove-compact-delete" "skipped because full DNS check failed"
    fi

    step
    if [ "$REMOVE_COMPACT_STATUS" = "running" ]; then
        REMOVE_COMPACT_STICKY_DNS=0
        REMOVE_COMPACT_KEEP_DNS_OK=0
        REMOVE_COMPACT_WILD_STICKY=0
        REMOVE_COMPACT_REMOVED_DNS=""
        REMOVE_COMPACT_KEEP_DNS2=""
        REMOVE_COMPACT_WILD_DNS2=""
        for _try in 1 2 3 4 5; do
            sleep "$REMOVE_COMPACT_SETTLE_SECS"
            REMOVE_COMPACT_REMOVED_DNS=$(target_dns_a "$REMOVE_COMPACT_REMOVED_DOMAIN" 2>/dev/null || true)
            REMOVE_COMPACT_KEEP_DNS2=$(target_dns_a "$REMOVE_COMPACT_KEEP_DOMAIN" 2>/dev/null || true)
            REMOVE_COMPACT_WILD_DNS2=$(target_dns_a "sub.wild.${REMOVE_COMPACT_PREFIX}" 2>/dev/null || true)
            if echo "$REMOVE_COMPACT_KEEP_DNS2" | grep -Fxq "$SINKHOLE_IPV4"; then
                REMOVE_COMPACT_KEEP_DNS_OK=1
            else
                REMOVE_COMPACT_KEEP_DNS_OK=0
            fi
            if echo "$REMOVE_COMPACT_REMOVED_DNS" | grep -Fxq "$SINKHOLE_IPV4"; then
                REMOVE_COMPACT_STICKY_DNS=1
            else
                REMOVE_COMPACT_STICKY_DNS=0
            fi
            if echo "$REMOVE_COMPACT_WILD_DNS2" | grep -Fxq "$SINKHOLE_IPV4"; then
                REMOVE_COMPACT_WILD_STICKY=1
            else
                REMOVE_COMPACT_WILD_STICKY=0
            fi
            if [ "$REMOVE_COMPACT_KEEP_DNS_OK" -eq 1 ] \
                && [ "$REMOVE_COMPACT_STICKY_DNS" -eq 0 ] \
                && [ "$REMOVE_COMPACT_WILD_STICKY" -eq 0 ]; then
                break
            fi
        done
        if [ "$REMOVE_COMPACT_KEEP_DNS_OK" -ne 1 ]; then
            REMOVE_COMPACT_STATUS="dns_failed"
            fail "$STEP" "remove-compact-after-delete" "keep domain no longer sinkholed (got=${REMOVE_COMPACT_KEEP_DNS2:-empty})"
        elif [ "$REMOVE_COMPACT_STICKY_DNS" -ne 0 ] || [ "$REMOVE_COMPACT_WILD_STICKY" -ne 0 ]; then
            REMOVE_COMPACT_STATUS="sticky_dns"
            fail "$STEP" "remove-compact-after-delete" "removed still sinkholed sticky_dns=$REMOVE_COMPACT_STICKY_DNS wild_sticky=$REMOVE_COMPACT_WILD_STICKY removed=${REMOVE_COMPACT_REMOVED_DNS:-empty} wild=${REMOVE_COMPACT_WILD_DNS2:-empty}"
        else
            ok "$STEP" "remove-compact-after-delete" "sticky_dns=0 keep_ok=1 wild_sticky=0 removed_dns=${REMOVE_COMPACT_REMOVED_DNS:-empty}"
        fi
    else
        skip "$STEP" "remove-compact-after-delete" "skipped because delete did not complete"
    fi

    step
    if [ "$REMOVE_COMPACT_STATUS" = "running" ]; then
        # Churn unique insert+delete pairs; compact path must leave no residue.
        # RSS growth is observational only (arena holes << page noise at this scale).
        REMOVE_COMPACT_CHURN_OK=1
        CHURN_BASE="${REMOVE_COMPACT_PREFIX}.churn"
        for i in $(seq 1 "$REMOVE_COMPACT_CHURN"); do
            domain="churn-${i}.${CHURN_BASE}"
            add_resp=$("${CURL[@]}" -w "\n%{http_code}" -b "$COOKIE_JAR" \
                -X POST "$BASE_URL/api/blocklist" \
                -H "Content-Type: application/json" \
                -d "{\"domain\":\"$domain\"}")
            add_http=$(printf '%s\n' "$add_resp" | tail -1)
            add_body=$(printf '%s\n' "$add_resp" | sed '$d')
            add_id=$(printf '%s\n' "$add_body" | json_number "id")
            if [ "$add_http" != "201" ] || [ -z "$add_id" ]; then
                REMOVE_COMPACT_CHURN_OK=0
                break
            fi
            del_http=$("${CURL[@]}" --max-time 30 -o /dev/null -w "%{http_code}" -b "$COOKIE_JAR" \
                -X DELETE "$BASE_URL/api/blocklist/$add_id")
            if [ "$del_http" != "200" ]; then
                REMOVE_COMPACT_CHURN_OK=0
                break
            fi
        done
        sleep "$REMOVE_COMPACT_SETTLE_SECS"
        churn_keep_dns=$(target_dns_a "$REMOVE_COMPACT_KEEP_DOMAIN" 2>/dev/null || true)
        if ! echo "$churn_keep_dns" | grep -Fxq "$SINKHOLE_IPV4"; then
            REMOVE_COMPACT_CHURN_OK=0
        fi
        if remote_resource_snapshot; then
            REMOVE_COMPACT_RSS_AFTER_CHURN_KB="$RESOURCE_RSS_KB"
            if [ "$REMOVE_COMPACT_RSS_AFTER_DELETE_KB" -gt 0 ]; then
                REMOVE_COMPACT_RSS_CHURN_GROWTH_KB=$((REMOVE_COMPACT_RSS_AFTER_CHURN_KB - REMOVE_COMPACT_RSS_AFTER_DELETE_KB))
                [ "$REMOVE_COMPACT_RSS_CHURN_GROWTH_KB" -lt 0 ] && REMOVE_COMPACT_RSS_CHURN_GROWTH_KB=0
            fi
        fi
        leftover=$("${CURL[@]}" -b "$COOKIE_JAR" "$BASE_URL/api/blocklist?search=$CHURN_BASE&limit=1")
        if ! printf '%s\n' "$leftover" | grep -q '"domains":\[\]'; then
            REMOVE_COMPACT_CHURN_OK=0
        fi
        if [ "$REMOVE_COMPACT_CHURN_OK" -ne 1 ]; then
            REMOVE_COMPACT_STATUS="churn_failed"
            fail "$STEP" "remove-compact-churn" "insert/delete churn failed or left residue (rss_note_growth=${REMOVE_COMPACT_RSS_CHURN_GROWTH_KB}KB)"
        else
            REMOVE_COMPACT_STATUS="passed"
            ok "$STEP" "remove-compact-churn" "${REMOVE_COMPACT_CHURN} insert/delete cycles ok keep_sinkholed residue=0 rss_note_growth=${REMOVE_COMPACT_RSS_CHURN_GROWTH_KB}KB rss_after=${REMOVE_COMPACT_RSS_AFTER_CHURN_KB}KB"
        fi
    else
        skip "$STEP" "remove-compact-churn" "skipped because after-delete DNS check failed"
    fi

    step
    remove_compact_cleanup "$REMOVE_COMPACT_PREFIX"
    # Churn used nested prefix; clean that too if residue somehow remains.
    remove_compact_cleanup "${REMOVE_COMPACT_PREFIX}.churn"
    ok "$STEP" "remove-compact-cleanup" "removed temporary domains for $REMOVE_COMPACT_PREFIX"

    step
    write_remove_compact_baseline
    if [ "$REMOVE_COMPACT_STATUS" = "passed" ]; then
        ok "$STEP" "remove-compact-report" "wrote $REMOVE_COMPACT_BASELINE_FILE status=passed deleted=$REMOVE_COMPACT_DELETED churn=$REMOVE_COMPACT_CHURN growth=${REMOVE_COMPACT_RSS_CHURN_GROWTH_KB}KB"
    else
        fail "$STEP" "remove-compact-report" "wrote $REMOVE_COMPACT_BASELINE_FILE status=$REMOVE_COMPACT_STATUS sticky_dns=$REMOVE_COMPACT_STICKY_DNS growth=${REMOVE_COMPACT_RSS_CHURN_GROWTH_KB}KB"
    fi
else
    step
    skip "$STEP" "remove-compact" "hardcoded off (MOCK_REMOVE_COMPACT_BASELINE=false)"
fi

# Sync apply_domains replace_with (finding 5): always-on agent smoke.
# Side slave polls master; after master shrinks blocklist, slave DNS must drop
# removed domains (apply_domains_inner uses replace_with). Capacity reclaim is
# unit-level; this proves the sync apply runtime path.
if enabled "$MOCK_SYNC_APPLY_BASELINE"; then
    SYNC_APPLY_PREFIX="${RUN_TAG}-syncapply.rustblocker.test"
    SYNC_APPLY_STATUS="running"
    SYNC_APPLY_NOTE="post-fix sync apply_domains replace_with via temp slave"
    SYNC_APPLY_KEEP_DOMAIN="sap-1.${SYNC_APPLY_PREFIX}"
    SYNC_APPLY_REMOVED_DOMAIN="sap-${SYNC_APPLY_DOMAINS}.${SYNC_APPLY_PREFIX}"
    SYNC_APPLY_SLAVE_DB="/tmp/rb-sync-apply-$$.db"
    SYNC_APPLY_SLAVE_LOG="/tmp/rb-sync-apply-slave.log"
    SYNC_APPLY_MASTER_URL="http://127.0.0.1:${WEB_PORT}"

    if [ "$SYNC_APPLY_KEEP" -ge "$SYNC_APPLY_DOMAINS" ]; then
        step
        fail "$STEP" "sync-apply-prereq" "SYNC_APPLY_KEEP ($SYNC_APPLY_KEEP) must be < SYNC_APPLY_DOMAINS ($SYNC_APPLY_DOMAINS)"
        SYNC_APPLY_STATUS="invalid_config"
    fi

    # Ensure no leftover slave from a prior aborted run.
    step
    if [ "$SYNC_APPLY_STATUS" = "running" ]; then
        sync_apply_cleanup_slave
        ok "$STEP" "sync-apply-prep" "cleared prior slave state ports=${SYNC_APPLY_SLAVE_DNS_PORT}/${SYNC_APPLY_SLAVE_WEB_PORT}"
    else
        skip "$STEP" "sync-apply-prep" "skipped because prerequisite failed"
    fi

    # Seed master blocklist (full set).
    step
    if [ "$SYNC_APPLY_STATUS" = "running" ]; then
        SYNC_APPLY_CONTENT=""
        for i in $(seq 1 "$SYNC_APPLY_DOMAINS"); do
            SYNC_APPLY_CONTENT="${SYNC_APPLY_CONTENT}0.0.0.0 sap-${i}.${SYNC_APPLY_PREFIX}\\n"
        done
        SYNC_APPLY_IMPORT=$("${CURL[@]}" -w "\n%{http_code}" -b "$COOKIE_JAR" \
            -X POST "$BASE_URL/api/blocklist/import" \
            -H "Content-Type: application/json" \
            -d "{\"content\":\"$SYNC_APPLY_CONTENT\"}")
        SYNC_APPLY_IMPORT_HTTP=$(printf '%s\n' "$SYNC_APPLY_IMPORT" | tail -1)
        SYNC_APPLY_IMPORT_BODY=$(printf '%s\n' "$SYNC_APPLY_IMPORT" | sed '$d')
        SYNC_APPLY_IMPORTED=$(printf '%s\n' "$SYNC_APPLY_IMPORT_BODY" | json_number "imported")
        if [ "$SYNC_APPLY_IMPORT_HTTP" = "200" ] && [ "${SYNC_APPLY_IMPORTED:-0}" -ge "$SYNC_APPLY_DOMAINS" ]; then
            ok "$STEP" "sync-apply-master-import" "master imported ${SYNC_APPLY_IMPORTED} domains"
        else
            SYNC_APPLY_STATUS="import_failed"
            fail "$STEP" "sync-apply-master-import" "import failed HTTP=$SYNC_APPLY_IMPORT_HTTP body=${SYNC_APPLY_IMPORT_BODY:-empty}"
        fi
    else
        skip "$STEP" "sync-apply-master-import" "skipped because prerequisite failed"
    fi

    # Start temp slave on remote host against local master web port.
    step
    if [ "$SYNC_APPLY_STATUS" = "running" ]; then
        SLAVE_BIN="${REMOTE_INSTALL_DIR}/${BINARY_NAME}"
        remote_root "rm -f $(shell_quote "$SYNC_APPLY_SLAVE_DB") $(shell_quote "${SYNC_APPLY_SLAVE_DB}-wal") $(shell_quote "${SYNC_APPLY_SLAVE_DB}-shm") $(shell_quote "$SYNC_APPLY_SLAVE_LOG")" || true
        # Fresh DB seeds its own admin hash; --sync-password is master auth only.
        START_OUT=$(remote_root "nohup $(shell_quote "$SLAVE_BIN") \
            --db-path $(shell_quote "$SYNC_APPLY_SLAVE_DB") \
            --dns-port ${SYNC_APPLY_SLAVE_DNS_PORT} \
            --web-port ${SYNC_APPLY_SLAVE_WEB_PORT} \
            --force-http \
            --sync-master $(shell_quote "$SYNC_APPLY_MASTER_URL") \
            --sync-password $(shell_quote "$WEBUI_PASSWORD") \
            --sync-interval ${SYNC_APPLY_INTERVAL_SECS} \
            >$(shell_quote "$SYNC_APPLY_SLAVE_LOG") 2>&1 & echo \$!" 2>/dev/null || true)
        SYNC_APPLY_SLAVE_PID=$(printf '%s\n' "$START_OUT" | tr -d '[:space:]' | tail -1)
        if [ -n "$SYNC_APPLY_SLAVE_PID" ] && [ "$SYNC_APPLY_SLAVE_PID" -gt 0 ] 2>/dev/null; then
            SLAVE_HEALTHY=false
            for _i in $(seq 1 15); do
                if curl -s --connect-timeout 2 --max-time 3 -o /dev/null -w "%{http_code}" \
                    "http://${SSH_HOST}:${SYNC_APPLY_SLAVE_WEB_PORT}/api/health" 2>/dev/null | grep -q '200'; then
                    SLAVE_HEALTHY=true
                    break
                fi
                sleep 1
            done
            if [ "$SLAVE_HEALTHY" = true ]; then
                ok "$STEP" "sync-apply-slave-start" "slave pid=$SYNC_APPLY_SLAVE_PID dns=${SYNC_APPLY_SLAVE_DNS_PORT} web=${SYNC_APPLY_SLAVE_WEB_PORT}"
            else
                SYNC_APPLY_STATUS="slave_start_failed"
                SLAVE_LOG_TAIL=$(remote_root "tail -n 40 $(shell_quote "$SYNC_APPLY_SLAVE_LOG") 2>/dev/null" 2>/dev/null || true)
                fail "$STEP" "sync-apply-slave-start" "slave health failed pid=${SYNC_APPLY_SLAVE_PID:-?} log=${SLAVE_LOG_TAIL:-empty}"
                sync_apply_cleanup_slave
            fi
        else
            SYNC_APPLY_STATUS="slave_start_failed"
            fail "$STEP" "sync-apply-slave-start" "failed to launch slave (out=${START_OUT:-empty})"
        fi
    else
        skip "$STEP" "sync-apply-slave-start" "skipped because master import failed"
    fi

    # Wait for first sync poll via slave DNS only (/api/sync/status needs auth cookie).
    # Poll loop discards immediate tick → first apply after ~SYNC_APPLY_INTERVAL_SECS.
    step
    if [ "$SYNC_APPLY_STATUS" = "running" ]; then
        SYNC_APPLY_SYNC_OK=false
        for _i in $(seq 1 "$SYNC_APPLY_WAIT_ATTEMPTS"); do
            sleep "$SYNC_APPLY_SETTLE_SECS"
            FULL_DNS=$(remote_dns_a_port "$SYNC_APPLY_REMOVED_DOMAIN" "$SYNC_APPLY_SLAVE_DNS_PORT" 2>/dev/null || true)
            KEEP_DNS=$(remote_dns_a_port "$SYNC_APPLY_KEEP_DOMAIN" "$SYNC_APPLY_SLAVE_DNS_PORT" 2>/dev/null || true)
            if echo "$FULL_DNS" | grep -Fxq "$SINKHOLE_IPV4" \
                && echo "$KEEP_DNS" | grep -Fxq "$SINKHOLE_IPV4"; then
                SYNC_APPLY_FULL_DNS_OK=1
                SYNC_APPLY_SYNC_OK=true
                break
            fi
        done
        if [ "$SYNC_APPLY_SYNC_OK" = true ]; then
            ok "$STEP" "sync-apply-full-sync" "slave DNS full+keep sinkholed on port $SYNC_APPLY_SLAVE_DNS_PORT"
        else
            SYNC_APPLY_STATUS="sync_failed"
            SLAVE_LOG_TAIL=$(remote_root "tail -n 60 $(shell_quote "$SYNC_APPLY_SLAVE_LOG") 2>/dev/null" 2>/dev/null || true)
            fail "$STEP" "sync-apply-full-sync" "slave DNS did not sinkhole full list keep=${KEEP_DNS:-empty} removed=${FULL_DNS:-empty} log=${SLAVE_LOG_TAIL:-empty}"
        fi
    else
        skip "$STEP" "sync-apply-full-sync" "skipped because slave did not start"
    fi

    # Shrink master list: delete domains above KEEP via API.
    step
    if [ "$SYNC_APPLY_STATUS" = "running" ]; then
        SYNC_APPLY_DELETED=0
        SYNC_APPLY_DELETE_OK=true
        for _pass in $(seq 1 40); do
            page=$("${CURL[@]}" -b "$COOKIE_JAR" \
                "$BASE_URL/api/blocklist?search=$SYNC_APPLY_PREFIX&limit=250")
            if printf '%s\n' "$page" | grep -q '"domains":\[\]'; then
                break
            fi
            deleted_this_pass=0
            while IFS= read -r obj; do
                [ -z "$obj" ] && continue
                domain=$(printf '%s\n' "$obj" | sed -n 's/.*"domain":"\([^"]*\)".*/\1/p' | head -1)
                id=$(printf '%s\n' "$obj" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p' | head -1)
                [ -n "$domain" ] && [ -n "$id" ] || continue
                case "$domain" in
                    sap-*.${SYNC_APPLY_PREFIX})
                        n=${domain#sap-}
                        n=${n%%.*}
                        if [ "$n" -ge 1 ] 2>/dev/null && [ "$n" -le "$SYNC_APPLY_KEEP" ] 2>/dev/null; then
                            continue
                        fi
                        ;;
                esac
                http_code=$("${CURL[@]}" --max-time 30 -o /dev/null -w "%{http_code}" -b "$COOKIE_JAR" \
                    -X DELETE "$BASE_URL/api/blocklist/$id")
                if [ "$http_code" = "200" ]; then
                    SYNC_APPLY_DELETED=$((SYNC_APPLY_DELETED + 1))
                    deleted_this_pass=$((deleted_this_pass + 1))
                else
                    SYNC_APPLY_DELETE_OK=false
                fi
            done < <(printf '%s\n' "$page" | tr '{' '\n' | grep -F '"domain":' || true)
            leftover_non_keep=0
            check_page=$("${CURL[@]}" -b "$COOKIE_JAR" \
                "$BASE_URL/api/blocklist?search=$SYNC_APPLY_PREFIX&limit=250")
            while IFS= read -r obj; do
                [ -z "$obj" ] && continue
                domain=$(printf '%s\n' "$obj" | sed -n 's/.*"domain":"\([^"]*\)".*/\1/p' | head -1)
                [ -n "$domain" ] || continue
                case "$domain" in
                    sap-*.${SYNC_APPLY_PREFIX})
                        n=${domain#sap-}
                        n=${n%%.*}
                        if [ "$n" -ge 1 ] 2>/dev/null && [ "$n" -le "$SYNC_APPLY_KEEP" ] 2>/dev/null; then
                            continue
                        fi
                        ;;
                esac
                leftover_non_keep=$((leftover_non_keep + 1))
            done < <(printf '%s\n' "$check_page" | tr '{' '\n' | grep -F '"domain":' || true)
            if [ "$leftover_non_keep" -eq 0 ]; then
                break
            fi
            if [ "$deleted_this_pass" -eq 0 ]; then
                SYNC_APPLY_DELETE_OK=false
                break
            fi
        done
        expected_deleted=$((SYNC_APPLY_DOMAINS - SYNC_APPLY_KEEP))
        if [ "$SYNC_APPLY_DELETE_OK" = true ] && [ "$SYNC_APPLY_DELETED" -ge "$expected_deleted" ]; then
            ok "$STEP" "sync-apply-master-shrink" "master deleted ${SYNC_APPLY_DELETED} (expected>=${expected_deleted})"
        else
            SYNC_APPLY_STATUS="shrink_failed"
            fail "$STEP" "sync-apply-master-shrink" "delete incomplete deleted=${SYNC_APPLY_DELETED} expected>=${expected_deleted} ok=$SYNC_APPLY_DELETE_OK"
        fi
    else
        skip "$STEP" "sync-apply-master-shrink" "skipped because full sync failed"
    fi

    # Wait for slave next poll to apply shrink (replace_with path).
    step
    if [ "$SYNC_APPLY_STATUS" = "running" ]; then
        SYNC_APPLY_STICKY_DNS=1
        SYNC_APPLY_KEEP_DNS_OK=0
        for _i in $(seq 1 "$SYNC_APPLY_WAIT_ATTEMPTS"); do
            sleep "$SYNC_APPLY_SETTLE_SECS"
            REMOVED_DNS=$(remote_dns_a_port "$SYNC_APPLY_REMOVED_DOMAIN" "$SYNC_APPLY_SLAVE_DNS_PORT" 2>/dev/null || true)
            KEEP_DNS2=$(remote_dns_a_port "$SYNC_APPLY_KEEP_DOMAIN" "$SYNC_APPLY_SLAVE_DNS_PORT" 2>/dev/null || true)
            if echo "$KEEP_DNS2" | grep -Fxq "$SINKHOLE_IPV4"; then
                SYNC_APPLY_KEEP_DNS_OK=1
            else
                SYNC_APPLY_KEEP_DNS_OK=0
            fi
            if echo "$REMOVED_DNS" | grep -Fxq "$SINKHOLE_IPV4"; then
                SYNC_APPLY_STICKY_DNS=1
            else
                SYNC_APPLY_STICKY_DNS=0
            fi
            if [ "$SYNC_APPLY_KEEP_DNS_OK" -eq 1 ] && [ "$SYNC_APPLY_STICKY_DNS" -eq 0 ]; then
                break
            fi
        done
        if [ "$SYNC_APPLY_KEEP_DNS_OK" -ne 1 ]; then
            SYNC_APPLY_STATUS="dns_failed"
            fail "$STEP" "sync-apply-after-shrink" "slave keep no longer sinkholed (got=${KEEP_DNS2:-empty})"
        elif [ "$SYNC_APPLY_STICKY_DNS" -ne 0 ]; then
            SYNC_APPLY_STATUS="sticky_dns"
            fail "$STEP" "sync-apply-after-shrink" "slave still sinkholes removed domain (apply_domains did not replace) removed_dns=${REMOVED_DNS:-empty}"
        else
            SYNC_APPLY_STATUS="passed"
            ok "$STEP" "sync-apply-after-shrink" "sticky_dns=0 keep_ok=1 slave applied shrink via replace_with path"
        fi
    else
        skip "$STEP" "sync-apply-after-shrink" "skipped because master shrink failed"
    fi

    step
    # Cleanup master domains + slave process (always).
    if remote_root "command -v sqlite3 >/dev/null 2>&1" >/dev/null 2>&1 \
        || (enabled "$STRESS_INSTALL_SQLITE3" && stress_install_sqlite3 >/dev/null 2>&1); then
        STRESS_CLEANUP_METHOD="sqlite"
        stress_cleanup_blocklist "$SYNC_APPLY_PREFIX" || true
    else
        api_cleanup_blocklist_prefix "$SYNC_APPLY_PREFIX" 250 40 || true
    fi
    sync_apply_cleanup_slave
    ok "$STEP" "sync-apply-cleanup" "removed master prefix + stopped slave"

    step
    write_sync_apply_baseline
    if [ "$SYNC_APPLY_STATUS" = "passed" ]; then
        ok "$STEP" "sync-apply-report" "wrote $SYNC_APPLY_BASELINE_FILE status=passed deleted=$SYNC_APPLY_DELETED sticky_dns=$SYNC_APPLY_STICKY_DNS"
    else
        fail "$STEP" "sync-apply-report" "wrote $SYNC_APPLY_BASELINE_FILE status=$SYNC_APPLY_STATUS sticky_dns=$SYNC_APPLY_STICKY_DNS"
    fi
else
    step
    skip "$STEP" "sync-apply" "hardcoded off (MOCK_SYNC_APPLY_BASELINE=false)"
fi





# Optional blocklist capacity stress. This intentionally grows the deployed
# blocklist until DNS latency/resource thresholds reject a tier, then records
# the last accepted tier and force-cleans the temporary prefix from SQLite.
if enabled "$MOCK_STRESS_BLOCKLIST"; then
    stress_resolve_tiers
    STRESS_BASE="${RUN_TAG}-blocklist-stress.rustblocker.test"
    STRESS_TOTAL=0
    STRESS_LAST_OK=0
    STRESS_FIRST_BAD=0
    STRESS_STATUS="not_started"
    STRESS_BASE_RSS_KB="$RESOURCE_BASE_RSS_KB"
    STRESS_LAST_OK_RSS_GROWTH=0
    STRESS_LAST_OK_P95=0
    STRESS_LAST_OK_MAX=0
    STRESS_LAST_OK_FAILURES=0
    STRESS_LAST_OK_SAMPLES=0
    STRESS_LAST_OK_RSS_KB=0
    STRESS_LAST_OK_THREADS=0
    STRESS_LAST_OK_FDS=0

    step
    if stress_select_cleanup_method; then
        ok "$STEP" "blocklist-stress-prereq" "cleanup method=$STRESS_CLEANUP_METHOD (api cap=$STRESS_API_CLEANUP_MAX_DOMAINS, db=$REMOTE_DB_PATH)"
    else
        fail "$STEP" "blocklist-stress-prereq" "no safe cleanup method: install sqlite3 on target or keep max tier <= STRESS_API_CLEANUP_MAX_DOMAINS ($STRESS_API_CLEANUP_MAX_DOMAINS)"
        STRESS_STATUS="cleanup_unavailable"
    fi

    step
    if [ "$STRESS_STATUS" != "cleanup_unavailable" ] && remote_resource_snapshot; then
        STRESS_BASE_RSS_KB="$RESOURCE_RSS_KB"
        ok "$STEP" "blocklist-stress-baseline" "base=$STRESS_BASE rss=${STRESS_BASE_RSS_KB}KB tiers=$STRESS_RESOLVED_TIERS"
        STRESS_STATUS="running"
    elif [ "$STRESS_STATUS" != "cleanup_unavailable" ]; then
        fail "$STEP" "blocklist-stress-baseline" "could not read process resources before stress"
        STRESS_STATUS="resource_failed"
    else
        skip "$STEP" "blocklist-stress-baseline" "skipped because stress prerequisite failed"
    fi

    if [ "$STRESS_STATUS" = "running" ]; then
        for tier in $STRESS_RESOLVED_TIERS; do
            step
            if [ "$tier" -le "$STRESS_TOTAL" ]; then
                skip "$STEP" "blocklist-stress-tier" "tier $tier already covered by prior imports"
                continue
            fi

            TIER_STARTED_MS=$(now_ms)
            TIER_IMPORT_OK=true
            while [ "$STRESS_TOTAL" -lt "$tier" ]; do
                remaining=$((tier - STRESS_TOTAL))
                batch="$STRESS_BLOCKLIST_BATCH"
                [ "$batch" -gt "$remaining" ] && batch="$remaining"
                if stress_import_blocklist_batch "$STRESS_BASE" $((STRESS_TOTAL + 1)) "$batch"; then
                    STRESS_TOTAL=$((STRESS_TOTAL + STRESS_IMPORTED_BATCH))
                else
                    TIER_IMPORT_OK=false
                    break
                fi
            done
            TIER_IMPORT_MS=$(( $(now_ms) - TIER_STARTED_MS ))

            if [ "$TIER_IMPORT_OK" != true ]; then
                STRESS_FIRST_BAD="$tier"
                STRESS_STATUS="import_failed"
                fail "$STEP" "blocklist-stress-tier" "tier $tier import failed after ${TIER_IMPORT_MS}ms (${STRESS_IMPORT_ERROR:-unknown error})"
                break
            fi

            if ! stress_ensure_blocklist_size "$STRESS_BASE" "$tier"; then
                STRESS_FIRST_BAD="$tier"
                STRESS_STATUS="api_size_failed"
                fail "$STEP" "blocklist-stress-tier" "tier $tier imported but API search did not report expected size"
                break
            fi

            stress_measure_dns_latency "$STRESS_BASE" "$tier" "$STRESS_DNS_SAMPLES"
            if ! remote_resource_snapshot; then
                STRESS_FIRST_BAD="$tier"
                STRESS_STATUS="resource_failed"
                fail "$STEP" "blocklist-stress-tier" "tier $tier could not read process resources"
                break
            fi
            STRESS_RSS_GROWTH=$((RESOURCE_RSS_KB - STRESS_BASE_RSS_KB))
            [ "$STRESS_RSS_GROWTH" -lt 0 ] && STRESS_RSS_GROWTH=0

            if [ "$STRESS_DNS_FAILURES" -gt "$STRESS_DNS_MAX_FAILURES" ] \
                || [ "$STRESS_DNS_P95_MS" -gt "$STRESS_DNS_P95_MAX_MS" ] \
                || [ "$STRESS_DNS_MAX_OBSERVED_MS" -gt "$STRESS_DNS_MAX_MS" ] \
                || [ "$STRESS_RSS_GROWTH" -gt "$STRESS_RSS_GROWTH_MAX_KB" ]; then
                STRESS_FIRST_BAD="$tier"
                STRESS_STATUS="limit_reached"
                ok "$STEP" "blocklist-stress-limit" "tier $tier rejected (p95=${STRESS_DNS_P95_MS}ms max=${STRESS_DNS_MAX_OBSERVED_MS}ms failures=$STRESS_DNS_FAILURES rss_growth=${STRESS_RSS_GROWTH}KB sample=${STRESS_DNS_FAILURE_SAMPLE:-none})"
                break
            fi

            STRESS_LAST_OK="$tier"
            STRESS_LAST_OK_RSS_GROWTH="$STRESS_RSS_GROWTH"
            STRESS_LAST_OK_P95="$STRESS_DNS_P95_MS"
            STRESS_LAST_OK_MAX="$STRESS_DNS_MAX_OBSERVED_MS"
            STRESS_LAST_OK_FAILURES="$STRESS_DNS_FAILURES"
            STRESS_LAST_OK_SAMPLES="$STRESS_DNS_SAMPLE_COUNT"
            STRESS_LAST_OK_RSS_KB="$RESOURCE_RSS_KB"
            STRESS_LAST_OK_THREADS="$RESOURCE_THREADS"
            STRESS_LAST_OK_FDS="$RESOURCE_FDS"
            STRESS_STATUS="passed"
            ok "$STEP" "blocklist-stress-tier" "tier $tier accepted: import=${TIER_IMPORT_MS}ms dns_samples=${STRESS_DNS_SAMPLE_COUNT} p95=${STRESS_DNS_P95_MS}ms max=${STRESS_DNS_MAX_OBSERVED_MS}ms avg=${STRESS_DNS_AVG_MS}ms rss=${RESOURCE_RSS_KB}KB growth=${STRESS_RSS_GROWTH}KB"
        done
    fi

    step
    if [ "$STRESS_TOTAL" -gt 0 ]; then
        if stress_cleanup_blocklist "$STRESS_BASE"; then
            STRESS_LEFTOVER=$("${CURL[@]}" -b "$COOKIE_JAR" "$BASE_URL/api/blocklist?search=$STRESS_BASE&limit=1")
            STRESS_RECOVERY_DNS=$(target_dns_a "stress-1.$STRESS_BASE" 2>/dev/null || true)
            if printf '%s\n' "$STRESS_LEFTOVER" | grep -q '"domains":\[\]' \
                && ! printf '%s\n' "$STRESS_RECOVERY_DNS" | grep -Fxq "$SINKHOLE_IPV4"; then
                ok "$STEP" "blocklist-stress-recovery" "removed stress prefix and restarted service"
            else
                fail "$STEP" "blocklist-stress-recovery" "stress prefix cleanup did not fully recover runtime state (search=${STRESS_LEFTOVER:-empty}, dns=${STRESS_RECOVERY_DNS:-empty})"
            fi
        else
            fail "$STEP" "blocklist-stress-recovery" "failed to force-clean stress prefix $STRESS_BASE"
        fi
    else
        skip "$STEP" "blocklist-stress-recovery" "no stress entries were imported"
    fi

    step
    if [ "$STRESS_LAST_OK" -gt 0 ]; then
        STRESS_DNS_SAMPLE_COUNT="$STRESS_LAST_OK_SAMPLES"
        STRESS_DNS_P95_MS="$STRESS_LAST_OK_P95"
        STRESS_DNS_MAX_OBSERVED_MS="$STRESS_LAST_OK_MAX"
        STRESS_DNS_FAILURES="$STRESS_LAST_OK_FAILURES"
        RESOURCE_RSS_KB="$STRESS_LAST_OK_RSS_KB"
        RESOURCE_THREADS="$STRESS_LAST_OK_THREADS"
        RESOURCE_FDS="$STRESS_LAST_OK_FDS"
        write_stress_baseline "$STRESS_STATUS" "$STRESS_LAST_OK" "$STRESS_FIRST_BAD" "$STRESS_LAST_OK_RSS_GROWTH"
        if [ "$STRESS_LAST_OK" -lt "$STRESS_BASELINE_MIN_DOMAINS" ]; then
            fail "$STEP" "blocklist-stress-baseline" "last accepted tier $STRESS_LAST_OK below required baseline $STRESS_BASELINE_MIN_DOMAINS; wrote $STRESS_BASELINE_FILE"
        else
            ok "$STEP" "blocklist-stress-baseline" "baseline recorded at $STRESS_LAST_OK domains (first rejected=$STRESS_FIRST_BAD, file=$STRESS_BASELINE_FILE)"
        fi
    elif [ "$STRESS_STATUS" = "cleanup_unavailable" ]; then
        skip "$STEP" "blocklist-stress-baseline" "baseline not written because stress prerequisite failed"
    else
        write_stress_baseline "$STRESS_STATUS" 0 "$STRESS_FIRST_BAD" 0
        fail "$STEP" "blocklist-stress-baseline" "no acceptable stress tier found; wrote $STRESS_BASELINE_FILE"
    fi
else
    step
    skip "$STEP" "blocklist-stress" "disabled; set MOCK_STRESS_BLOCKLIST=true to discover blocklist capacity baseline"
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

# --- Panic-free validation: auth.rs hash_password → Result --------------
# change_password previously called AuthState::hash_password(...).expect,
# which panics and kills the worker thread on bcrypt failure.
# Now match Ok/Err and map Err to HTTP 500. Validate every branch.
MOCK_NEW_PASSWORD="MockedNewPass-$(date +%s)$$"

step
REJECT_RESPONSE=$("${CURL[@]}" -w "\n%{http_code}" -b "$COOKIE_JAR" \
    -X PUT "$BASE_URL/api/auth/password" \
    -H "Content-Type: application/json" \
    -d "{\"current_password\":\"wrong-password-$(date +%s)\",\"new_password\":\"ValidNewP1\"}")
REJECT_HTTP=$(printf '%s\n' "$REJECT_RESPONSE" | tail -1)
if [ "$REJECT_HTTP" = "401" ]; then
    ok "$STEP" "auth-change-wrong-current" "wrong current password rejected (HTTP 401)"
else
    fail "$STEP" "auth-change-wrong-current" "expected 401 for wrong current password, got HTTP $REJECT_HTTP"
fi

step
SHORT_RESPONSE=$("${CURL[@]}" -w "\n%{http_code}" -b "$COOKIE_JAR" \
    -X PUT "$BASE_URL/api/auth/password" \
    -H "Content-Type: application/json" \
    -d "{\"current_password\":\"$WEBUI_PASSWORD\",\"new_password\":\"ab\"}")
SHORT_HTTP=$(printf '%s\n' "$SHORT_RESPONSE" | tail -1)
if [ "$SHORT_HTTP" = "400" ]; then
    ok "$STEP" "auth-change-short" "short new password rejected (HTTP 400)"
else
    fail "$STEP" "auth-change-short" "expected 400 for short password, got HTTP $SHORT_HTTP"
fi

step
CHANGE_RESPONSE=$("${CURL[@]}" -w "\n%{http_code}" -b "$COOKIE_JAR" \
    -X PUT "$BASE_URL/api/auth/password" \
    -H "Content-Type: application/json" \
    -d "{\"current_password\":\"$WEBUI_PASSWORD\",\"new_password\":\"$MOCK_NEW_PASSWORD\"}")
CHANGE_HTTP=$(printf '%s\n' "$CHANGE_RESPONSE" | tail -1)
CHANGE_BODY=$(printf '%s\n' "$CHANGE_RESPONSE" | sed '$d')
if [ "$CHANGE_HTTP" = "200" ]; then
    ok "$STEP" "auth-change-valid" "password changed via hash_password Result path (HTTP 200)"
else
    fail "$STEP" "auth-change-valid" "expected 200 for valid password change, got HTTP $CHANGE_HTTP (body: ${CHANGE_BODY:-empty})"
fi

step
RELOGIN_RESPONSE=$("${CURL[@]}" -w "\n%{http_code}" -c "$COOKIE_JAR" \
    -X POST "$BASE_URL/api/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"password\":\"$MOCK_NEW_PASSWORD\"}")
RELOGIN_HTTP=$(printf '%s\n' "$RELOGIN_RESPONSE" | tail -1)
if [ "$RELOGIN_HTTP" = "200" ]; then
    ok "$STEP" "auth-change-relogin" "re-login with new password succeeded (HTTP 200)"
else
    fail "$STEP" "auth-change-relogin" "expected 200 re-login with new password, got HTTP $RELOGIN_HTTP"
fi

step
REVERT_RESPONSE=$("${CURL[@]}" -w "\n%{http_code}" -b "$COOKIE_JAR" \
    -X PUT "$BASE_URL/api/auth/password" \
    -H "Content-Type: application/json" \
    -d "{\"current_password\":\"$MOCK_NEW_PASSWORD\",\"new_password\":\"$WEBUI_PASSWORD\"}")
REVERT_HTTP=$(printf '%s\n' "$REVERT_RESPONSE" | tail -1)
if [ "$REVERT_HTTP" = "200" ]; then
    ok "$STEP" "auth-change-revert" "password reverted to original (HTTP 200)"
else
    fail "$STEP" "auth-change-revert" "expected 200 revert, got HTTP $REVERT_HTTP"
fi

step
RESTORE_RESPONSE=$("${CURL[@]}" -w "\n%{http_code}" -c "$COOKIE_JAR" \
    -X POST "$BASE_URL/api/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"password\":\"$WEBUI_PASSWORD\"}")
RESTORE_HTTP=$(printf '%s\n' "$RESTORE_RESPONSE" | tail -1)
if [ "$RESTORE_HTTP" = "200" ]; then
    ok "$STEP" "auth-change-restore" "session restored with original password (HTTP 200)"
else
    fail "$STEP" "auth-change-restore" "expected 200 restore login, got HTTP $RESTORE_HTTP"
fi

step
if "${CURL[@]}" -o /dev/null -w "%{http_code}" "$BASE_URL/api/health" 2>/dev/null | grep -q '200'; then
    ok "$STEP" "panic-free-health" "health ok after password round-trip, worker survived bcrypt + session rotation"
else
    fail "$STEP" "panic-free-health" "health check failed after password round-trip, worker may have panicked"
fi
# --- Summary ---
echo ""
if [ "$FAILED" -eq 0 ]; then
    ok 99 "summary" "ALL STEPS PASSED"
else
    fail 99 "summary" "SOME STEPS FAILED — see above"
fi

exit $FAILED
