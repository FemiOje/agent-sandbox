#!/usr/bin/env bash
#
# Security tests for the running sandbox. Run from WSL:  ./sandbox test
#
# 1. Control checks from your computer (WSL), outside the sandbox: they show
#    each blocked target really is reachable without the firewall, so a
#    "blocked" result below is caused by the sandbox, not by a dead server.
# 2. Agent checks inside the sandbox, run as the agent user through the same
#    path as ./sandbox shell and ./sandbox claude.
# 3. Admin checks as root, confirming the firewall survived the agent's
#    attempts to remove it.
#
# Exits non-zero if any check fails.

set -uo pipefail
cd "$(dirname "$(readlink -f "$0")")/.."

SERVICE=sandbox
export TEST_ALLOWED_URL="${TEST_ALLOWED_URL:-https://registry.npmjs.org}"
export TEST_BLOCKED_URL="${TEST_BLOCKED_URL:-https://example.com}"
export TEST_BLOCKED_PORT_TARGET="${TEST_BLOCKED_PORT_TARGET:-github.com:22}"
export TEST_DNS_SERVER="${TEST_DNS_SERVER:-1.1.1.1}"
HOST_TEST_PORT="${HOST_TEST_PORT:-18999}"

pass=0; fail=0; skip=0
ok()   { echo "PASS  $1"; pass=$((pass + 1)); }
bad()  { echo "FAIL  $1${2:+  ($2)}"; fail=$((fail + 1)); }
skp()  { echo "SKIP  $1${2:+  ($2)}"; skip=$((skip + 1)); }
root_exec() { docker compose exec -T "$SERVICE" "$@"; }

tcp_connect() { timeout 6 bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null; }
dns_query() {
  python3 - "$1" <<'PY'
import socket, sys
q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
try:
    s.sendto(q, (sys.argv[1], 53)); s.recvfrom(512)
except Exception:
    sys.exit(1)
PY
}

listener_pid=""
cleanup() { [ -n "$listener_pid" ] && kill "$listener_pid" 2>/dev/null; }
trap cleanup EXIT

echo "== Sandbox status"
state="$(docker compose ps --format '{{.Health}}' "$SERVICE" 2>/dev/null | head -1)"
if [ "$state" = "healthy" ]; then ok "sandbox is running and the firewall is ready"
else
  bad "sandbox is running and healthy" "health: ${state:-not running}. Start it with ./sandbox up"
  echo; echo "Summary: $pass passed, $fail failed, $skip skipped"; exit 1
fi
if docker compose logs "$SERVICE" 2>/dev/null | grep -q "dropping to user"; then
  ok "entrypoint applied the firewall, then dropped root"
else
  bad "entrypoint dropped root" "log line not found"
fi

echo "== Controls (from WSL, outside the sandbox)"
if curl -s --connect-timeout 6 --max-time 10 -o /dev/null "$TEST_BLOCKED_URL"; then
  ok "control: $TEST_BLOCKED_URL is reachable from WSL"
else
  skp "control: $TEST_BLOCKED_URL reachable from WSL" "unreachable, so its block test proves less"
fi
if tcp_connect "${TEST_BLOCKED_PORT_TARGET%:*}" "${TEST_BLOCKED_PORT_TARGET##*:}"; then
  ok "control: $TEST_BLOCKED_PORT_TARGET is reachable from WSL"
else
  skp "control: $TEST_BLOCKED_PORT_TARGET reachable from WSL" "unreachable, so its block test proves less"
fi
if command -v python3 >/dev/null 2>&1 && dns_query "$TEST_DNS_SERVER"; then
  ok "control: DNS server $TEST_DNS_SERVER answers from WSL"
else
  skp "control: DNS server $TEST_DNS_SERVER answers from WSL" "no answer or no python3"
fi

# A throwaway web server on your computer. If the sandbox can't reach it
# while WSL can, the sandbox has no network path to your machine.
gw_hex="$(root_exec awk '$2 == "00000000" { print $3; exit }' /proc/net/route | tr -d '\r')"
HOST_TEST_IP=""
if [[ "$gw_hex" =~ ^[0-9A-Fa-f]{8}$ ]]; then
  HOST_TEST_IP="$(printf '%d.%d.%d.%d' "0x${gw_hex:6:2}" "0x${gw_hex:4:2}" "0x${gw_hex:2:2}" "0x${gw_hex:0:2}")"
fi
if [ -n "$HOST_TEST_IP" ] && command -v python3 >/dev/null 2>&1; then
  python3 -m http.server "$HOST_TEST_PORT" --bind 0.0.0.0 >/dev/null 2>&1 &
  listener_pid=$!
  sleep 1
  if tcp_connect "$HOST_TEST_IP" "$HOST_TEST_PORT"; then
    ok "control: test server on your computer is reachable at $HOST_TEST_IP:$HOST_TEST_PORT"
  else
    skp "control: test server on your computer" "not reachable even from WSL"
  fi
else
  skp "control: test server on your computer" "no python3 or gateway IP"
  HOST_TEST_IP=""
fi

rules_before="$(root_exec iptables -S | tr -d '\r')"

echo
agent_out="$(docker compose exec -T \
  -e TEST_ALLOWED_URL -e TEST_BLOCKED_URL -e TEST_BLOCKED_PORT_TARGET -e TEST_DNS_SERVER \
  -e HOST_TEST_IP="$HOST_TEST_IP" -e HOST_TEST_PORT="$HOST_TEST_PORT" \
  "$SERVICE" agent-exec bash -s < tests/agent-checks.sh | tr -d '\r')"
echo "$agent_out" | grep -v '^RESULT '
if read -r _ p f s < <(echo "$agent_out" | grep '^RESULT '); then
  pass=$((pass + p)); fail=$((fail + f)); skip=$((skip + s))
else
  bad "agent checks ran to completion" "no result line"
fi

echo
echo "== Admin checks (root, for comparison)"
bnd="$(root_exec grep '^CapBnd' /proc/self/status | awk '{ print $2 }' | tr -d '\r')"
if [ -n "$bnd" ] && (( (16#$bnd >> 12) & 1 )); then
  ok "admin shell (you, via ./sandbox admin) still holds NET_ADMIN, so only you can change the firewall"
else
  bad "admin shell holds NET_ADMIN" "CapBnd=$bnd"
fi
rules_after="$(root_exec iptables -S | tr -d '\r')"
if echo "$rules_after" | grep -q -- '-P OUTPUT DROP' && echo "$rules_after" | grep -q -- '-P INPUT DROP'; then
  ok "firewall is active: default policy is DROP"
else
  bad "firewall default policy is DROP"
fi
if [ -n "$rules_before" ] && [ "$rules_before" = "$rules_after" ]; then
  ok "firewall rules are unchanged after the agent tried to remove them ($(echo "$rules_after" | wc -l) rules)"
else
  bad "firewall rules unchanged after the agent's attempts"
fi

echo
echo "Summary: $pass passed, $fail failed, $skip skipped"
[ "$fail" -eq 0 ]
