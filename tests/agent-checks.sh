#!/usr/bin/env bash
#
# Checks that run INSIDE the sandbox as the agent user (started through
# agent-exec, exactly like ./sandbox shell and ./sandbox claude).
# Called by tests/run-tests.sh; not meant to be run on its own.
#
# Output: one line per check ("PASS  ...", "FAIL  ...", "SKIP  ..."),
# then "RESULT <pass> <fail> <skip>".

set -u

TEST_ALLOWED_URL="${TEST_ALLOWED_URL:-https://registry.npmjs.org}"
TEST_BLOCKED_URL="${TEST_BLOCKED_URL:-https://example.com}"
TEST_BLOCKED_PORT_TARGET="${TEST_BLOCKED_PORT_TARGET:-github.com:22}"
TEST_DNS_SERVER="${TEST_DNS_SERVER:-1.1.1.1}"
HOST_TEST_IP="${HOST_TEST_IP:-}"
HOST_TEST_PORT="${HOST_TEST_PORT:-}"
TEST_GATEWAY_IP="${TEST_GATEWAY_IP:-}"
TEST_REBIND_HOST="${TEST_REBIND_HOST:-localtest.me}"
PROXY_USER="${PROXY_USER:-sbxproxy}"
PROXY_PORT="${PROXY_PORT:-15001}"

pass=0; fail=0; skip=0
ok()   { echo "PASS  $1"; pass=$((pass + 1)); }
bad()  { echo "FAIL  $1${2:+  ($2)}"; fail=$((fail + 1)); }
skp()  { echo "SKIP  $1${2:+  ($2)}"; skip=$((skip + 1)); }
# expect_ok NAME CMD...    -> PASS if CMD succeeds
# expect_fail NAME CMD...  -> PASS if CMD fails
expect_ok()   { local n="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$n"; else bad "$n"; fi; }
expect_fail() { local n="$1"; shift; if "$@" >/dev/null 2>&1; then bad "$n" "it succeeded"; else ok "$n"; fi; }

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
caps_zero() {  # all five capability sets of a process are empty
  local f="/proc/$1/status"
  [ "$(grep -cE '^Cap(Inh|Prm|Eff|Bnd|Amb):[[:space:]]+0000000000000000$' "$f")" -eq 5 ]
}

echo "== Privileges: root has been revoked from the agent"
if [ "$(id -u)" -ne 0 ]; then ok "runs as non-root user '$(id -un)' (uid $(id -u))"; else bad "runs as non-root" "uid 0"; fi
if caps_zero self; then ok "holds no capabilities, and its bounding set is empty (can never regain any)"
else bad "holds no capabilities" "$(grep ^Cap /proc/self/status | tr '\n' ' ')"; fi
if grep -qE '^NoNewPrivs:[[:space:]]+1$' /proc/self/status; then ok "no_new_privs is set (running a program can't grant privileges)"
else bad "no_new_privs is set"; fi
pid1_user="$(stat -c %U /proc/1)"
if [ "$pid1_user" != "root" ] && caps_zero 1; then ok "the container's main process (PID 1) runs as '$pid1_user' with no capabilities"
else bad "PID 1 is unprivileged" "owner $pid1_user"; fi
root_procs="$(ps -eo uid=,pid=,comm= | awk '$1 == 0 && $3 != "test" { print $2 "/" $3 }' | tr '\n' ' ')"
if [ -z "$root_procs" ]; then ok "no process in the container runs as root"; else bad "no root processes" "$root_procs"; fi
suid="$(find / -xdev -perm /6000 -type f 2>/dev/null | head -5 | tr '\n' ' ')"
if [ -z "$suid" ]; then ok "no setuid/setgid programs exist"; else bad "no setuid/setgid programs" "$suid"; fi
if command -v sudo >/dev/null 2>&1; then bad "sudo is not installed"; else ok "sudo is not installed"; fi
expect_fail "cannot become root with su" timeout 5 su -c true root </dev/null
expect_fail "cannot switch to uid 0 with setpriv" setpriv --reuid=0 true
expect_fail "cannot give itself NET_ADMIN" setpriv --inh-caps=+net_admin --ambient-caps=+net_admin true

echo "== Firewall: the agent cannot see, change or remove it"
expect_fail "cannot read the firewall rules (iptables -S)" iptables -S
expect_fail "cannot flush the rules (iptables -F)" iptables -F
expect_fail "cannot set the default policy to ACCEPT" iptables -P OUTPUT ACCEPT
if command -v iptables-legacy >/dev/null 2>&1; then
  expect_fail "cannot use the legacy iptables backend either" iptables-legacy -F
fi
open_all="$(printf '*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n')"
if printf '%s\n' "$open_all" | iptables-restore >/dev/null 2>&1; then bad "cannot load an allow-all ruleset" "it succeeded"
else ok "cannot load an allow-all ruleset (iptables-restore)"; fi
expect_fail "cannot re-run the firewall script" /usr/local/sbin/init-firewall.sh
expect_fail "cannot edit the allowlist (mounted read-only)" sh -c 'echo evil.example >> /etc/sandbox/allowed-domains.txt'
expect_fail "cannot modify the firewall script" sh -c ': >> /usr/local/sbin/init-firewall.sh'
expect_fail "cannot modify the privilege-drop script" sh -c ': >> /usr/local/sbin/agent-exec'
expect_fail "cannot modify the entrypoint" sh -c ': >> /usr/local/sbin/entrypoint.sh'

echo "== Approval proxy: the agent cannot get around it or answer for you"
proxy_pids="$(pgrep -u "$PROXY_USER" | tr '\n' ' ')"
proxy_caps_ok=true
for pid in $proxy_pids; do caps_zero "$pid" || proxy_caps_ok=false; done
if [ -n "$proxy_pids" ] && $proxy_caps_ok; then ok "the proxy runs as '$PROXY_USER' with no capabilities"
else bad "the proxy runs unprivileged" "pids: ${proxy_pids:-none}"; fi
# shellcheck disable=SC2086
expect_fail "cannot stop the proxy" kill -TERM $proxy_pids
expect_fail "cannot read the approval queue" ls /run/sandbox/proxy/pending
expect_fail "cannot write its own approval" sh -c 'echo allow > /run/sandbox/proxy/decisions/evil.example.org'
expect_fail "cannot approve through proxy-ctl" proxy-ctl allow evil.example.org
expect_fail "cannot modify the proxy" sh -c ': >> /usr/local/sbin/sandbox-proxy'
allowed_host="$(echo "$TEST_ALLOWED_URL" | sed -E 's#^[a-z]+://##; s#[:/].*$##')"
expect_fail "cannot use the proxy port directly (127.0.0.1:$PROXY_PORT)" \
  curl -s --max-time 10 -o /dev/null --connect-to "$allowed_host:443:127.0.0.1:$PROXY_PORT" "$TEST_ALLOWED_URL"
expect_fail "a bare IP with no hostname is refused (https://$TEST_DNS_SERVER)" \
  curl -sk --max-time 10 -o /dev/null "https://$TEST_DNS_SERVER"

echo "== Host: no access to your computer's files or Docker"
if [ ! -e /var/run/docker.sock ] && [ ! -e /run/docker.sock ]; then ok "no Docker socket (can't start containers on the host)"
else bad "no Docker socket" "socket present"; fi
if [ ! -e /mnt/c ] && [ ! -e /mnt/wsl ]; then ok "Windows/WSL drives are not mounted (/mnt/c, /mnt/wsl)"; else bad "Windows/WSL drives not mounted"; fi
expected="/ /etc/resolv.conf /etc/hostname /etc/hosts /etc/sandbox/allowed-domains.txt /home/node/work /home/node/.claude"
unexpected=""
while read -r mp; do
  case "$mp" in /proc|/proc/*|/sys|/sys/*|/dev|/dev/*) continue ;; esac
  case " $expected " in *" $mp "*) ;; *) unexpected="$unexpected $mp" ;; esac
done < <(awk '{ print $5 }' /proc/self/mountinfo)
if [ -z "$unexpected" ]; then ok "only the expected mounts exist (allowlist read-only + 2 Docker volumes)"
else bad "only expected mounts" "unexpected:$unexpected"; fi

echo "== Network: default deny"
expect_ok  "DNS works through Docker's resolver ($allowed_host)" getent hosts "$allowed_host"
expect_ok   "allowlisted site is reachable ($TEST_ALLOWED_URL)" curl -s --connect-timeout 10 --max-time 20 -o /dev/null "$TEST_ALLOWED_URL"
expect_fail "other sites are blocked ($TEST_BLOCKED_URL)" curl -s --connect-timeout 6 --max-time 10 -o /dev/null "$TEST_BLOCKED_URL"
expect_fail "non-web ports are blocked, even to allowed hosts ($TEST_BLOCKED_PORT_TARGET)" tcp_connect "${TEST_BLOCKED_PORT_TARGET%:*}" "${TEST_BLOCKED_PORT_TARGET##*:}"
expect_fail "direct DNS to outside servers is blocked ($TEST_DNS_SERVER:53)" dns_query "$TEST_DNS_SERVER"
if [ -n "$HOST_TEST_IP" ] && [ -n "$HOST_TEST_PORT" ]; then
  expect_fail "your computer (WSL host) is unreachable ($HOST_TEST_IP:$HOST_TEST_PORT)" tcp_connect "$HOST_TEST_IP" "$HOST_TEST_PORT"
else
  skp "your computer (WSL host) is unreachable" "the control found no path to test, so this would prove nothing"
fi

echo "== Local hosts: refused on web ports too, without asking you"
# Each goes through the proxy over plain HTTP, so its 403 says why.
proxy_says() { curl -s --max-time 10 "$@" 2>/dev/null; }
if [ -n "$TEST_GATEWAY_IP" ]; then
  out="$(proxy_says "http://$TEST_GATEWAY_IP/")"
  case "$out" in *"never allowed"*) ok "your computer's address is refused (http://$TEST_GATEWAY_IP/)" ;;
    *) bad "your computer's address is refused (http://$TEST_GATEWAY_IP/)" "${out:-no answer}" ;; esac
else
  skp "your computer's address is refused on port 80" "no gateway address found"
fi
out="$(proxy_says --resolve "host.docker.internal:80:$TEST_DNS_SERVER" http://host.docker.internal/)"
case "$out" in *"never allowed"*) ok "local network names are refused (host.docker.internal)" ;;
  *) bad "local network names are refused (host.docker.internal)" "${out:-no answer}" ;; esac
# A public name that points at a local address. The client is told to go to
# a public IP, so only the proxy's own lookup can catch it.
out="$(proxy_says --resolve "$TEST_REBIND_HOST:80:$TEST_DNS_SERVER" "http://$TEST_REBIND_HOST/")"
case "$out" in
  *"resolves to local address"*) ok "public names that resolve to local addresses are refused ($TEST_REBIND_HOST)" ;;
  *"does not resolve"*) skp "public names that resolve to local addresses are refused" "$TEST_REBIND_HOST does not resolve" ;;
  *) bad "public names that resolve to local addresses are refused ($TEST_REBIND_HOST)" "${out:-no answer}" ;;
esac

if [ ! -d /proc/sys/net/ipv6 ]; then ok "IPv6 is unavailable (kernel has no IPv6; no way around the IPv4 rules)"
elif [ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null)" = "1" ]; then ok "IPv6 is disabled (no way around the IPv4 rules)"
else bad "IPv6 is disabled"; fi

echo "RESULT $pass $fail $skip"
