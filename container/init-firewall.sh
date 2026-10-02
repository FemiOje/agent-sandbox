#!/usr/bin/env bash
#
# Default-deny firewall for the sandbox container.
#
# Run as root by entrypoint.sh BEFORE privileges are dropped. The agent never
# has the NET_ADMIN capability, so it cannot change or remove these rules.
#
# Outbound: web connections (OUTBOUND_PORTS) from everyone, root included, are
#           redirected to the approval proxy (sandbox-proxy), which decides by
#           hostname: allowed-domains.txt, or your answer in ./sandbox approve.
#           Only the proxy's own user may connect out, only on those ports,
#           and never to private, loopback or link-local addresses (your
#           Windows host, WSL, your local network, Docker's networks). DNS
#           only to Docker's upstream resolvers. Everything else is rejected.
# Inbound:  only the published ports (INBOUND_PORTS).
#
# The proxy rereads allowed-domains.txt by itself. Re-run this (from WSL:
# ./sandbox firewall) only to re-apply the rules.

set -euo pipefail

DOMAINS_FILE="${DOMAINS_FILE:-/etc/sandbox/allowed-domains.txt}"
INBOUND_PORTS="${INBOUND_PORTS:-3000,8545}"
OUTBOUND_PORTS="${OUTBOUND_PORTS:-80,443}"
PROXY_USER="${PROXY_USER:-sbxproxy}"
PROXY_PORT="${PROXY_PORT:-15001}"
DNS_ALLOW_ANY="${DNS_ALLOW_ANY:-false}"
VERIFY_ALLOWED_URL="${VERIFY_ALLOWED_URL:-https://registry.npmjs.org}"
VERIFY_BLOCKED_URL="${VERIFY_BLOCKED_URL:-https://example.com}"
IPTABLES="${IPTABLES:-iptables}"          # set to iptables-legacy if nf_tables fails
IP6TABLES="${IPTABLES/iptables/ip6tables}"

# Addresses the proxy may never connect to, even for an allowed name. The
# proxy refuses them too; this is the backstop.
LOCAL_NETS="0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12
            192.0.0.0/24 192.168.0.0/16 198.18.0.0/15 224.0.0.0/4 240.0.0.0/4"

log()  { echo "[firewall] $*"; }
warn() { echo "[firewall] WARNING: $*" >&2; }
die()  { echo "[firewall] ERROR: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "must run as root (the agent user cannot change the firewall)"
[ -f "$DOMAINS_FILE" ] || die "allowlist not found at $DOMAINS_FILE"
id -u "$PROXY_USER" >/dev/null 2>&1 || die "proxy user '$PROXY_USER' does not exist (rebuild the image)"
timeout 3 bash -c "exec 3<>/dev/tcp/127.0.0.1/$PROXY_PORT" 2>/dev/null \
  || die "the approval proxy is not listening on 127.0.0.1:$PROXY_PORT"

IPV4_RE='^[0-9]{1,3}(\.[0-9]{1,3}){3}$'

rules_file="$(mktemp)"
trap 'rm -f "$rules_file"' EXIT

# ---------------------------------------------------------------------------
# 1. DNS. Docker's resolver (127.0.0.11) forwards to the servers listed on
#    the "# ExtServers:" line of /etc/resolv.conf. Servers shown as
#    host(x.x.x.x) are queried from the host side and need no rule here;
#    plain IPs are queried from inside this container, so only those get
#    port 53.
# ---------------------------------------------------------------------------
dns_servers=()
dns_mode="restricted"
if [ "$DNS_ALLOW_ANY" = "true" ]; then
  dns_mode="any"
elif ext="$(grep -m1 '^# ExtServers:' /etc/resolv.conf)"; then
  for token in $(echo "$ext" | sed -e 's/^# ExtServers://' -e 's/[][]//g'); do
    [[ "$token" =~ $IPV4_RE ]] && dns_servers+=("$token")
  done
else
  # No internal resolver info: use plain nameserver lines instead.
  while read -r ns; do
    [[ "$ns" =~ $IPV4_RE && ! "$ns" =~ ^127\. ]] && dns_servers+=("$ns")
  done < <(awk '/^nameserver/ { print $2 }' /etc/resolv.conf)
  if [ "${#dns_servers[@]}" -eq 0 ]; then
    warn "could not find the upstream DNS servers; allowing DNS to any server"
    dns_mode="any"
  fi
fi

# ---------------------------------------------------------------------------
# 2. Filter rules, applied in one atomic step.
# ---------------------------------------------------------------------------
{
  echo "*filter"
  echo ":INPUT DROP [0:0]"
  echo ":FORWARD DROP [0:0]"
  echo ":OUTPUT DROP [0:0]"
  echo ":PROXY_OUT - [0:0]"

  # Loopback: local processes, the proxy, and Docker's DNS resolver
  echo "-A INPUT -i lo -j ACCEPT"
  echo "-A OUTPUT -o lo -j ACCEPT"
  # Connections the nat rules below redirected to the proxy. They still show
  # their original interface here, so the loopback rule doesn't match them.
  echo "-A OUTPUT -d 127.0.0.1 -p tcp --dport $PROXY_PORT -m conntrack --ctstate DNAT -j ACCEPT"

  # Replies to connections that were already allowed
  echo "-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
  echo "-A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"

  # DNS
  if [ "$dns_mode" = "any" ]; then
    echo "-A OUTPUT -p udp --dport 53 -j ACCEPT"
    echo "-A OUTPUT -p tcp --dport 53 -j ACCEPT"
  else
    for ns in "${dns_servers[@]}"; do
      echo "-A OUTPUT -d $ns -p udp --dport 53 -j ACCEPT"
      echo "-A OUTPUT -d $ns -p tcp --dport 53 -j ACCEPT"
    done
  fi

  # Inbound: published ports only
  for port in ${INBOUND_PORTS//,/ }; do
    echo "-A INPUT -p tcp --dport $port -m conntrack --ctstate NEW -j ACCEPT"
  done

  # Outbound: only the proxy, only web ports, only public addresses
  echo "-A OUTPUT -m owner --uid-owner $PROXY_USER -j PROXY_OUT"
  for net in $LOCAL_NETS; do
    echo "-A PROXY_OUT -d $net -p tcp -j REJECT --reject-with tcp-reset"
  done
  for port in ${OUTBOUND_PORTS//,/ }; do
    echo "-A PROXY_OUT -p tcp --dport $port -j ACCEPT"
  done

  # Everything else: reject, so tools fail fast instead of hanging
  echo "-A OUTPUT -p tcp -j REJECT --reject-with tcp-reset"
  echo "-A OUTPUT -j REJECT --reject-with icmp-admin-prohibited"
  echo "COMMIT"
} > "$rules_file"

"${IPTABLES}-restore" < "$rules_file" \
  || die "${IPTABLES}-restore failed. Try IPTABLES=iptables-legacy in .env (see README)"

# ---------------------------------------------------------------------------
# 3. Redirect web connections to the proxy. Its own chain in the nat table,
#    so Docker's DNS rules there stay untouched. While this is rebuilt, web
#    traffic simply hits the REJECT above: it fails closed.
# ---------------------------------------------------------------------------
nat() { "$IPTABLES" -t nat "$@"; }
nat -N SANDBOX_PROXY 2>/dev/null || true
nat -F SANDBOX_PROXY
nat -A SANDBOX_PROXY -d 127.0.0.0/8 -j RETURN
nat -A SANDBOX_PROXY -m owner --uid-owner "$PROXY_USER" -j RETURN
nat -A SANDBOX_PROXY -p tcp -m multiport --dports "$OUTBOUND_PORTS" -j REDIRECT --to-ports "$PROXY_PORT"
nat -C OUTPUT -j SANDBOX_PROXY 2>/dev/null || nat -I OUTPUT 1 -j SANDBOX_PROXY

if [ "$dns_mode" = "any" ]; then
  dns_desc="any server"
else
  dns_desc="${dns_servers[*]:-none needed (forwarded by Docker)}"
fi
log "applied: web ports [$OUTBOUND_PORTS] go through the approval proxy; inbound ports [$INBOUND_PORTS]; DNS to [$dns_desc]"

# IPv6 is disabled in docker-compose.yml; block it here too as a backstop.
if command -v "${IP6TABLES}-restore" >/dev/null 2>&1; then
  printf '*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT DROP [0:0]\n-A INPUT -i lo -j ACCEPT\n-A OUTPUT -o lo -j ACCEPT\nCOMMIT\n' \
    | "${IP6TABLES}-restore" 2>/dev/null || warn "could not set IPv6 rules (IPv6 should already be disabled)"
fi

# ---------------------------------------------------------------------------
# 4. Verify. A firewall that lets the blocked URL through is a hard failure:
#    the container stops rather than running unprotected.
# ---------------------------------------------------------------------------
if curl -s --connect-timeout 5 --max-time 10 -o /dev/null "$VERIFY_BLOCKED_URL"; then
  die "verification failed: $VERIFY_BLOCKED_URL is reachable"
fi
log "check passed: $VERIFY_BLOCKED_URL is blocked"

allowed_host="$(echo "$VERIFY_ALLOWED_URL" | sed -E 's#^[a-z]+://##; s#[:/].*$##')"
if ! getent hosts "$allowed_host" >/dev/null; then
  die "DNS stopped working after the firewall was applied. Set DNS_ALLOW_ANY=true in .env and restart"
fi
if curl -s --connect-timeout 10 --max-time 20 -o /dev/null "$VERIFY_ALLOWED_URL"; then
  log "check passed: $VERIFY_ALLOWED_URL is reachable through the proxy"
else
  warn "$VERIFY_ALLOWED_URL is not reachable (network down, or not in allowed-domains.txt?)"
fi

log "firewall ready"
