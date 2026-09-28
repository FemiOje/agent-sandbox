#!/usr/bin/env bash
#
# Default-deny firewall for the sandbox container.
#
# Run as root by entrypoint.sh BEFORE privileges are dropped. The agent never
# has the NET_ADMIN capability, so it cannot change or remove these rules.
#
# Outbound: HTTP/HTTPS only, and only to the IPs of entries in the allowlist
#           (plus GitHub's published IP ranges). DNS only to Docker's upstream
#           resolvers. Everything else is rejected, including your Windows host,
#           WSL and your local network.
# Inbound:  only the published ports (INBOUND_PORTS).
#
# Re-run after editing allowed-domains.txt (from WSL):  ./sandbox firewall

set -euo pipefail

DOMAINS_FILE="${DOMAINS_FILE:-/etc/sandbox/allowed-domains.txt}"
INBOUND_PORTS="${INBOUND_PORTS:-3000,8545}"
OUTBOUND_PORTS="${OUTBOUND_PORTS:-80,443}"
ALLOW_GITHUB_RANGES="${ALLOW_GITHUB_RANGES:-true}"
DNS_ALLOW_ANY="${DNS_ALLOW_ANY:-false}"
VERIFY_ALLOWED_URL="${VERIFY_ALLOWED_URL:-https://registry.npmjs.org}"
VERIFY_BLOCKED_URL="${VERIFY_BLOCKED_URL:-https://example.com}"
IPTABLES="${IPTABLES:-iptables}"          # set to iptables-legacy if nf_tables fails
IP6TABLES="${IPTABLES/iptables/ip6tables}"

log()  { echo "[firewall] $*"; }
warn() { echo "[firewall] WARNING: $*" >&2; }
die()  { echo "[firewall] ERROR: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "must run as root (the agent user cannot change the firewall)"
[ -f "$DOMAINS_FILE" ] || die "allowlist not found at $DOMAINS_FILE"

IPV4_RE='^[0-9]{1,3}(\.[0-9]{1,3}){3}$'
CIDR_RE='^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$'

allowed_file="$(mktemp)"
rules_file="$(mktemp)"
trap 'rm -f "$allowed_file" "$rules_file"' EXIT

# ---------------------------------------------------------------------------
# 1. Work out what to allow. This happens BEFORE the rules change, so on a
#    refresh the old rules stay in force until the new set is swapped in.
# ---------------------------------------------------------------------------
if [ "$ALLOW_GITHUB_RANGES" = "true" ]; then
  log "fetching GitHub IP ranges"
  if meta="$(curl -fsS --connect-timeout 10 https://api.github.com/meta)"; then
    echo "$meta" | jq -r '(.web + .api + .git)[]' | grep -E "$CIDR_RE" >> "$allowed_file" || true
  else
    warn "could not fetch GitHub ranges; relying on DNS for GitHub domains"
  fi
fi

# Entries can be domains, IPv4 addresses or IPv4 CIDRs. Comments, blank lines
# and Windows line endings are ignored.
mapfile -t entries < <(sed -e 's/\r$//' -e 's/#.*//' -e 's/[[:space:]]//g' "$DOMAINS_FILE" | grep -v '^$' || true)
[ "${#entries[@]}" -gt 0 ] || die "no entries in $DOMAINS_FILE"

for entry in "${entries[@]}"; do
  if [[ "$entry" =~ $IPV4_RE || "$entry" =~ $CIDR_RE ]]; then
    echo "$entry" >> "$allowed_file"
    log "allow $entry"
    continue
  fi
  ips="$(getent ahostsv4 "$entry" | awk '{ print $1 }' | sort -u || true)"
  if [ -z "$ips" ]; then
    warn "could not resolve $entry (skipped)"
    continue
  fi
  while read -r ip; do
    [[ "$ip" =~ $IPV4_RE ]] && echo "$ip" >> "$allowed_file"
  done <<< "$ips"
  log "allow $entry -> $(echo "$ips" | tr '\n' ' ')"
done

sort -u -o "$allowed_file" "$allowed_file"
count="$(wc -l < "$allowed_file")"
[ "$count" -gt 0 ] || die "allowlist resolved to zero IPs; refusing to continue"

# DNS. Docker's resolver (127.0.0.11) forwards to the servers listed on the
# "# ExtServers:" line of /etc/resolv.conf. Servers shown as host(x.x.x.x) are
# queried from the host side and need no rule here; plain IPs are queried
# from inside this container, so only those get port 53.
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
# 2. Build the rules and apply them in one atomic step. The nat table is left
#    alone because Docker's embedded DNS relies on rules there.
# ---------------------------------------------------------------------------
{
  echo "*filter"
  echo ":INPUT DROP [0:0]"
  echo ":FORWARD DROP [0:0]"
  echo ":OUTPUT DROP [0:0]"
  echo ":ALLOWLIST - [0:0]"

  # Loopback: local processes and Docker's DNS resolver at 127.0.0.11
  echo "-A INPUT -i lo -j ACCEPT"
  echo "-A OUTPUT -o lo -j ACCEPT"

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

  # Outbound: web ports, and only to allowlisted IPs
  for port in ${OUTBOUND_PORTS//,/ }; do
    echo "-A OUTPUT -p tcp --dport $port -j ALLOWLIST"
  done
  while read -r entry; do
    echo "-A ALLOWLIST -d $entry -j ACCEPT"
  done < "$allowed_file"

  # Everything else: reject, so tools fail fast instead of hanging
  echo "-A OUTPUT -p tcp -j REJECT --reject-with tcp-reset"
  echo "-A OUTPUT -j REJECT --reject-with icmp-admin-prohibited"
  echo "COMMIT"
} > "$rules_file"

"${IPTABLES}-restore" < "$rules_file" \
  || die "${IPTABLES}-restore failed. Try IPTABLES=iptables-legacy in .env (see README)"

if [ "$dns_mode" = "any" ]; then
  dns_desc="any server"
else
  dns_desc="${dns_servers[*]:-none needed (forwarded by Docker)}"
fi
log "applied: $count allowed IPv4 entries; inbound ports [$INBOUND_PORTS]; DNS to [$dns_desc]"

# IPv6 is disabled in docker-compose.yml; block it here too as a backstop.
if command -v "${IP6TABLES}-restore" >/dev/null 2>&1; then
  printf '*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT DROP [0:0]\n-A INPUT -i lo -j ACCEPT\n-A OUTPUT -o lo -j ACCEPT\nCOMMIT\n' \
    | "${IP6TABLES}-restore" 2>/dev/null || warn "could not set IPv6 rules (IPv6 should already be disabled)"
fi

# ---------------------------------------------------------------------------
# 3. Verify. A firewall that lets the blocked URL through is a hard failure:
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
  log "check passed: $VERIFY_ALLOWED_URL is reachable"
else
  warn "$VERIFY_ALLOWED_URL is not reachable (network down, or its IPs changed?)"
fi

log "firewall ready"
