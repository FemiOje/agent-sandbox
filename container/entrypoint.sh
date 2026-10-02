#!/usr/bin/env bash
#
# Container entrypoint. Runs as root for exactly three steps:
#   1. start the approval proxy as its own unprivileged user
#   2. apply the firewall
#   3. replace itself with the main command running as the agent user, with
#      every capability removed (see agent-exec)
# After step 3 no root process is left in the container.

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "[entrypoint] ERROR: must start as root to set up the firewall." >&2
  echo "[entrypoint] Don't set 'user:' for this service in docker-compose.yml." >&2
  exit 1
fi

rm -f /run/sandbox/ready

# The proxy gets no capabilities either; the firewall lets only its user
# connect out. The loop restarts it if it ever exits.
proxy_user="${PROXY_USER:-sbxproxy}"
setpriv \
  --reuid="$(id -u "$proxy_user")" --regid="$(id -g "$proxy_user")" --clear-groups \
  --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
  -- sh -c 'while :; do /usr/local/sbin/sandbox-proxy; echo "[proxy] exited; restarting" >&2; sleep 1; done' &
for _ in $(seq 50); do
  timeout 1 bash -c "exec 3<>/dev/tcp/127.0.0.1/${PROXY_PORT:-15001}" 2>/dev/null && break
  sleep 0.2
done

/usr/local/sbin/init-firewall.sh
touch /run/sandbox/ready

echo "[entrypoint] firewall set; dropping to user '${AGENT_USER:-node}' with no capabilities"
exec /usr/local/sbin/agent-exec "$@"
