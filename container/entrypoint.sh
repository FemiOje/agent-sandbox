#!/usr/bin/env bash
#
# Container entrypoint. Runs as root for exactly two steps:
#   1. apply the firewall
#   2. replace itself with the main command running as the agent user, with
#      every capability removed (see agent-exec)
# After step 2 no root process is left in the container.

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "[entrypoint] ERROR: must start as root to set up the firewall." >&2
  echo "[entrypoint] Don't set 'user:' for this service in docker-compose.yml." >&2
  exit 1
fi

rm -f /run/sandbox/ready
/usr/local/sbin/init-firewall.sh
touch /run/sandbox/ready

echo "[entrypoint] firewall set; dropping to user '${AGENT_USER:-node}' with no capabilities"
exec /usr/local/sbin/agent-exec "$@"
