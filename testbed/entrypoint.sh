#!/bin/sh
# Start charon in the background, then hand over to the command.
#
# The orchestrator drives the run from outside the container (load config,
# initiate, wait, tear down), so this only has to get the daemon up and report
# clearly if it does not.
set -e

echo "[entrypoint] kernel: $(uname -r)"
echo "[entrypoint] role: ${ROLE:-unset}  peer: ${PEER_IP:-unset}"

# charon writes its control socket here; a stale one blocks startup.
rm -f /var/run/charon.vici /var/run/charon.ctl

/usr/lib/strongswan/charon --use-syslog &
CHARON_PID=$!
echo "[entrypoint] charon started as pid ${CHARON_PID}"

# Wait for the vici socket so the orchestrator never races the daemon.
i=0
while [ ! -S /var/run/charon.vici ]; do
  i=$((i + 1))
  if [ "$i" -gt 100 ]; then
    echo "[entrypoint] FATAL: charon vici socket did not appear within 10s" >&2
    exit 1
  fi
  sleep 0.1
done
echo "[entrypoint] vici socket ready after $((i))00ms"

exec "$@"
