#!/bin/sh
# Load the kernel modules the testbed needs, once per Docker Desktop restart.
#
# Why this exists: risk R1 in PLAN.md asked whether containers on this machine
# can do kernel IPsec at all. They can. The WSL2 kernel has CONFIG_XFRM=y built
# in, but ships ESP, AH and PF_KEY as modules (=m) that are not loaded at boot:
#
#     CONFIG_XFRM=y        CONFIG_NET_KEY=m
#     CONFIG_INET_ESP=m    CONFIG_INET_AH=m
#
# A container cannot modprobe for itself, because modules load into the shared
# host kernel and /lib/modules is not in the container image. So this runs one
# throwaway privileged container that enters the Docker VM init namespace and
# loads them there. After that, ordinary containers with CAP_NET_ADMIN can
# install xfrm states and policies normally.
#
# Idempotent: modprobe on an already-loaded module is a no-op.
set -e

MODULES="af_key esp4 ah4 esp6 ah6 xfrm6_tunnel tunnel4 xfrm_user"

echo "[bootstrap] loading IPsec kernel modules into the Docker VM"
docker run --rm --privileged --pid=host alpine:3.20 \
  nsenter -t 1 -m -u -n -i sh -c "
    for m in ${MODULES}; do
      modprobe \$m 2>/dev/null && echo \"  loaded \$m\" || echo \"  FAILED \$m\"
    done
  "

echo "[bootstrap] verifying an ESP SA can actually be installed"
docker run --rm --cap-add=NET_ADMIN alpine:3.20 sh -c '
  apk add -q iproute2 >/dev/null 2>&1
  ip xfrm state add src 10.99.0.1 dst 10.99.0.2 proto esp spi 0x999 mode tunnel \
     enc "cbc(aes)" 0x0123456789abcdef0123456789abcdef \
     auth "hmac(sha256)" 0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
     >/dev/null 2>&1 \
    && { echo "  ESP SA install: OK"; exit 0; } \
    || { echo "  ESP SA install: FAILED" >&2; exit 1; }
'

echo "[bootstrap] ready"
