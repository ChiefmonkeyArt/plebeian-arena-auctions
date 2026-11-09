#!/usr/bin/env bash
# Foreground entry point: ensure the fake-sats mint is up, then run the gateway (which supervises 4 validators).
cd "$(dirname "$0")"
if ! curl -sf 127.0.0.1:3338/v1/info >/dev/null; then ./scripts.sh mint; for i in $(seq 1 30); do curl -sf 127.0.0.1:3338/v1/info >/dev/null && break; sleep 1; done; fi
[ -d run/chain/v1 ] || ./bin/arena init -root run/chain
exec ./bin/arena gateway -root run/chain -static web/dist -addr 0.0.0.0:${PORT:-8080}
