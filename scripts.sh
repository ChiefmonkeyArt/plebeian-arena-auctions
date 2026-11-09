#!/usr/bin/env bash
# Arena auctions demo control: ./scripts.sh build|reset|start|stop|test
set -e; cd "$(dirname "$0")"; export PATH=/tmp/go/bin:$PATH
case "$1" in
  build) (cd chain && go build -o ../bin/arena .) && (cd web && npm run build >/dev/null) && echo built ;;
  mint)  set -a; . run/mint.env; set +a; (set -m; nohup .venv-mint/bin/mint > run/mint.log 2>&1 &) ;;
  stop)  pkill -TERM -f "bin/arena gateway" || true; sleep 2; pkill -TERM -f "bin/arena node" || true ;;
  reset) $0 stop; sleep 1; ./bin/arena init -root run/chain ;;
  start) (set -m; nohup ./bin/arena gateway -root run/chain -static web/dist -addr 0.0.0.0:${PORT:-8080} > run/gateway.log 2>&1 &); sleep 4; curl -s 127.0.0.1:${PORT:-8080}/api/network | head -c 200; echo ;;
  test)  node tests/e2e.mjs "http://127.0.0.1:${PORT:-8080}" ;;
esac
