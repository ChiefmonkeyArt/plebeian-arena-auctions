#!/usr/bin/env bash
# Build the self-contained release tarball the Torii Suite installs:
#   plebeian-auctions-<tag>.tar.gz (+ .sha256)
# Layout (flat): MANIFEST.json, bin/arena, bin/arena-frost, web/ (built front end),
# runtime/python/ (CPython 3.12 + Nutshell, hash-pinned, prebuilt wheels only).
# Nothing is built or downloaded on the VPS. Linux x86_64 only.
#   scripts/package.sh <tag> [out dir]
set -euo pipefail
cd "$(dirname "$0")/.."
TAG="${1:?usage: scripts/package.sh <tag> [out dir]}"
OUT="${2:-dist-release}"
[[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || { echo "bad tag $TAG" >&2; exit 1; }
PY="${ARENA_PYTHON:-3.12}"
NAME="plebeian-auctions-${TAG}"
STAGE="$(mktemp -d)"; trap 'rm -rf -- "$STAGE"' EXIT
R="$STAGE/root"; mkdir -p "$R/bin" "$R/runtime"

# 1. Chain binary (static, reproducible flags).
(cd chain && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -ldflags="-s -w" -o "$R/bin/arena" .)

# 1b. FROST signer tool (Rust, static musl so it runs on any x86_64 Linux).
rustup target add x86_64-unknown-linux-musl >/dev/null 2>&1 || true
(cd frost && cargo build --release --locked --target x86_64-unknown-linux-musl)
install -m 0755 frost/target/x86_64-unknown-linux-musl/release/arena-frost "$R/bin/arena-frost"

# 2. Front end.
(cd web && npm ci --no-audit --no-fund --silent && npm run build >/dev/null && node test/page-cost.mjs >/dev/null)
cp -a web/dist "$R/web"

# 3. Mint runtime: a private CPython (python-build-standalone via uv) with
#    Nutshell installed from mint/requirements.txt (hashes required, wheels only).
uv python install "$PY" >/dev/null 2>&1
PYBIN="$(uv python find "$PY")"
PYHOME="$(dirname "$(dirname "$(readlink -f "$PYBIN")")")"
cp -a "$PYHOME" "$R/runtime/python"
P="$R/runtime/python"
rm -f "$P"/lib/python3.*/EXTERNALLY-MANAGED
"$P/bin/python3" -m pip install -q --disable-pip-version-check --no-warn-script-location \
  --require-hashes --only-binary=:all: --no-deps --no-compile -r mint/requirements.txt
install -m 0644 mint/breez_sdk_spark.py "$(echo "$P"/lib/python3.*)/site-packages/breez_sdk_spark.py" # unused Spark backend
"$P/bin/python3" -c 'import cashu.mint.main' # imports cleanly
# Trim what a headless mint never uses.
L="$(echo "$P"/lib/python3.*)"
rm -rf "$P/include" "$P/share" "$P"/lib/tcl* "$P"/lib/tk* "$P"/lib/itcl* "$P"/lib/thread* "$P"/lib/libtcl* "$P"/lib/libtk* \
  "$L/test" "$L/idlelib" "$L/tkinter" "$L/turtledemo" "$L/ensurepip" "$L/lib2to3" "$L/pydoc_data" \
  "$L/site-packages/pip" "$L/site-packages/pip-"* "$L/site-packages/grpc_tools" "$L"/config-*
find "$P" -name '__pycache__' -type d -prune -exec rm -rf {} +
find "$P" -name '*.a' -delete
find "$P/bin" -mindepth 1 ! -name 'python3*' -delete
find "$P" -name '*.so*' -type f -exec strip --strip-unneeded {} +
"$P/bin/python3" -c 'import zstandard, asyncpg, grpc, cryptography.hazmat.bindings._rust, cashu.mint.main' # still loads

# 3b. The FROST tool and the client agree: 3-of-4 key ceremony and signing.
node web/test/frost-roundtrip.mjs "$R/bin/arena-frost" >/dev/null

# 4. Manifest, then a deterministic tarball.
COMMIT="$(git rev-parse HEAD)"
NUT="$(sed -n 's/^cashu==\([0-9.]*\).*/\1/p' mint/requirements.txt | head -1)"
PYV="$("$P/bin/python3" -c 'import platform; print(platform.python_version())')"
FROSTV="$(sed -n 's/^frost-secp256k1-tr = .*version = "=\{0,1\}\([0-9.]*\)".*/\1/p' frost/Cargo.toml | head -1)"
printf '{"name":"plebeian-auctions","tag":"%s","commit":"%s","python":"%s","nutshell":"%s","frost":"frost-secp256k1-tr %s","escrow":"frost-3of4","arch":"x86_64"}\n' \
  "$TAG" "$COMMIT" "$PYV" "$NUT" "$FROSTV" > "$R/MANIFEST.json"
mkdir -p "$OUT"
EPOCH="$(git log -1 --format=%ct)"
tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@${EPOCH}" -C "$R" -cf - . | gzip -9 -n > "$OUT/${NAME}.tar.gz"
(cd "$OUT" && sha256sum "${NAME}.tar.gz" > "${NAME}.tar.gz.sha256")
ls -l "$OUT/${NAME}.tar.gz"; cat "$OUT/${NAME}.tar.gz.sha256"
