#!/bin/sh
# Idempotent uninstaller for ALT macOS package and system integration.
# Leaves Caddy, 127.0.0.1, *:443, and user owner keys intact (pass --purge-state to also delete local CA/cache).
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "Error: uninstall requires root privileges. Re-run with: sudo $0 $*" >&2
  exit 1
fi

EXTRA_FLAGS=""
for arg in "$@"; do
  if [ "$arg" = "--purge-state" ]; then
    EXTRA_FLAGS="--purge-state"
  fi
done

if [ -x /usr/local/bin/alt ]; then
  /usr/local/bin/alt uninstall $EXTRA_FLAGS || true
fi

rm -f /usr/local/bin/alt
rm -f /usr/local/share/zsh/site-functions/_alt
rm -f /usr/local/share/bash-completion/completions/alt
rm -f /usr/local/share/fish/vendor_completions.d/alt.fish
rm -rf "/Library/Application Support/alt"

/usr/sbin/pkgutil --forget dev.alt.pkg >/dev/null 2>&1 || true

echo "ALT has been cleanly uninstalled."
