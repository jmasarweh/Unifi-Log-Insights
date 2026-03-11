#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIST_DIR="$SCRIPT_DIR/dist"

# Shared source directories
SHARED_DIRS=(background content icons lib popup)

echo "Building extension packages..."

# Clean previous builds
rm -rf "$DIST_DIR"

for browser in chrome firefox; do
  OUT="$DIST_DIR/$browser"
  mkdir -p "$OUT"

  # Copy shared files
  for dir in "${SHARED_DIRS[@]}"; do
    cp -r "$SCRIPT_DIR/$dir" "$OUT/$dir"
  done

  # Copy browser-specific manifest
  if [ ! -f "$SCRIPT_DIR/manifests/$browser.json" ]; then
    echo "ERROR: $SCRIPT_DIR/manifests/$browser.json not found" >&2
    exit 1
  fi
  cp "$SCRIPT_DIR/manifests/$browser.json" "$OUT/manifest.json"

  # Copy updates.json for Firefox (used for self-distribution auto-updates)
  if [ "$browser" = "firefox" ] && [ -f "$SCRIPT_DIR/updates.json" ]; then
    cp "$SCRIPT_DIR/updates.json" "$OUT/updates.json"
  fi

  echo "  $browser -> dist/$browser/"
done

echo "Done. Load from:"
echo "  Chrome/Edge: extension/dist/chrome/"
echo "  Firefox:     extension/dist/firefox/"
