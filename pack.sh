#!/bin/sh
# Builds dist/bw-lite-<version>.zip (for "Load unpacked") and, when BW_LITE_KEY points at the signing key,
# dist/bw-lite-<version>.crx. Keep that key: it fixes the extension ID across releases.
#   BW_LITE_KEY=~/.config/bw-lite/key.pem CHROME=/path/to/chrome ./pack.sh
set -eu
cd "$(dirname "$0")"
v=$(sed -n 's/.*"version": "\(.*\)".*/\1/p' manifest.json)
rm -rf dist && mkdir -p dist/bw-lite
cp -R manifest.json popup.html popup.css popup.js theme.js bw.js icons vendor LICENSE dist/bw-lite/
(cd dist && zip -qrX "bw-lite-$v.zip" bw-lite)
if [ -n "${BW_LITE_KEY:-}" ]; then
  "${CHROME:-google-chrome}" --no-message-box --pack-extension="$PWD/dist/bw-lite" --pack-extension-key="$BW_LITE_KEY" >/dev/null 2>&1
  mv dist/bw-lite.crx "dist/bw-lite-$v.crx"
fi
ls -l dist
