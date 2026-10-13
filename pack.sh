#!/bin/sh
# Builds dist/bw-lite-<version>.zip, the release artifact for "Load unpacked".
# No .crx: Chrome only installs .crx files signed by the Chrome Web Store. The extension ID is pinned by "key" in
# manifest.json instead (public half of the release key).
set -eu
cd "$(dirname "$0")"
v=$(sed -n 's/.*"version": "\(.*\)".*/\1/p' manifest.json)
rm -rf dist && mkdir -p dist/bw-lite
cp -R manifest.json popup.html popup.css popup.js theme.js bw.js icons vendor LICENSE dist/bw-lite/
(cd dist && zip -qrX "bw-lite-$v.zip" bw-lite)
ls -l dist
