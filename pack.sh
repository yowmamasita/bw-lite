#!/bin/sh
# Builds dist/bw-lite-<version>.zip, the release artifact for "Load unpacked", and dist/bw-lite-<version>-store.zip
# for the Chrome Web Store and addons.mozilla.org (files at the root, no "key": the stores assign their own ID).
# No .crx: Chrome only installs .crx files signed by the Chrome Web Store. The extension ID is pinned by "key" in
# manifest.json instead (public half of the release key).
set -eu
cd "$(dirname "$0")"
v=$(sed -n 's/.*"version": "\(.*\)".*/\1/p' manifest.json)
rm -rf dist && mkdir -p dist/bw-lite
cp -R manifest.json popup.html popup.css popup.js theme.js bw.js background.js bridge.js page.js inpage.js autofill.js coord.js icons vendor LICENSE dist/bw-lite/
rm dist/bw-lite/vendor/psl.sh dist/bw-lite/vendor/public_suffix_list.dat # psl.sh builds public_suffix_list.js from the .dat; only the .js is loaded
(cd dist && zip -qrX "bw-lite-$v.zip" bw-lite)
cp -R dist/bw-lite dist/store && grep -v '"key":' manifest.json > dist/store/manifest.json
(cd dist/store && zip -qrX "../bw-lite-$v-store.zip" .) && rm -rf dist/store
ls -l dist
