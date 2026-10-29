#!/bin/sh
# Builds dist/bw-lite-<version>.zip, the release artifact for "Load unpacked" in Chrome, dist/bw-lite-<version>-chrome.zip
# for the Chrome Web Store and dist/bw-lite-<version>-firefox.zip for addons.mozilla.org (files at the root, no "key": the
# stores assign their own ID). Chrome flags background.scripts as MV2-only and Firefox has no service_worker, so the Firefox
# manifest swaps one for the other.
# No .crx: Chrome only installs .crx files signed by the Chrome Web Store. The extension ID is pinned by "key" in
# manifest.json instead (public half of the release key).
set -eu
cd "$(dirname "$0")"
v=$(sed -n 's/.*"version": "\(.*\)".*/\1/p' manifest.json)
manifest() { # manifest <js mutating m> <out file>
  node -e 'const fs = require("fs"), m = JSON.parse(fs.readFileSync("manifest.json", "utf8")); eval(process.argv[1]); fs.writeFileSync(process.argv[2], JSON.stringify(m, null, 2) + "\n")' "$1" "$2"
}
rm -rf dist && mkdir -p dist/bw-lite
cp -R manifest.json popup.html popup.css popup.js theme.js bw.js background.js bridge.js page.js inpage.js autofill.js coord.js icons vendor LICENSE dist/bw-lite/
rm dist/bw-lite/vendor/psl.sh dist/bw-lite/vendor/public_suffix_list.dat # psl.sh builds public_suffix_list.js from the .dat; only the .js is loaded
(cd dist && zip -qrX "bw-lite-$v.zip" bw-lite)
cp -R dist/bw-lite dist/chrome && manifest 'delete m.key' dist/chrome/manifest.json
(cd dist/chrome && zip -qrX "../bw-lite-$v-chrome.zip" .) && rm -rf dist/chrome
cp -R dist/bw-lite dist/firefox && manifest 'delete m.key; m.background.scripts = [m.background.service_worker]; delete m.background.service_worker' dist/firefox/manifest.json
(cd dist/firefox && zip -qrX "../bw-lite-$v-firefox.zip" .) # dist/firefox stays for web-ext lint
ls -l dist
