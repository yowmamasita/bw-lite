#!/bin/sh
# Regenerates public_suffix_list.js from public_suffix_list.dat: the rules only, without comments or blank lines.
# usage: vendor/psl.sh <list date, e.g. 2026-10-20>
set -eu
cd "$(dirname "$0")"
{
  echo "// Generated from public_suffix_list.dat (Public Suffix List $1, MPL 2.0): https://publicsuffix.org/list/ and https://mozilla.org/MPL/2.0/."
  echo 'export const PUBLIC_SUFFIX_LIST = `'
  grep -v -e '^//' -e '^[[:space:]]*$' public_suffix_list.dat | sed 's/[[:space:]]*$//'
  echo '`;'
} > public_suffix_list.js
