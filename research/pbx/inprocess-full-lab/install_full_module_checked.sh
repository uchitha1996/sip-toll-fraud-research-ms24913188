#!/bin/bash
# Install only the reviewed new observer; do not load or alter configuration.
set -euo pipefail
src=/home/astrix/sip-fraud-research/inprocess-full-lab/res_sipfraud_full_lab.so
dst=/usr/lib/asterisk/modules/res_sipfraud_full_lab.so
expected=84c30bcaf2d9f1db5336b06a91a3244752659239d6dd2ac56ea04431d84bb712
[ "$(id -u)" = 0 ] || { echo 'Run locally on Astrix-lab with sudo.'; exit 1; }
[ "$(sha256sum "$src" | cut -d ' ' -f 1)" = "$expected" ] || { echo 'Source hash mismatch'; exit 1; }
asterisk -rx 'core show channels count' | grep -qx '0 active calls'
asterisk -rx 'module show like sipfraud' | grep -qx '0 modules loaded'
for dest in 88001 88002; do
  asterisk -rx "dialplan show $dest@internal" | grep -q 'no existence'
done
if [ -e "$dst" ]; then
  cmp -- "$src" "$dst" || { echo 'Different target exists; no overwrite'; exit 1; }
  echo 'Identical module already installed; not loaded.'; exit 0
fi
install -o root -g root -m 0644 -- "$src" "$dst"
cmp -- "$src" "$dst"
echo 'Hash-checked module installed. It has not been loaded.'
