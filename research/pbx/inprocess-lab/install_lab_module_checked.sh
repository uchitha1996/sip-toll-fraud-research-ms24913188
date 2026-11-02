#!/bin/bash
# Install the inspected lab module only. Loading requires a separate idle lab test.
set -euo pipefail
src=/home/astrix/sip-fraud-research/inprocess-lab/res_sipfraud_lab.so
dst=/usr/lib/asterisk/modules/res_sipfraud_lab.so
expected=02160968346541cc7ca45b848758a269275567707dd1fb54fb1c31c518f3bb26
if [ "$(id -u)" != 0 ]; then
  echo "Run locally on Astrix-lab with sudo."; exit 1
fi
actual=$(sha256sum "$src" | cut -d ' ' -f 1)
[ "$actual" = "$expected" ] || { echo "Module hash mismatch."; exit 1; }
asterisk -rx 'core show channels count' | grep -qx '0 active calls'
[ ! -e "$dst" ] || { echo "Target already exists; no overwrite performed."; exit 1; }
install -o root -g root -m 0644 -- "$src" "$dst"
cmp -- "$src" "$dst"
echo "Module installed and bytes verified. It has not been loaded."
