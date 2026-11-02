#!/bin/bash
set -euo pipefail
cd /home/astrix/sip-fraud-research/inprocess-full-lab
astsrc=/usr/local/src/asterisk-20.6.0
pjroot=$astsrc/third-party/pjproject/source
gcc -std=c99 -Wall -Wextra -Werror -fPIC -shared progression_core.c core_bridge.c -lm -o libprogression_core.so
gcc -shared -fPIC -O2 -Wall -Wextra -Werror -Wno-unused-parameter \
 -Wno-old-style-declaration -Wno-ignored-qualifiers -D_GNU_SOURCE \
 '-DAST_MODULE="res_sipfraud_full_lab"' \
 -DAST_MODULE_SELF_SYM=__internal_res_sipfraud_full_lab_self \
 -DPJ_AUTOCONF=1 -DPJ_IS_BIG_ENDIAN=0 -DPJ_IS_LITTLE_ENDIAN=1 \
 -I"$astsrc/include" -I"$astsrc" -I"$pjroot/pjlib/include" \
 -I"$pjroot/pjlib-util/include" -I"$pjroot/pjnath/include" \
 -I"$pjroot/pjmedia/include" -I"$pjroot/pjsip/include" \
 res_sipfraud_full_lab.c -lm -o res_sipfraud_full_lab.so
file res_sipfraud_full_lab.so
sha256sum progression_core.c progression_core.h res_sipfraud_full_lab.c res_sipfraud_full_lab.so libprogression_core.so
