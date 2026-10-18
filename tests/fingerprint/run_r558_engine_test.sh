#!/bin/bash
# Builds and runs the host test for the R558 engine. Needs gcc and the third-party headers of a
# previous emulation build (path in $PICO_FIDO_EMU_BUILD, default /tmp/emu, created by:
#   cmake -DENABLE_EMULATION=1 <repo> && make -k).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
emu="${PICO_FIDO_EMU_BUILD:-/tmp/emu}"
flags="$emu/CMakeFiles/pico_fido.dir/flags.make"
inc="$(grep '^C_INCLUDES' "$flags" | sed 's/^C_INCLUDES = //')"
defs="$(grep '^C_DEFINES' "$flags" | sed 's/^C_DEFINES = //')"
out="$(mktemp -d)"
eval gcc -std=gnu11 -Wall -Wextra -DENABLE_R558_FINGERPRINT=1 $defs $inc \
    "$here/engine_test.c" "$root/src/fido/fp_r558.c" "$root/src/fido/fp_r558_sensor.c" \
    "$root/src/fido/fp_led.c" -o "$out/engine_test"
"$out/engine_test"
rm -rf "$out"
