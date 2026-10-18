#!/bin/bash
# Builds and runs the host test for the R558 packet layer. Needs only a C compiler.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
out="$(mktemp -d)"
gcc -std=gnu11 -Wall -Wextra -Werror -I"$root/src/fido" \
    "$here/r558_sensor_test.c" "$root/src/fido/fp_r558_sensor.c" -o "$out/r558_sensor_test"
"$out/r558_sensor_test"
rm -rf "$out"
