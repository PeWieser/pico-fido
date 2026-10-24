#!/bin/bash
# Builds and runs the host test for the R558-S password recovery ladder.
# Needs nothing but a C compiler: the ladder and the packet layer have no firmware dependencies.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT

gcc -std=gnu11 -Wall -Wextra -Werror -I"$root/src/fido" \
    "$here/recover_test.c" "$root/src/fido/fp_r558_recover.c" "$root/src/fido/fp_r558_sensor.c" \
    -o "$out/recover_test"
"$out/recover_test"
