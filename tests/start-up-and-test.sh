#!/bin/bash -eu

/usr/sbin/pcscd &
sleep 2
rm -f memory.flash
cp -R tests/docker/fido2/* /usr/local/lib/python3.11/dist-packages/fido2/hid
./build_in_docker/pico_fido > /dev/null &
if [ -n "${PICO_FIDO_VAULT_ENROLLMENT_JSON:-}" ] || [ -n "${PICO_FIDO_VAULT_ENROLLMENT:-}" ]; then
    pytest tests
else
    pytest tests --ignore=tests/pico-fido/test_080_vault.py
fi
