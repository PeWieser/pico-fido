/*
 * Pico FIDO - board initialisation hook for the R558 fingerprint feature.
 *
 * This file is part of the Pico FIDO distribution (https://github.com/polhenarejos/pico-fido).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include <stdbool.h>
#include "picokeys.h"
#include "fp_led.h"
#include "fp_r558.h"

/* Overrides the WEAK hook in pico-keys-sdk/src/main.c. Runs after led_init(). */
int picokey_init(void) {
    fp_led_init();
    fp_init();
    return 0;
}

/*
 * Ensures USB CTAP sends CTAPHID_KEEPALIVE(STATUS_UPNEEDED = 0x02) every 250 ms
 * while waiting for user finger interaction on the R558-S sensor, without touching
 * the pico-keys-sdk submodule.
 */
#if defined(ESP_PLATFORM) || defined(__linux__)
extern bool __real_is_req_button_pending(void);
bool __wrap_is_req_button_pending(void);
bool __wrap_is_req_button_pending(void) {
    return __real_is_req_button_pending() || fp_is_waiting_finger();
}
#endif
