/*
 * Pico FIDO - status ring for the R558 fingerprint feature.
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
 *
 * Ring behaviour:
 *   idle                    off
 *   passkey request         blue, steady
 *   saving a passkey        blue, pulsing
 *   enrolling a finger      blue, breathing (light to strong blue)
 *   success                 green, steady for FP_LED_RESULT_MS
 *   failure                 red, steady for FP_LED_RESULT_MS
 */

#ifndef FP_LED_H_
#define FP_LED_H_

#include <stdbool.h>

/* Installs the ring driver. Only effective on ESP32 builds with the feature enabled. */
void fp_led_init(void);

/* A FIDO operation (MakeCredential, GetAssertion, vendor command) starts: blue. */
void fp_led_op_begin(void);

/* The operation ended: green on success, red otherwise. */
void fp_led_op_end(bool ok);

/* A passkey is being written to flash: blue pulse while true. */
void fp_led_saving(bool on);

/* Fingerprint enrollment is running: blue breathing between light and strong blue while true. */
void fp_led_enrolling(bool on);

#endif /* FP_LED_H_ */
