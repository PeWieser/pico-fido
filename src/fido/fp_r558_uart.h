/*
 * Pico FIDO - R558 fingerprint sensor, UART transport.
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

#ifndef FP_R558_UART_H_
#define FP_R558_UART_H_

#include <stdbool.h>
#include <stdint.h>
#include "fp_r558_sensor.h"

/* Installs the UART driver. Returns 0 on success. */
int fp_uart_init(void);

/*
 * Scans candidate UART TX/RX GPIO pairs (including auto TX/RX swap) and baud/stop-bit
 * framings on ESP32 hardware until a live R558-S answers with a valid packet.
 * Returns true if a sensor answered (or on host/emulation builds).
 */
bool fp_uart_scan_pins(uint32_t paired_addr);

/* Sweeps all candidate UART GPIO pairs and baud rates sending R558-S RestSetting (0x3B) + eFuse unlock. */
bool fp_uart_rescue_factory_reset(uint32_t hint_addr);

/* Human-readable active UART description (e.g. "TX=GPIO1, RX=GPIO2 @ 57600"), or "" if none answered. */
const char *fp_uart_active_pins(void);

/* Transport bound to the UART. On builds without UART it always reports an I/O error. */
const fp_transport_t *fp_uart_transport(void);

#endif /* FP_R558_UART_H_ */
