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

#include "fp_r558_sensor.h"

/* Installs the UART driver. Returns 0 on success. */
int fp_uart_init(void);

/* Transport bound to the UART. On builds without UART it always reports an I/O error. */
const fp_transport_t *fp_uart_transport(void);

#endif /* FP_R558_UART_H_ */
