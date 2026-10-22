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
#include <stddef.h>
#include <stdint.h>
#include "fp_r558_sensor.h"

/* Installs the UART driver. Returns 0 on success. */
int fp_uart_init(void);

/*
 * Scans candidate UART TX/RX GPIO pairs (including auto TX/RX swap) and baud/stop-bit
 * framings on ESP32 hardware until a live R558-S answers with a valid packet.
 * Preserves previously observed non-factory ChipAddr across scans so password-locked
 * sensors keep answering reliably without requiring a USB power-cycle.
 */
bool fp_uart_scan_pins(uint32_t paired_addr);

/* Sweeps candidate UART GPIO pairs and baud rates cleanly without anti-brute-force lockup. */
bool fp_uart_rescue_factory_reset(uint32_t hint_addr);

/* Human-readable active UART description (e.g. "TX=GPIO1, RX=GPIO2 (57600 8N1)"), or "". */
const char *fp_uart_active_pins(void);

/* Updates active diagnostic description on ESP32 / emulation builds. */
void fp_uart_set_diag(const char *msg);

/* Last non-zero ChipAddr observed on UART across scans (survives re-scans). */
uint32_t fp_uart_sticky_addr(void);
void fp_uart_set_sticky_addr(uint32_t addr);

/* Active ESP32 UART GPIO numbers (-1 on host/emulation builds). */
int fp_uart_active_tx_gpio(void);
int fp_uart_active_rx_gpio(void);

/* Raw UART framing / zero-guard I/O helpers used by the R558-S hardware unlock & ISP engine. */
bool fp_uart_reconfig_raw(int tx_gpio, int rx_gpio, int baud, bool even_parity, bool two_stop_bits);
int fp_uart_write_raw_fast(const uint8_t *buf, size_t len);
int fp_uart_read_raw_fast(uint8_t *buf, size_t max_len, uint32_t timeout_ms);

/* Transport bound to the UART. On builds without UART it always reports an I/O error. */
const fp_transport_t *fp_uart_transport(void);

#endif /* FP_R558_UART_H_ */
