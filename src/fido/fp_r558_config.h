/*
 * Pico FIDO - R558 fingerprint sensor, hardware and policy configuration.
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
 * All values can be overridden with -D on the build command line. The GPIO defaults are for the
 * ESP32-S3 Super Mini: check them against the pinout of your board before flashing.
 */

#ifndef FP_R558_CONFIG_H_
#define FP_R558_CONFIG_H_

/* R558 UART (3.3 V TTL, 57600 8N1 by default). Module TX -> FP_UART_RX_GPIO, module RX <- FP_UART_TX_GPIO. */
#ifndef FP_UART_NUM
#define FP_UART_NUM            1
#endif
#ifndef FP_UART_TX_GPIO
#define FP_UART_TX_GPIO       17
#endif
#ifndef FP_UART_RX_GPIO
#define FP_UART_RX_GPIO       18
#endif
#ifndef FP_UART_BAUD
#define FP_UART_BAUD          57600
#endif

/* WS2812/NeoPixel ring that shows the status. Replaces the single onboard LED while the feature is enabled. */
#ifndef FP_LED_GPIO
#define FP_LED_GPIO            4
#endif
#ifndef FP_LED_COUNT
#define FP_LED_COUNT         12
#endif
#ifndef FP_LED_RESULT_MS
#define FP_LED_RESULT_MS   1500   /* how long green/red stays after a result */
#endif
#ifndef FP_LED_PULSE_PERIOD_MS
#define FP_LED_PULSE_PERIOD_MS 1200
#endif
#ifndef FP_LED_BREATH_PERIOD_MS
#define FP_LED_BREATH_PERIOD_MS 2400  /* one light-to-strong-blue cycle during enrollment */
#endif

/* Policy. */
#ifndef FP_VERIFY_TIMEOUT_MS
#define FP_VERIFY_TIMEOUT_MS  15000  /* time the user has to place a finger for a passkey request */
#endif
#ifndef FP_ENROLL_STEP_TIMEOUT_MS
#define FP_ENROLL_STEP_TIMEOUT_MS 20000
#endif
#ifndef FP_MAX_FAILED_ATTEMPTS
#define FP_MAX_FAILED_ATTEMPTS 5     /* consecutive non-matching fingers before UV is locked */
#endif
#define FP_TEMPLATE_MAX      256     /* upper bound for sensor capacity, bitmap size in EF */

#endif /* FP_R558_CONFIG_H_ */
