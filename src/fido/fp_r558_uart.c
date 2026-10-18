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

#include "fp_r558_uart.h"
#include "fp_r558_config.h"

#if defined(ESP_PLATFORM)

#include "driver/uart.h"
#include "driver/gpio.h"
#include "freertos/FreeRTOS.h"

#define FP_UART_RX_BUF 256

static bool uart_ready = false;

int fp_uart_init(void) {
    if (uart_ready) {
        return 0;
    }
    uart_config_t cfg = {
        .baud_rate = FP_UART_BAUD,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        /* R558-S manual, section IV: 8N2 (8 data bits, no parity, 2 stop bits). */
        .stop_bits = UART_STOP_BITS_2,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };
    if (uart_param_config(FP_UART_NUM, &cfg) != ESP_OK) {
        return -1;
    }
    if (uart_set_pin(FP_UART_NUM, FP_UART_TX_GPIO, FP_UART_RX_GPIO, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE) != ESP_OK) {
        return -1;
    }
    if (uart_driver_install(FP_UART_NUM, FP_UART_RX_BUF, 0, 0, NULL, 0) != ESP_OK) {
        return -1;
    }
    uart_ready = true;
    return 0;
}

static int uart_write(void *ctx, const uint8_t *data, size_t len) {
    (void)ctx;
    if (!uart_ready) {
        return -1;
    }
    int w = uart_write_bytes(FP_UART_NUM, (const char *)data, len);
    if (w < 0 || (size_t)w != len) {
        return -1;
    }
    return uart_wait_tx_done(FP_UART_NUM, pdMS_TO_TICKS(200)) == ESP_OK ? 0 : -1;
}

static int uart_read(void *ctx, uint8_t *data, size_t len, uint32_t timeout_ms) {
    (void)ctx;
    if (!uart_ready) {
        return -1;
    }
    int r = uart_read_bytes(FP_UART_NUM, data, len, pdMS_TO_TICKS(timeout_ms));
    return r < 0 ? -1 : r;
}

static void fp_uart_transport_flush(void *ctx) {
    (void)ctx;
    if (uart_ready) {
        uart_flush_input(FP_UART_NUM);
    }
}

static const fp_transport_t uart_transport = {
    .ctx = NULL,
    .write = uart_write,
    .read = uart_read,
    .flush = fp_uart_transport_flush,
};

const fp_transport_t *fp_uart_transport(void) {
    return &uart_transport;
}

#else /* host or non-ESP builds: no sensor attached */

int fp_uart_init(void) {
    return -1;
}

static int no_write(void *ctx, const uint8_t *data, size_t len) {
    (void)ctx;
    (void)data;
    (void)len;
    return -1;
}

static int no_read(void *ctx, uint8_t *data, size_t len, uint32_t timeout_ms) {
    (void)ctx;
    (void)data;
    (void)len;
    (void)timeout_ms;
    return -1;
}

static const fp_transport_t no_transport = {
    .ctx = NULL,
    .write = no_write,
    .read = no_read,
    .flush = NULL,
};

const fp_transport_t *fp_uart_transport(void) {
    return &no_transport;
}

#endif
