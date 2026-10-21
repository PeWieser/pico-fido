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

/* ------------------------------------------------------------------------- */
/* ESP32 implementation via the ESP-IDF UART driver (multi-pin auto-detect)  */
/* ------------------------------------------------------------------------- */
#if defined(ESP_PLATFORM)

#include <stdio.h>
#include <string.h>
#include "driver/uart.h"
#include "driver/gpio.h"
#include "esp_rom_gpio.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#define FP_UART_RX_BUF       256
#define FP_POWERUP_SETTLE_MS 350

static bool uart_installed = false;
static int cur_tx_gpio = -1;
static int cur_rx_gpio = -1;
static char active_desc[48] = "";

typedef struct {
    int tx_gpio;
    int rx_gpio;
} fp_pin_pair_t;

typedef struct {
    int baud;
    uart_stop_bits_t stop_bits;
    const char *label;
    uint32_t timeout_ms;
} fp_framing_t;

static uint32_t esp_now_ms(void) {
    return (uint32_t)(xTaskGetTickCount() * portTICK_PERIOD_MS);
}

static int esp_uart_write(void *ctx, const uint8_t *buf, size_t len) {
    (void)ctx;
    if (!uart_installed) {
        return -1;
    }
    int n = uart_write_bytes(FP_UART_NUM, (const char *)buf, len);
    if (n < 0 || (size_t)n != len) {
        return -1;
    }
    return uart_wait_tx_done(FP_UART_NUM, pdMS_TO_TICKS(200)) == ESP_OK ? 0 : -1;
}

static int esp_uart_read(void *ctx, uint8_t *buf, size_t max_len, uint32_t timeout_ms) {
    (void)ctx;
    if (!uart_installed) {
        return -1;
    }
    TickType_t ticks = pdMS_TO_TICKS(timeout_ms);
    if (ticks == 0 && timeout_ms > 0) {
        ticks = 1;
    }
    int r = uart_read_bytes(FP_UART_NUM, buf, (uint32_t)max_len, ticks);
    return r < 0 ? -1 : r;
}

static void esp_uart_flush(void *ctx) {
    (void)ctx;
    if (uart_installed) {
        uart_flush_input(FP_UART_NUM);
    }
}

static const fp_transport_t uart_transport = {
    .ctx = NULL,
    .write = esp_uart_write,
    .read = esp_uart_read,
    .flush = esp_uart_flush,
};

static bool configure_uart_channel(int tx_gpio, int rx_gpio, int baud, uart_stop_bits_t stop_bits) {
    if (cur_tx_gpio >= 0 && cur_tx_gpio != tx_gpio && cur_tx_gpio != rx_gpio) {
        gpio_reset_pin((gpio_num_t)cur_tx_gpio);
    }
    if (cur_rx_gpio >= 0 && cur_rx_gpio != tx_gpio && cur_rx_gpio != rx_gpio) {
        gpio_reset_pin((gpio_num_t)cur_rx_gpio);
    }

    esp_rom_gpio_pad_select_gpio((uint32_t)tx_gpio);
    esp_rom_gpio_pad_select_gpio((uint32_t)rx_gpio);

    const uart_config_t cfg = {
        .baud_rate = baud,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = stop_bits,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };

    if (!uart_installed) {
        if (uart_driver_install(FP_UART_NUM, FP_UART_RX_BUF, 0, 0, NULL, 0) != ESP_OK) {
            return false;
        }
        uart_installed = true;
    }
    if (uart_param_config(FP_UART_NUM, &cfg) != ESP_OK) {
        return false;
    }
    if (uart_set_pin(FP_UART_NUM, tx_gpio, rx_gpio, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE) != ESP_OK) {
        return false;
    }
    (void)gpio_pullup_en((gpio_num_t)rx_gpio);
    cur_tx_gpio = tx_gpio;
    cur_rx_gpio = rx_gpio;
    (void)uart_flush_input(FP_UART_NUM);
    return true;
}

static bool probe_address_once(uint32_t addr, uint32_t timeout_ms) {
    const uint8_t zero_pwd[4] = { 0, 0, 0, 0 };
    uint8_t code = 0xFF;
    return fp_sensor_txn(&uart_transport, addr, FP_INS_VFY_PWD,
                         zero_pwd, sizeof(zero_pwd), NULL, 0, NULL,
                         &code, timeout_ms, false) == FP_SENSOR_OK;
}

int fp_uart_init(void) {
    return configure_uart_channel(FP_UART_TX_GPIO, FP_UART_RX_GPIO, FP_UART_BAUD, UART_STOP_BITS_2) ? 0 : -1;
}

bool fp_uart_scan_pins(uint32_t paired_addr) {
    /* Ensure R558-S MCU has completed its ~300 ms power-on initialization after USB plug-in. */
    uint32_t up = esp_now_ms();
    if (up < FP_POWERUP_SETTLE_MS) {
        vTaskDelay(pdMS_TO_TICKS(FP_POWERUP_SETTLE_MS - up));
    }

    if (!uart_installed && fp_uart_init() != 0) {
        return false;
    }

    /*
     * Automatic pin & TX/RX polarity discovery for ESP32-S3 Super Mini + DevKit boards:
     *  - GP1 / GP2 (recommended right-side header pins next to GND & 3V3, normal + swapped)
     *  - GP43 / GP44 (Super Mini labeled TX / RX pins, normal + swapped — zero unsoldering needed)
     *  - GP4 / GP5 (clean alternative header pins, normal + swapped)
     */
    const fp_pin_pair_t pairs[] = {
        { FP_UART_TX_GPIO, FP_UART_RX_GPIO },
        { FP_UART_RX_GPIO, FP_UART_TX_GPIO },
        { 43, 44 },
        { 44, 43 },
        { 4, 5 },
        { 5, 4 },
    };
    const fp_framing_t framings[] = {
        { 57600, UART_STOP_BITS_2, "57600 8N2", 40 },
        { 57600, UART_STOP_BITS_1, "57600 8N1", 35 },
        { 115200, UART_STOP_BITS_1, "115200 8N1", 35 },
    };

    for (size_t i = 0; i < sizeof(pairs) / sizeof(pairs[0]); i++) {
        for (size_t f = 0; f < sizeof(framings) / sizeof(framings[0]); f++) {
            if (!configure_uart_channel(pairs[i].tx_gpio, pairs[i].rx_gpio, framings[f].baud, framings[f].stop_bits)) {
                continue;
            }
            if (f == 0) {
                /* Wake R558-S UART oscillator in case the module entered idle standby. */
                const uint8_t wake = 0x00;
                uart_write_bytes(FP_UART_NUM, (const char *)&wake, 1);
                uart_wait_tx_done(FP_UART_NUM, pdMS_TO_TICKS(10));
                vTaskDelay(pdMS_TO_TICKS(8));
                uart_flush_input(FP_UART_NUM);
            }
            bool ok = probe_address_once(FP_FACTORY_ADDRESS, framings[f].timeout_ms);
            if (!ok && paired_addr != 0 && paired_addr != FP_FACTORY_ADDRESS) {
                ok = probe_address_once(paired_addr, framings[f].timeout_ms);
            }
            if (ok) {
                snprintf(active_desc, sizeof(active_desc), "TX=GPIO%d, RX=GPIO%d (%s)",
                         pairs[i].tx_gpio, pairs[i].rx_gpio, framings[f].label);
                return true;
            }
        }
    }

    active_desc[0] = '\0';
    configure_uart_channel(FP_UART_TX_GPIO, FP_UART_RX_GPIO, FP_UART_BAUD, UART_STOP_BITS_2);
    return false;
}

const char *fp_uart_active_pins(void) {
    return active_desc;
}

const fp_transport_t *fp_uart_transport(void) {
    return &uart_transport;
}

/* ------------------------------------------------------------------------- */
/* Emulation: TCP stream socket port from $PICO_FIDO_R558_PORT               */
/* ------------------------------------------------------------------------- */
#elif defined(ENABLE_EMULATION) && (defined(__linux__) || defined(__APPLE__))

#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int emu_fd = -1;

static int emu_ensure_conn(void) {
    if (emu_fd >= 0) {
        return emu_fd;
    }
    const char *port_s = getenv("PICO_FIDO_R558_PORT");
    if (port_s == NULL || port_s[0] == '\0') {
        return -1;
    }
    int port = atoi(port_s);
    if (port <= 0 || port > 65535) {
        return -1;
    }
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        close(fd);
        return -1;
    }
    emu_fd = fd;
    return emu_fd;
}

int fp_uart_init(void) {
    const char *port_s = getenv("PICO_FIDO_R558_PORT");
    if (port_s == NULL || port_s[0] == '\0') {
        return -1;
    }
    return 0;
}

bool fp_uart_scan_pins(uint32_t paired_addr) {
    (void)paired_addr;
    return emu_ensure_conn() >= 0;
}

const char *fp_uart_active_pins(void) {
    return emu_fd >= 0 ? "TX=GPIO1, RX=GPIO2 (57600 8N2)" : "";
}

static int emu_write(void *ctx, const uint8_t *data, size_t len) {
    (void)ctx;
    int fd = emu_ensure_conn();
    if (fd < 0) {
        return -1;
    }
    size_t off = 0;
    while (off < len) {
        ssize_t w = send(fd, data + off, len - off, MSG_NOSIGNAL);
        if (w <= 0) {
            close(fd);
            emu_fd = -1;
            return -1;
        }
        off += (size_t)w;
    }
    return 0;
}

static int emu_read(void *ctx, uint8_t *data, size_t len, uint32_t timeout_ms) {
    (void)ctx;
    int fd = emu_ensure_conn();
    if (fd < 0) {
        return -1;
    }
    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    int pr = poll(&pfd, 1, (int)timeout_ms);
    if (pr <= 0) {
        return pr == 0 ? 0 : -1;
    }
    ssize_t r = recv(fd, data, len, 0);
    if (r <= 0) {
        close(fd);
        emu_fd = -1;
        return 0;
    }
    return (int)r;
}

static void emu_flush(void *ctx) {
    (void)ctx;
    int fd = emu_ensure_conn();
    if (fd < 0) {
        return;
    }
    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    uint8_t sink[64];
    while (poll(&pfd, 1, 0) > 0) {
        if (recv(fd, sink, sizeof(sink), 0) <= 0) {
            close(fd);
            emu_fd = -1;
            break;
        }
    }
}

static const fp_transport_t emu_transport = {
    .ctx = NULL,
    .write = emu_write,
    .read = emu_read,
    .flush = emu_flush,
};

const fp_transport_t *fp_uart_transport(void) {
    return &emu_transport;
}

#else /* host or non-ESP builds without virtual sensor: no sensor attached */

int fp_uart_init(void) {
    return -1;
}

bool fp_uart_scan_pins(uint32_t paired_addr) {
    (void)paired_addr;
    return false;
}

const char *fp_uart_active_pins(void) {
    return "";
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
