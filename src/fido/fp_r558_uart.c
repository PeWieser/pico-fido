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

#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include "driver/uart.h"
#include "driver/gpio.h"
#include "esp_mac.h"
#include "esp_rom_gpio.h"
#include "esp_rom_sys.h"
#include "esp_timer.h"
#include "soc/gpio_sig_map.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "mbedtls/sha256.h"

#ifndef SIG_GPIO_OUT_IDX
#define SIG_GPIO_OUT_IDX 256
#endif

#define FP_UART_RX_BUF          256
#define FP_POWERUP_SETTLE_MS    350
#define FP_INTERFRAME_GUARD_US  12000 /* 12 ms idle mark so R558-S completes stop bits + re-arms RX */
#define FP_DEV_SHARED_ADDR      0x5049434Fu /* "PICO" */

static bool uart_installed = false;
static int cur_tx_gpio = -1;
static int cur_rx_gpio = -1;
static int64_t last_bus_activity_us = 0;
static char active_desc[64] = "";

static const int diag_header_gpios[] = { 1, 2, 3, 4, 43, 44 };
#define NUM_DIAG_GPIOS (sizeof(diag_header_gpios) / sizeof(diag_header_gpios[0]))

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

static void detach_pin(int pin) {
    if (pin < 0) {
        return;
    }
    esp_rom_gpio_connect_out_signal((uint32_t)pin, SIG_GPIO_OUT_IDX, false, false);
    (void)gpio_reset_pin((gpio_num_t)pin);
    (void)gpio_set_direction((gpio_num_t)pin, GPIO_MODE_INPUT);
    (void)gpio_pulldown_dis((gpio_num_t)pin);
    (void)gpio_pullup_en((gpio_num_t)pin);
}

static void restore_uart0_console_if_unused(void) {
    if (cur_tx_gpio != 43 && cur_rx_gpio != 43) {
        esp_rom_gpio_pad_select_gpio(43);
        (void)gpio_set_direction((gpio_num_t)43, GPIO_MODE_OUTPUT);
        esp_rom_gpio_connect_out_signal(43, U0TXD_OUT_IDX, false, false);
    }
}

static int esp_uart_write(void *ctx, const uint8_t *buf, size_t len) {
    (void)ctx;
    if (!uart_installed) {
        return -1;
    }
    /*
     * Enforce a 12 ms idle turnaround guard after any prior RX/TX activity on the R558-S line.
     * Without this guard, a 240 MHz ESP32-S3 starts the next 0xEF01 packet within microseconds of
     * reading an ACK — colliding with the R558-S's 2nd stop bit before its MCU re-arms UART RX!
     */
    if (last_bus_activity_us > 0) {
        int64_t elapsed = esp_timer_get_time() - last_bus_activity_us;
        if (elapsed >= 0 && elapsed < FP_INTERFRAME_GUARD_US) {
            uint32_t wait_us = (uint32_t)(FP_INTERFRAME_GUARD_US - elapsed);
            if (wait_us >= 10000u) {
                vTaskDelay(pdMS_TO_TICKS((wait_us + 999u) / 1000u));
            }
            else {
                esp_rom_delay_us(wait_us);
            }
        }
    }
    int n = uart_write_bytes(FP_UART_NUM, (const char *)buf, len);
    if (n < 0 || (size_t)n != len) {
        return -1;
    }
    esp_err_t rc = uart_wait_tx_done(FP_UART_NUM, pdMS_TO_TICKS(200));
    last_bus_activity_us = esp_timer_get_time();
    return rc == ESP_OK ? 0 : -1;
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
    if (r > 0) {
        last_bus_activity_us = esp_timer_get_time();
    }
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
    int prev_tx = cur_tx_gpio;
    int prev_rx = cur_rx_gpio;
    detach_pin(prev_tx);
    detach_pin(prev_rx);
    detach_pin(tx_gpio);
    detach_pin(rx_gpio);
    cur_tx_gpio = -1;
    cur_rx_gpio = -1;

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
            restore_uart0_console_if_unused();
            return false;
        }
        uart_installed = true;
    }
    if (uart_param_config(FP_UART_NUM, &cfg) != ESP_OK) {
        restore_uart0_console_if_unused();
        return false;
    }
    if (uart_set_pin(FP_UART_NUM, tx_gpio, rx_gpio, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE) != ESP_OK) {
        restore_uart0_console_if_unused();
        return false;
    }
    (void)gpio_pulldown_dis((gpio_num_t)rx_gpio);
    (void)gpio_pullup_en((gpio_num_t)rx_gpio);
    cur_tx_gpio = tx_gpio;
    cur_rx_gpio = rx_gpio;
    restore_uart0_console_if_unused();
    esp_rom_delay_us(500);
    (void)uart_flush_input(FP_UART_NUM);
    return true;
}

static size_t detect_driven_high_pins(const int *pin_list, size_t n_pins, int *high_pins, size_t max_out) {
    detach_pin(cur_tx_gpio);
    detach_pin(cur_rx_gpio);
    cur_tx_gpio = -1;
    cur_rx_gpio = -1;

    for (size_t i = 0; i < n_pins; i++) {
        int pin = pin_list[i];
        esp_rom_gpio_connect_out_signal((uint32_t)pin, SIG_GPIO_OUT_IDX, false, false);
        (void)gpio_reset_pin((gpio_num_t)pin);
        (void)gpio_set_direction((gpio_num_t)pin, GPIO_MODE_INPUT);
        (void)gpio_pullup_dis((gpio_num_t)pin);
        (void)gpio_pulldown_en((gpio_num_t)pin);
    }
    vTaskDelay(pdMS_TO_TICKS(2));

    size_t count = 0;
    for (size_t i = 0; i < n_pins; i++) {
        int pin = pin_list[i];
        if (gpio_get_level((gpio_num_t)pin) == 1 && count < max_out) {
            high_pins[count++] = pin;
        }
        (void)gpio_pulldown_dis((gpio_num_t)pin);
        (void)gpio_pullup_en((gpio_num_t)pin);
    }
    restore_uart0_console_if_unused();
    return count;
}

static bool uart_efuse_session(fp_session_t *out) {
    uint8_t mac[6] = { 0 };
    if (esp_efuse_mac_get_default(mac) != ESP_OK) {
        return false;
    }
    static const uint8_t domain[] = "pico-fido-r558-efuse-bind-v1";
    uint8_t digest[32];
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, domain, sizeof(domain) - 1u);
    mbedtls_sha256_update(&ctx, mac, sizeof(mac));
    mbedtls_sha256_finish(&ctx, digest);
    mbedtls_sha256_free(&ctx);

    memcpy(out->password, digest, 4);
    if (out->password[0] == 0 && out->password[1] == 0 && out->password[2] == 0 && out->password[3] == 0) {
        out->password[0] = 0xA5;
    }
    uint32_t addr = ((uint32_t)digest[4] << 24) | ((uint32_t)digest[5] << 16) | ((uint32_t)digest[6] << 8) | digest[7];
    if (addr == 0 || addr == FP_FACTORY_ADDRESS) {
        addr = 0x5A3CC3A5u;
    }
    out->address = addr;
    return true;
}

static bool probe_address_fast(uint32_t addr, uint32_t timeout_ms) {
    const uint8_t zero_pwd[4] = { 0, 0, 0, 0 };
    uint8_t code = 0xFF;
    return fp_sensor_txn(&uart_transport, addr, FP_INS_VFY_PWD,
                         zero_pwd, sizeof(zero_pwd), NULL, 0, NULL,
                         &code, timeout_ms, false) == FP_SENSOR_OK;
}

static void unlock_module_at_address(uint32_t addr) {
    const uint8_t zero_pwd[4] = { 0, 0, 0, 0 };
    const uint8_t ff_pwd[4] = { 0xFF, 0xFF, 0xFF, 0xFF };
    uint8_t code = 0xFF;
    fp_session_t tmp_s = { .address = addr, .password = { 0, 0, 0, 0 } };
    (void)fp_sensor_cancel(&uart_transport, &tmp_s, &code);
    fp_session_t ff_s = { .address = addr, .password = { 0xFF, 0xFF, 0xFF, 0xFF } };
    if (fp_sensor_verify_password(&uart_transport, &ff_s, &code) == FP_SENSOR_OK && code == FP_CONF_OK) {
        (void)fp_sensor_set_password(&uart_transport, addr, zero_pwd, &code);
    }
    else {
        (void)fp_sensor_set_password(&uart_transport, addr, zero_pwd, &code);
        (void)fp_sensor_set_password(&uart_transport, addr, ff_pwd, &code);
        (void)fp_sensor_set_password(&uart_transport, addr, zero_pwd, &code);
    }
    if (addr != FP_FACTORY_ADDRESS) {
        (void)fp_sensor_set_chip_address(&uart_transport, addr, FP_FACTORY_ADDRESS, &code);
    }
    if (fp_sensor_rest_setting(&uart_transport, addr, &code) == FP_SENSOR_OK && code == FP_CONF_OK) {
        vTaskDelay(pdMS_TO_TICKS(80));
    }
}

int fp_uart_init(void) {
    return configure_uart_channel(FP_UART_TX_GPIO, FP_UART_RX_GPIO, FP_UART_BAUD, UART_STOP_BITS_1) ? 0 : -1;
}

bool fp_uart_scan_pins(uint32_t paired_addr) {
    uint32_t up = esp_now_ms();
    if (up < FP_POWERUP_SETTLE_MS) {
        vTaskDelay(pdMS_TO_TICKS(FP_POWERUP_SETTLE_MS - up));
    }

    if (!uart_installed && fp_uart_init() != 0) {
        return false;
    }

    fp_sensor_clear_last_ack();

    fp_session_t ef = { 0 };
    bool have_ef = uart_efuse_session(&ef);

    /*
     * TX=GPIO1, RX=GPIO2 (wiring diagram default) first, followed by swapped polarity & GP43/44/4/5:
     */
    const fp_pin_pair_t pairs[] = {
        { FP_UART_TX_GPIO, FP_UART_RX_GPIO }, /* TX=GPIO1, RX=GPIO2 (diagram default!) */
        { FP_UART_RX_GPIO, FP_UART_TX_GPIO }, /* TX=GPIO2, RX=GPIO1 (swapped) */
        { 43, 44 },                           /* TX=GPIO43, RX=GPIO44 */
        { 44, 43 },                           /* TX=GPIO44, RX=GPIO43 */
        { 4, 5 },
        { 5, 4 },
    };
    const fp_framing_t framings[] = {
        { 57600, UART_STOP_BITS_1, "57600 8N1", 32 },
        { 57600, UART_STOP_BITS_2, "57600 8N2", 30 },
    };

    for (size_t i = 0; i < sizeof(pairs) / sizeof(pairs[0]); i++) {
        for (size_t f = 0; f < sizeof(framings) / sizeof(framings[0]); f++) {
            if (!configure_uart_channel(pairs[i].tx_gpio, pairs[i].rx_gpio, framings[f].baud, framings[f].stop_bits)) {
                continue;
            }
            if (f == 0) {
                const uint8_t wake = 0x00;
                uart_write_bytes(FP_UART_NUM, (const char *)&wake, 1);
                uart_wait_tx_done(FP_UART_NUM, pdMS_TO_TICKS(8));
                vTaskDelay(pdMS_TO_TICKS(15));
                uart_flush_input(FP_UART_NUM);
                last_bus_activity_us = esp_timer_get_time();
            }
            bool ok = probe_address_fast(FP_FACTORY_ADDRESS, framings[f].timeout_ms);
            if (!ok && f == 0) {
                ok = probe_address_fast(FP_DEV_SHARED_ADDR, framings[f].timeout_ms);
            }
            if (!ok && paired_addr != 0 && paired_addr != FP_FACTORY_ADDRESS && paired_addr != FP_DEV_SHARED_ADDR) {
                ok = probe_address_fast(paired_addr, framings[f].timeout_ms);
            }
            if (!ok && f == 0 && have_ef && ef.address != paired_addr) {
                ok = probe_address_fast(ef.address, framings[f].timeout_ms);
            }
            if (ok) {
                snprintf(active_desc, sizeof(active_desc), "TX=GPIO%d, RX=GPIO%d (%s)",
                         pairs[i].tx_gpio, pairs[i].rx_gpio, framings[f].label);
                return true;
            }
        }
    }

    int high_pins[6] = { 0 };
    size_t high_count = detect_driven_high_pins(diag_header_gpios, NUM_DIAG_GPIOS, high_pins, 6);
    if (high_count == 0) {
        snprintf(active_desc, sizeof(active_desc), "DIAG: Alle Pins 0V (GP1..4,43,44 LOW) -> Strom/Kabel!");
    }
    else if (high_count == 1) {
        snprintf(active_desc, sizeof(active_desc), "DIAG: Sensor-TX auf GP%d=3.3V aktiv (0B Antwort)", high_pins[0]);
    }
    else {
        snprintf(active_desc, sizeof(active_desc), "DIAG: 3.3V auf GP%d,GP%d aktiv (0B Antwort)", high_pins[0], high_pins[1]);
    }

    configure_uart_channel(FP_UART_TX_GPIO, FP_UART_RX_GPIO, FP_UART_BAUD, UART_STOP_BITS_1);
    restore_uart0_console_if_unused();
    return false;
}

bool fp_uart_rescue_factory_reset(uint32_t hint_addr) {
    if (!uart_installed && fp_uart_init() != 0) {
        return false;
    }

    uint32_t deadline = esp_now_ms() + 4500u; /* Strictly finish inside 4.5s — zero USB timeout ever! */
    fp_sensor_clear_last_ack();

    const fp_pin_pair_t rescue_pairs[] = {
        { FP_UART_TX_GPIO, FP_UART_RX_GPIO }, /* TX=GPIO1, RX=GPIO2 */
        { FP_UART_RX_GPIO, FP_UART_TX_GPIO }, /* TX=GPIO2, RX=GPIO1 */
        { 43, 44 },
        { 44, 43 },
        { 2, 3 },
        { 3, 2 },
        { 4, 5 },
        { 5, 4 },
    };
    const fp_framing_t framings[] = {
        { 57600, UART_STOP_BITS_1, "57600 8N1", 40 },
        { 57600, UART_STOP_BITS_2, "57600 8N2", 40 },
        { 115200, UART_STOP_BITS_1, "115200 8N1", 35 },
        { 9600, UART_STOP_BITS_1, "9600 8N1", 50 },
    };

    fp_session_t ef = { 0 };
    bool have_ef = uart_efuse_session(&ef);
    const uint8_t zero_pwd[4] = { 0, 0, 0, 0 };
    const fp_session_t dev_sh = { .address = FP_DEV_SHARED_ADDR, .password = { 0x52, 0x35, 0x35, 0x38 } };

    for (size_t i = 0; i < sizeof(rescue_pairs) / sizeof(rescue_pairs[0]); i++) {
        if (esp_now_ms() >= deadline) {
            break;
        }
        for (size_t f = 0; f < sizeof(framings) / sizeof(framings[0]); f++) {
            if (esp_now_ms() >= deadline) {
                break;
            }
            if (f >= 2 && i >= 4) {
                break;
            }
            if (!configure_uart_channel(rescue_pairs[i].tx_gpio, rescue_pairs[i].rx_gpio,
                                        framings[f].baud, framings[f].stop_bits)) {
                continue;
            }
            if (f == 0) {
                const uint8_t wake = 0x00;
                uart_write_bytes(FP_UART_NUM, (const char *)&wake, 1);
                uart_wait_tx_done(FP_UART_NUM, pdMS_TO_TICKS(8));
                vTaskDelay(pdMS_TO_TICKS(15));
                uart_flush_input(FP_UART_NUM);
                last_bus_activity_us = esp_timer_get_time();
            }

            uint8_t code = 0xFF;
            if (fp_sensor_verify_password(&uart_transport, &dev_sh, &code) == FP_SENSOR_OK && code == FP_CONF_OK) {
                (void)fp_sensor_empty(&uart_transport, &dev_sh, &code);
                (void)fp_sensor_set_password(&uart_transport, dev_sh.address, zero_pwd, &code);
                (void)fp_sensor_set_chip_address(&uart_transport, dev_sh.address, FP_FACTORY_ADDRESS, &code);
                vTaskDelay(pdMS_TO_TICKS(50));
            }
            if (have_ef && fp_sensor_verify_password(&uart_transport, &ef, &code) == FP_SENSOR_OK && code == FP_CONF_OK) {
                (void)fp_sensor_empty(&uart_transport, &ef, &code);
                (void)fp_sensor_set_password(&uart_transport, ef.address, zero_pwd, &code);
                (void)fp_sensor_set_chip_address(&uart_transport, ef.address, FP_FACTORY_ADDRESS, &code);
                vTaskDelay(pdMS_TO_TICKS(50));
            }

            /* Probe factory address & capture any self-reported stored ChipAddr from the module's ACK header! */
            (void)probe_address_fast(FP_FACTORY_ADDRESS, framings[f].timeout_ms);
            if (fp_sensor_has_last_ack()) {
                uint32_t seen_addr = fp_sensor_last_ack_addr();
                unlock_module_at_address(seen_addr);
                if (seen_addr != FP_FACTORY_ADDRESS) {
                    unlock_module_at_address(FP_FACTORY_ADDRESS);
                }
                if (probe_address_fast(FP_FACTORY_ADDRESS, framings[f].timeout_ms) ||
                    probe_address_fast(seen_addr, framings[f].timeout_ms)) {
                    snprintf(active_desc, sizeof(active_desc),
                             "TX=GPIO%d, RX=GPIO%d (%s) A=0x%08" PRIX32,
                             rescue_pairs[i].tx_gpio, rescue_pairs[i].rx_gpio,
                             framings[f].label, fp_sensor_last_ack_addr());
                    return true;
                }
            }

            if (hint_addr != 0 && hint_addr != FP_FACTORY_ADDRESS) {
                unlock_module_at_address(hint_addr);
                if (probe_address_fast(FP_FACTORY_ADDRESS, framings[f].timeout_ms) ||
                    probe_address_fast(hint_addr, framings[f].timeout_ms)) {
                    snprintf(active_desc, sizeof(active_desc), "TX=GPIO%d, RX=GPIO%d (%s)",
                             rescue_pairs[i].tx_gpio, rescue_pairs[i].rx_gpio, framings[f].label);
                    return true;
                }
            }
        }
    }

    return fp_uart_scan_pins(hint_addr);
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

bool fp_uart_rescue_factory_reset(uint32_t hint_addr) {
    return fp_uart_scan_pins(hint_addr);
}

const char *fp_uart_active_pins(void) {
    return emu_fd >= 0 ? "TX=GPIO1, RX=GPIO2 (57600 8N1)" : "";
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

bool fp_uart_rescue_factory_reset(uint32_t hint_addr) {
    (void)hint_addr;
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
