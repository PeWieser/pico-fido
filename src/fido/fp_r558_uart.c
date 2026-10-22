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
#include "esp_mac.h"
#include "esp_rom_gpio.h"
#include "soc/gpio_sig_map.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "mbedtls/sha256.h"

#ifndef SIG_GPIO_OUT_IDX
#define SIG_GPIO_OUT_IDX 256
#endif

#define FP_UART_RX_BUF       256
#define FP_POWERUP_SETTLE_MS 350
#define FP_DEV_SHARED_ADDR   0x5049434Fu /* "PICO" — universal dev-mode address across flashes & boards */

static bool uart_installed = false;
static bool candidate_pins_detached_once = false;
static int cur_tx_gpio = -1;
static int cur_rx_gpio = -1;
static char active_desc[64] = "";

/* All usable ESP32-S3 Super Mini + DevKit header GPIOs (never strapping GP0/45/46 or USB GP19/20). */
static const int candidate_gpios[] = {
    1, 2, 43, 44, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 17, 18
};
#define NUM_CANDIDATE_GPIOS (sizeof(candidate_gpios) / sizeof(candidate_gpios[0]))

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

/*
 * Unconditionally detach a pin from the ESP32-S3 GPIO output matrix (U1TXD_OUT_IDX, U0TXD_OUT_IDX, etc.)
 * AND reset IO_MUX back to plain high-Z GPIO input.
 *
 * CRITICAL: In ESP-IDF, uart_set_pin(port, new_tx, new_rx, ...) does NOT disconnect U1TXD_OUT_IDX or
 * U0TXD_OUT_IDX from old_tx when old_tx becomes new_rx (e.g. swapping {1,2} -> {2,1} or {43,44} -> {44,43}).
 * Without detaching unconditionally, the ESP32-S3 drives 3.3 V push-pull output onto its own RX pin!
 */
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

static void detach_all_candidate_pins(void) {
    if (cur_tx_gpio >= 0) {
        detach_pin(cur_tx_gpio);
        cur_tx_gpio = -1;
    }
    if (cur_rx_gpio >= 0) {
        detach_pin(cur_rx_gpio);
        cur_rx_gpio = -1;
    }
    /* Free GPIO43/GPIO44 from default boot console UART0 and ensure clean GPIO inputs on header pins. */
    detach_pin(43);
    detach_pin(44);
    detach_pin(1);
    detach_pin(2);
    candidate_pins_detached_once = true;
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
    if (!candidate_pins_detached_once) {
        detach_all_candidate_pins();
    }
    detach_pin(cur_tx_gpio);
    detach_pin(cur_rx_gpio);
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
    (void)gpio_pulldown_dis((gpio_num_t)rx_gpio);
    (void)gpio_pullup_en((gpio_num_t)rx_gpio);
    cur_tx_gpio = tx_gpio;
    cur_rx_gpio = rx_gpio;
    vTaskDelay(pdMS_TO_TICKS(2));
    (void)uart_flush_input(FP_UART_NUM);
    return true;
}

/*
 * Detect which ESP32-S3 GPIOs are actively driven to 3.3 V idle HIGH by an external CMOS output
 * (specifically R558-S Pin 4 = UART_TX) when loaded with the ESP32-S3's internal ~45 kOhm pull-down.
 * Unconnected / open / powered-off pins read 0; a powered R558-S UART_TX pin reads solid 1!
 */
static size_t detect_driven_high_pins(int *high_pins, size_t max_out) {
    detach_pin(cur_tx_gpio);
    detach_pin(cur_rx_gpio);
    cur_tx_gpio = -1;
    cur_rx_gpio = -1;

    for (size_t i = 0; i < NUM_CANDIDATE_GPIOS; i++) {
        int pin = candidate_gpios[i];
        esp_rom_gpio_connect_out_signal((uint32_t)pin, SIG_GPIO_OUT_IDX, false, false);
        (void)gpio_reset_pin((gpio_num_t)pin);
        (void)gpio_set_direction((gpio_num_t)pin, GPIO_MODE_INPUT);
        (void)gpio_pullup_dis((gpio_num_t)pin);
        (void)gpio_pulldown_en((gpio_num_t)pin);
    }
    vTaskDelay(pdMS_TO_TICKS(3));

    size_t count = 0;
    for (size_t i = 0; i < NUM_CANDIDATE_GPIOS; i++) {
        int pin = candidate_gpios[i];
        if (gpio_get_level((gpio_num_t)pin) == 1 && count < max_out) {
            high_pins[count++] = pin;
        }
        (void)gpio_pulldown_dis((gpio_num_t)pin);
        (void)gpio_pullup_en((gpio_num_t)pin);
    }
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

static bool probe_address_once(uint32_t addr, uint32_t timeout_ms) {
    const uint8_t zero_pwd[4] = { 0, 0, 0, 0 };
    uint8_t code = 0xFF;
    if (fp_sensor_txn(&uart_transport, addr, FP_INS_VFY_PWD,
                      zero_pwd, sizeof(zero_pwd), NULL, 0, NULL,
                      &code, timeout_ms, false) == FP_SENSOR_OK) {
        return true;
    }
    return fp_sensor_txn(&uart_transport, addr, FP_INS_HANDSHAKE,
                         NULL, 0, NULL, 0, NULL,
                         &code, timeout_ms, false) == FP_SENSOR_OK;
}

static bool try_pair_framing(int tx_gpio, int rx_gpio, const fp_framing_t *fr,
                             uint32_t paired_addr, const fp_session_t *ef, bool have_ef, bool wake_pulse) {
    if (!configure_uart_channel(tx_gpio, rx_gpio, fr->baud, fr->stop_bits)) {
        return false;
    }
    if (wake_pulse) {
        const uint8_t wake = 0x00;
        uart_write_bytes(FP_UART_NUM, (const char *)&wake, 1);
        uart_wait_tx_done(FP_UART_NUM, pdMS_TO_TICKS(10));
        vTaskDelay(pdMS_TO_TICKS(6));
        uart_flush_input(FP_UART_NUM);
    }
    bool ok = probe_address_once(FP_FACTORY_ADDRESS, fr->timeout_ms);
    if (!ok) {
        ok = probe_address_once(FP_DEV_SHARED_ADDR, fr->timeout_ms);
    }
    if (!ok && paired_addr != 0 && paired_addr != FP_FACTORY_ADDRESS && paired_addr != FP_DEV_SHARED_ADDR) {
        ok = probe_address_once(paired_addr, fr->timeout_ms);
    }
    if (!ok && have_ef && ef->address != paired_addr) {
        ok = probe_address_once(ef->address, fr->timeout_ms);
    }
    if (!ok) {
        ok = probe_address_once(0x00000000u, fr->timeout_ms);
    }
    if (ok) {
        snprintf(active_desc, sizeof(active_desc), "TX=GPIO%d, RX=GPIO%d (%s)",
                 tx_gpio, rx_gpio, fr->label);
        return true;
    }
    return false;
}

static void record_electrical_diagnostic(const int *high_pins, size_t high_count, bool listen_boot_byte) {
    if (high_count == 0 && listen_boot_byte) {
        /* Poll briefly in case the user cycles 3V3 right now during rescue diagnostics. */
        uint32_t start = esp_now_ms();
        int dyn_pins[4] = { 0 };
        size_t dyn_count = 0;
        while (esp_now_ms() - start < 900 && dyn_count == 0) {
            dyn_count = detect_driven_high_pins(dyn_pins, 4);
            if (dyn_count > 0) {
                high_pins = dyn_pins;
                high_count = dyn_count;
                break;
            }
            vTaskDelay(pdMS_TO_TICKS(40));
        }
        if (high_count == 0) {
            snprintf(active_desc, sizeof(active_desc),
                     "DIAG: Alle Pins 0V (GP1..13,43,44 LOW) -> 3V3/GND/Kabel!");
            return;
        }
    }

    if (high_count == 0) {
        snprintf(active_desc, sizeof(active_desc),
                 "DIAG: Alle Pins 0V (GP1..13,43,44 LOW) -> 3V3/GND/Kabel!");
        return;
    }

    int rx_pin = high_pins[0];
    int alt_tx = (rx_pin == 2) ? 1 : 2;
    uint8_t raw[8] = { 0 };
    int got = 0;
    if (listen_boot_byte && configure_uart_channel(alt_tx, rx_pin, 57600, UART_STOP_BITS_1)) {
        got = esp_uart_read(NULL, raw, sizeof(raw), 1100);
    }
    if (got > 0) {
        bool saw_55 = false;
        for (int i = 0; i < got; i++) {
            if (raw[i] == 0x55) {
                saw_55 = true;
            }
        }
        if (saw_55) {
            snprintf(active_desc, sizeof(active_desc),
                     "DIAG: GP%d=3.3V + 0x55 Boot OK -> Addr-Sperre / RX!", rx_pin);
        }
        else {
            snprintf(active_desc, sizeof(active_desc),
                     "DIAG: GP%d=3.3V, RX=%dB (0x%02X) -> Baud/Addr!", rx_pin, got, raw[0]);
        }
        return;
    }

    if (high_count == 1) {
        snprintf(active_desc, sizeof(active_desc),
                 "DIAG: Sensor-TX auf GP%d=3.3V aktiv (0B) -> Addr/RX!", rx_pin);
    }
    else {
        snprintf(active_desc, sizeof(active_desc),
                 "DIAG: 3.3V auf GP%d,GP%d aktiv (0B) -> Addr-Sperre!", high_pins[0], high_pins[1]);
    }
}

int fp_uart_init(void) {
    detach_all_candidate_pins();
    return configure_uart_channel(FP_UART_RX_GPIO, FP_UART_TX_GPIO, FP_UART_BAUD, UART_STOP_BITS_2) ? 0 : -1;
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

    int high_pins[6] = { 0 };
    size_t high_count = detect_driven_high_pins(high_pins, 6);

    fp_session_t ef = { 0 };
    bool have_ef = uart_efuse_session(&ef);

    const fp_framing_t primary_framings[] = {
        { 57600, UART_STOP_BITS_2, "57600 8N2", 38 },
        { 57600, UART_STOP_BITS_1, "57600 8N1", 32 },
        { 115200, UART_STOP_BITS_1, "115200 8N1", 30 },
    };

    /*
     * Fast path #1: If one or more pins electrically hold CMOS 3.3 V HIGH (powered R558-S UART_TX!),
     * test EVERY candidate ESP32 GPIO as MCU TX paired with that exact RX pin first!
     * This finds ANY wiring across the entire board (adjacent, swapped, or non-adjacent like GP1+GP44) in <0.5 s!
     */
    for (size_t h = 0; h < high_count; h++) {
        int rx_pin = high_pins[h];
        for (size_t t = 0; t < NUM_CANDIDATE_GPIOS; t++) {
            int tx_pin = candidate_gpios[t];
            if (tx_pin == rx_pin) {
                continue;
            }
            for (size_t f = 0; f < sizeof(primary_framings) / sizeof(primary_framings[0]); f++) {
                if (try_pair_framing(tx_pin, rx_pin, &primary_framings[f], paired_addr, &ef, have_ef, f == 0)) {
                    return true;
                }
            }
        }
    }

    /*
     * Fast path #2: Standard pin pairs in both polarities (Sensor TX->GP1/RX->GP2 first, then swapped,
     * GP43/GP44 both polarities, plus adjacent Super Mini header pins).
     */
    const fp_pin_pair_t pairs[] = {
        { FP_UART_RX_GPIO, FP_UART_TX_GPIO }, /* TX=GPIO2, RX=GPIO1 (Sensor TX->GP1, Sensor RX->GP2) */
        { FP_UART_TX_GPIO, FP_UART_RX_GPIO }, /* TX=GPIO1, RX=GPIO2 (Sensor RX->GP1, Sensor TX->GP2) */
        { 44, 43 },                           /* TX=GPIO44, RX=GPIO43 (Sensor TX->GP43, Sensor RX->GP44) */
        { 43, 44 },                           /* TX=GPIO43, RX=GPIO44 (Sensor RX->GP43, Sensor TX->GP44) */
        { 3, 2 },
        { 2, 3 },
        { 4, 3 },
        { 3, 4 },
        { 5, 4 },
        { 4, 5 },
        { 17, 18 },
        { 18, 17 },
    };

    for (size_t i = 0; i < sizeof(pairs) / sizeof(pairs[0]); i++) {
        for (size_t f = 0; f < sizeof(primary_framings) / sizeof(primary_framings[0]); f++) {
            if (try_pair_framing(pairs[i].tx_gpio, pairs[i].rx_gpio, &primary_framings[f],
                                 paired_addr, &ef, have_ef, f == 0)) {
                return true;
            }
        }
    }

    record_electrical_diagnostic(high_pins, high_count, false);
    configure_uart_channel(FP_UART_RX_GPIO, FP_UART_TX_GPIO, FP_UART_BAUD, UART_STOP_BITS_2);
    return false;
}

bool fp_uart_rescue_factory_reset(uint32_t hint_addr) {
    if (!uart_installed && fp_uart_init() != 0) {
        return false;
    }

    int high_pins[6] = { 0 };
    size_t high_count = detect_driven_high_pins(high_pins, 6);

    const fp_pin_pair_t base_pairs[] = {
        { FP_UART_RX_GPIO, FP_UART_TX_GPIO },
        { FP_UART_TX_GPIO, FP_UART_RX_GPIO },
        { 44, 43 },
        { 43, 44 },
        { 3, 2 },
        { 2, 3 },
        { 5, 4 },
        { 4, 5 },
    };
    const fp_framing_t framings[] = {
        { 57600, UART_STOP_BITS_2, "57600 8N2", 55 },
        { 57600, UART_STOP_BITS_1, "57600 8N1", 45 },
        { 115200, UART_STOP_BITS_1, "115200 8N1", 40 },
        { 38400, UART_STOP_BITS_1, "38400 8N1", 45 },
        { 19200, UART_STOP_BITS_1, "19200 8N1", 55 },
        { 9600, UART_STOP_BITS_1, "9600 8N1", 65 },
    };

    /* Build combined rescue pair table: all crosspoint pairs for detected 3.3 V pins + standard pairs. */
    fp_pin_pair_t rescue_pairs[40];
    size_t num_pairs = 0;
    for (size_t h = 0; h < high_count && num_pairs < 32; h++) {
        int rx_pin = high_pins[h];
        for (size_t t = 0; t < NUM_CANDIDATE_GPIOS && num_pairs < 32; t++) {
            if (candidate_gpios[t] != rx_pin) {
                rescue_pairs[num_pairs].tx_gpio = candidate_gpios[t];
                rescue_pairs[num_pairs].rx_gpio = rx_pin;
                num_pairs++;
            }
        }
    }
    for (size_t i = 0; i < sizeof(base_pairs) / sizeof(base_pairs[0]) && num_pairs < 40; i++) {
        rescue_pairs[num_pairs++] = base_pairs[i];
    }

    fp_session_t ef = { 0 };
    bool have_ef = uart_efuse_session(&ef);
    const uint8_t zero_pwd[4] = { 0, 0, 0, 0 };
    const uint8_t ff_pwd[4] = { 0xFF, 0xFF, 0xFF, 0xFF };

    for (size_t i = 0; i < num_pairs; i++) {
        for (size_t f = 0; f < sizeof(framings) / sizeof(framings[0]); f++) {
            /* Only exhaust slower bauds on primary pairs or electrically-active pins. */
            if (f >= 3 && i >= 6) {
                break;
            }
            if (!configure_uart_channel(rescue_pairs[i].tx_gpio, rescue_pairs[i].rx_gpio,
                                        framings[f].baud, framings[f].stop_bits)) {
                continue;
            }
            if (f == 0) {
                const uint8_t wake = 0x00;
                uart_write_bytes(FP_UART_NUM, (const char *)&wake, 1);
                uart_wait_tx_done(FP_UART_NUM, pdMS_TO_TICKS(10));
                vTaskDelay(pdMS_TO_TICKS(6));
                uart_flush_input(FP_UART_NUM);
            }
            uint8_t code = 0xFF;
            const fp_session_t dev_sh = { .address = FP_DEV_SHARED_ADDR, .password = { 0x52, 0x35, 0x35, 0x38 } };
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
            uint32_t addrs[5] = { FP_FACTORY_ADDRESS, FP_DEV_SHARED_ADDR, 0x00000000u, hint_addr, have_ef ? ef.address : 0u };
            for (size_t a = 0; a < 5; a++) {
                if (a >= 3 && addrs[a] == 0u) {
                    continue;
                }
                /* Try Cancel + SetPwd(0) + SetChipAddr(0xFFFFFFFF) + RestSetting(0x3B) (R558-S hardware unlock). */
                fp_session_t tmp_s = { .address = addrs[a], .password = { 0, 0, 0, 0 } };
                (void)fp_sensor_cancel(&uart_transport, &tmp_s, &code);
                fp_session_t ff_s = { .address = addrs[a], .password = { 0xFF, 0xFF, 0xFF, 0xFF } };
                if (fp_sensor_verify_password(&uart_transport, &ff_s, &code) == FP_SENSOR_OK && code == FP_CONF_OK) {
                    (void)fp_sensor_set_password(&uart_transport, addrs[a], zero_pwd, &code);
                }
                else {
                    (void)fp_sensor_set_password(&uart_transport, addrs[a], zero_pwd, &code);
                    (void)fp_sensor_set_password(&uart_transport, addrs[a], ff_pwd, &code);
                    (void)fp_sensor_set_password(&uart_transport, addrs[a], zero_pwd, &code);
                }
                if (addrs[a] != FP_FACTORY_ADDRESS) {
                    (void)fp_sensor_set_chip_address(&uart_transport, addrs[a], FP_FACTORY_ADDRESS, &code);
                }
                if (fp_sensor_rest_setting(&uart_transport, addrs[a], &code) == FP_SENSOR_OK && code == FP_CONF_OK) {
                    vTaskDelay(pdMS_TO_TICKS(120));
                    snprintf(active_desc, sizeof(active_desc), "TX=GPIO%d, RX=GPIO%d (%s)",
                             rescue_pairs[i].tx_gpio, rescue_pairs[i].rx_gpio, framings[f].label);
                    return true;
                }
            }
            if (probe_address_once(FP_FACTORY_ADDRESS, framings[f].timeout_ms)) {
                snprintf(active_desc, sizeof(active_desc), "TX=GPIO%d, RX=GPIO%d (%s)",
                         rescue_pairs[i].tx_gpio, rescue_pairs[i].rx_gpio, framings[f].label);
                return true;
            }
        }
    }

    if (fp_uart_scan_pins(hint_addr)) {
        return true;
    }
    record_electrical_diagnostic(high_pins, high_count, true);
    configure_uart_channel(FP_UART_RX_GPIO, FP_UART_TX_GPIO, FP_UART_BAUD, UART_STOP_BITS_2);
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

bool fp_uart_rescue_factory_reset(uint32_t hint_addr) {
    return fp_uart_scan_pins(hint_addr);
}

const char *fp_uart_active_pins(void) {
    return emu_fd >= 0 ? "TX=GPIO2, RX=GPIO1 (57600 8N2)" : "";
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
