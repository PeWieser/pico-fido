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

#ifndef FP_R558_UNLOCK_H_
#define FP_R558_UNLOCK_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "fp_r558.h"
#include "fp_r558_sensor.h"

/* Maximum pass index for multi-pass hardware power/glitch sweeps (0 = software/audit, 1..32 = GP3+GP4 sweeps). */
#define FP_UNLOCK_MAX_PASSES        32u

/* Additional protocol opcodes documented in OEM V1.1 / V1.5.1 / R5xx hardware manuals. */
#define FP_INS_READ_INF_PAGE        0x16
#define FP_INS_WRITE_NOTEPAD        0x18
#define FP_INS_READ_NOTEPAD         0x19
#define FP_INS_SOFT_RESET           0x33
#define FP_INS_AURA_LED_RAW         0x40
#define FP_INS_ZA_GET_ECHO          0x53
#define FP_INS_ZA_AUTO_LOGIN        0x54
#define FP_INS_ZA_AUTO_SEARCH       0x55
#define FP_INS_ZA_SEARCH_RES_BACK   0x56
#define FP_INS_ZA_AUTO_LOGIN_STAB   0x57
#define FP_INS_ZA_AUTO_SEARCH_ECHO  0x58
#define FP_INS_ZA_TERMINATE         0xAA

#define FP_ZA_ECHO_OK               0x55
#define FP_ZA_TERMINATED_OK         0x58

typedef struct {
    bool unlocked_factory;      /* Password erased to 0x00000000 & ChipAddr reset to 0xFFFFFFFF */
    bool za_bypass_available;   /* §5 `za` opcodes (0x53/0x54/0x55) bypass password lock cleanly */
    bool gp3_power_capable;     /* Pin 3 (VCC_MCU) responds to GP3 power cycling */
    bool swd_detected;          /* ARM ADIv5 SWD debug port answered on GP4/GP5 */
    uint32_t target_addr;       /* Observed ChipAddr (e.g. 0x29062D09 or 0xFFFFFFFF) */
    uint8_t recovered_pwd[4];   /* Recovered 4-byte password if extracted */
    bool has_recovered_pwd;
    uint32_t crit_cycles;       /* Calibrated 240 MHz crowbar reset threshold in CPU cycles */
    uint32_t swd_idcode;        /* Observed SWD DP IDCODE if connected */
    char summary[160];          /* Compact human/UI telemetry string stored in status.sensor_pins */
} fp_unlock_report_t;

/* Virtualizable hardware hooks so host unit tests can exercise all 5 stages deterministically. */
typedef struct {
    /* Checks whether pulling GP3 LOW removes power from R558-S UART_TX (true = Pin 3 is on GP3). */
    bool (*check_gp3_power)(void *ctx);
    /* Cycles GP3 LOW for off_ms, then HIGH, waiting settle_ms (0 = return immediately at rising edge). */
    void (*power_cycle_gp3)(void *ctx, uint32_t off_ms, uint32_t settle_ms);
    /*
     * Fires a cycle-accurate crowbar pulse on GP3 after waiting delay_us:
     * if crowbar_rx is true, also pulls UART TX (sensor RX) LOW during the pulse; otherwise floats TX Hi-Z.
     */
    void (*glitch_pulse)(void *ctx, uint32_t delay_us, uint32_t width_cycles, bool crowbar_rx);
    /* Raw zero-guard UART write/read/reconfig for split-packet calibration & 8E1 ISP bootloader. */
    bool (*uart_raw_mode)(void *ctx, int baud, bool even_parity);
    int (*uart_write_raw)(void *ctx, const uint8_t *buf, size_t len);
    int (*uart_read_raw)(void *ctx, uint8_t *buf, size_t max_len, uint32_t timeout_ms);
    /* Non-destructive SWD probe + 32-bit AHB-AP memory read/write on GP4 (SWCLK) / GP5 (SWDIO). */
    bool (*swd_connect)(void *ctx, uint32_t *idcode_out);
    bool (*swd_read32)(void *ctx, uint32_t addr, uint32_t *val_out);
    bool (*swd_write32)(void *ctx, uint32_t addr, uint32_t val);
} fp_unlock_hal_t;

/* Installs a custom HAL for host unit tests (pass NULL to restore default hardware HAL). */
void fp_unlock_set_hal(const fp_unlock_hal_t *hal, void *ctx);

/* Resets internal multi-pass calibration state. */
void fp_unlock_reset_state(void);

/*
 * Executes one bounded recovery pass (`pass` = 0..32, max ~2.2 s so USB & WDT never time out)
 * against a password-locked GROW R558-S sensor using `t` and optional board `efuse_pwd`.
 */
void fp_unlock_run_pass(const fp_transport_t *t, uint8_t pass, uint32_t hint_addr,
                        const uint8_t efuse_pwd[4], bool has_efuse_pwd,
                        fp_unlock_report_t *out);

/* §5 `za` passwordless compatibility engine helpers used when `za_bypass_available` is paired. */
bool fp_za_probe_echo(const fp_transport_t *t, uint32_t addr);
fp_result_t fp_za_enroll_finger(const fp_transport_t *t, uint32_t addr, uint16_t slot, uint8_t entries,
                                volatile bool *cancel_flag, volatile bool *waiting_flag,
                                uint8_t *err_ins, uint8_t *err_conf);
fp_result_t fp_za_verify_finger(const fp_transport_t *t, uint32_t addr, uint32_t timeout_ms, uint16_t *page_out,
                                volatile bool *cancel_flag, volatile bool *waiting_flag,
                                uint8_t *err_ins, uint8_t *err_conf);

#endif /* FP_R558_UNLOCK_H_ */
