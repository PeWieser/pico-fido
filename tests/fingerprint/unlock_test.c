/*
 * Host unit tests for the 5-stage GROW R558-S Password Unlock & Passwordless `za` Bypass Engine.
 * Exercises:
 *   1. Stage 1A: AVX-512 OUI key (`0x7BF6B530`) unlock -> factory `0xFFFFFFFF` + `pwd=0`.
 *   2. Stage 1B: `PS_ReadINFpage (0x16)` 512-byte flash parameter leak (`INF[0x3C..0x3F]`, LE/BE).
 *   3. Stage 3A: `PS_ReadNotepad (0x19)` signed `int8_t` negative page OOB Flash leak (`0xFA..0xFF`).
 *   4. Stage 2:  OEM §5 `za` passwordless bypass (`0x53 -> 0x55`, `0x54` enroll, `0x55` 1:N search)
 *                when `0x13 VfyPwd` stays permanently locked (`0x21`).
 *   5. Stage 4:  `GP3` Split-Packet FSM Retention binary-search calibration + 240 MHz boot brownout
 *                glitch resetting `ParaTableFlag != 0x1234` -> factory reset.
 *   6. Stage 5:  `GP4/GP5` ARM ADIv5 SWD non-destructive SRAM/Flash password extraction at `+0x34`.
 */

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "fp_r558.h"
#include "fp_r558_sensor.h"
#include "fp_r558_unlock.h"

/* Simulated R558-S hardware state */
typedef struct {
    uint32_t chip_addr;
    uint8_t password[4];
    bool authenticated;
    bool allow_inf_leak;
    bool allow_notepad_oob;
    bool allow_za_bypass;
    bool allow_swd;
    bool allow_gp3_glitch;
    uint32_t crit_threshold;
    uint32_t glitch_delay_min_us;
    uint32_t glitch_delay_max_us;
    uint16_t za_match_page;
    uint32_t wrong_vfy_strikes;
    bool uart_muted;
    bool flash_baud_corrupted;

    /* Raw TX/RX buffers for ZFM framing + split-packet calibration */
    uint8_t rx_to_host[1024];
    size_t rx_len;
    size_t rx_pos;

    uint8_t split_half[16];
    size_t split_len;
    bool split_reset;
} sim_r558_t;

static sim_r558_t g_sim;

static void sim_reset(uint32_t addr, const uint8_t pwd[4]) {
    memset(&g_sim, 0, sizeof(g_sim));
    g_sim.chip_addr = addr;
    memcpy(g_sim.password, pwd, 4);
    fp_unlock_reset_state();
    fp_unlock_set_hal(NULL, NULL);
}

static void sim_push_packet(uint32_t addr, uint8_t pid, const uint8_t *payload, uint16_t plen) {
    uint8_t tmp[256];
    size_t n = fp_sensor_encode_packet(tmp, sizeof(tmp), addr, pid, payload, plen);
    assert(n > 0 && g_sim.rx_len + n <= sizeof(g_sim.rx_to_host));
    memcpy(g_sim.rx_to_host + g_sim.rx_len, tmp, n);
    g_sim.rx_len += n;
}

static void sim_push_ack(uint8_t conf, const uint8_t *extra, uint16_t extra_len) {
    uint8_t pay[64];
    pay[0] = conf;
    if (extra_len > 0) {
        memcpy(pay + 1, extra, extra_len);
    }
    sim_push_packet(g_sim.chip_addr, FP_PID_ACK, pay, (uint16_t)(1u + extra_len));
}

static int sim_uart_write(void *ctx, const uint8_t *data, size_t len) {
    (void)ctx;
    assert(len >= 12);
    assert(data[0] == 0xEF && data[1] == 0x01);
    uint32_t dst_addr = ((uint32_t)data[2] << 24) | ((uint32_t)data[3] << 16) |
                        ((uint32_t)data[4] << 8) | data[5];
    uint16_t plen = (uint16_t)(((uint16_t)data[7] << 8) | data[8]);
    uint8_t ins = data[9];
    const uint8_t *params = data + 10;
    uint16_t param_len = (uint16_t)(plen - 3u);

    bool is_zero_pwd = (g_sim.password[0] == 0 && g_sim.password[1] == 0 &&
                        g_sim.password[2] == 0 && g_sim.password[3] == 0);

    if (g_sim.uart_muted) {
        return 0; /* Real GROW R558-S hardware completely drops UART RX once muted! */
    }

    /* Address filter: accept exact ChipAddr or broadcast HandShake/VfyPwd */
    if (dst_addr != g_sim.chip_addr && dst_addr != FP_FACTORY_ADDRESS) {
        return 0;
    }

    if (ins == FP_INS_VFY_PWD && param_len >= 4) {
        if (memcmp(params, g_sim.password, 4) == 0) {
            g_sim.authenticated = true;
            g_sim.wrong_vfy_strikes = 0;
            sim_push_ack(FP_CONF_OK, NULL, 0);
        }
        else {
            g_sim.wrong_vfy_strikes++;
            if (g_sim.wrong_vfy_strikes > 8u) {
                g_sim.uart_muted = true;
                return 0;
            }
            sim_push_ack(FP_CONF_WRONG_PWD, NULL, 0);
        }
        return 0;
    }

    if (ins == FP_INS_READ_INF_PAGE && g_sim.allow_inf_leak) {
        sim_push_ack(FP_CONF_OK, NULL, 0);
        uint8_t inf[128];
        memset(inf, 0, sizeof(inf));
        /* Table 2-1 layout: DeviceAddress @ 0x08 (BE), Password @ 0x3C (LE reversed to test endianness!) */
        inf[0x08] = (uint8_t)(g_sim.chip_addr >> 24);
        inf[0x09] = (uint8_t)(g_sim.chip_addr >> 16);
        inf[0x0A] = (uint8_t)(g_sim.chip_addr >> 8);
        inf[0x0B] = (uint8_t)g_sim.chip_addr;
        inf[0x3C] = g_sim.password[3];
        inf[0x3D] = g_sim.password[2];
        inf[0x3E] = g_sim.password[1];
        inf[0x3F] = g_sim.password[0];
        inf[0x7E] = 0x12;
        inf[0x7F] = 0x34;
        sim_push_packet(g_sim.chip_addr, FP_PID_END_DATA, inf, sizeof(inf));
        return 0;
    }

    if (ins == FP_INS_READ_NOTEPAD && g_sim.allow_notepad_oob && param_len >= 1) {
        int8_t spage = (int8_t)params[0];
        uint8_t page_data[32];
        memset(page_data, 0, sizeof(page_data));
        if (spage < 0) {
            /* Simulate ParaTable starting at NOTEPAD_BASE - 128 (`spage = -4` -> offset 0..31) */
            int base_off = (spage + 4) * 32;
            uint8_t para[128];
            memset(para, 0, sizeof(para));
            para[0x08] = (uint8_t)(g_sim.chip_addr >> 24);
            para[0x09] = (uint8_t)(g_sim.chip_addr >> 16);
            para[0x0A] = (uint8_t)(g_sim.chip_addr >> 8);
            para[0x0B] = (uint8_t)g_sim.chip_addr;
            memcpy(para + 0x3C, g_sim.password, 4);
            if (base_off >= 0 && base_off + 32 <= 128) {
                memcpy(page_data, para + base_off, 32);
            }
        }
        sim_push_ack(FP_CONF_OK, page_data, 32);
        return 0;
    }

    /* §5 `za` passwordless compatibility opcodes */
    if (g_sim.allow_za_bypass) {
        if (ins == FP_INS_ZA_GET_ECHO) {
            sim_push_ack(FP_ZA_ECHO_OK, NULL, 0);
            return 0;
        }
        if (ins == FP_INS_ZA_TERMINATE) {
            sim_push_ack(FP_ZA_TERMINATED_OK, NULL, 0);
            return 0;
        }
        if (ins == FP_INS_ZA_AUTO_LOGIN) {
            const uint8_t step_done[1] = { 0x06 };
            sim_push_ack(FP_CONF_OK, step_done, 1);
            return 0;
        }
        if (ins == FP_INS_ZA_AUTO_SEARCH) {
            const uint8_t hit[4] = {
                (uint8_t)(g_sim.za_match_page >> 8),
                (uint8_t)(g_sim.za_match_page & 0xFF),
                0x00, 0x64
            };
            sim_push_ack(FP_CONF_OK, hit, 4);
            return 0;
        }
    }

    /* Locked gate: every other command returns 0x21 unless authenticated or zero password! */
    if (!g_sim.authenticated && !is_zero_pwd) {
        sim_push_ack(0x21, NULL, 0);
        return 0;
    }

    switch (ins) {
        case FP_INS_EMPTY:
        case FP_INS_CONTROL_BLN:
        case FP_INS_HANDSHAKE:
            sim_push_ack(FP_CONF_OK, NULL, 0);
            break;
        case FP_INS_SET_PWD:
            memcpy(g_sim.password, params, 4);
            sim_push_ack(FP_CONF_OK, NULL, 0);
            break;
        case FP_INS_SET_CHIP_ADDR:
            sim_push_ack(FP_CONF_OK, NULL, 0);
            g_sim.chip_addr = ((uint32_t)params[0] << 24) | ((uint32_t)params[1] << 16) |
                              ((uint32_t)params[2] << 8) | params[3];
            break;
        case FP_INS_REST_SETTING:
            memset(g_sim.password, 0, 4);
            g_sim.chip_addr = FP_FACTORY_ADDRESS;
            sim_push_ack(FP_CONF_OK, NULL, 0);
            break;
        default:
            sim_push_ack(FP_CONF_OK, NULL, 0);
            break;
    }
    return 0;
}

static int sim_uart_read(void *ctx, uint8_t *data, size_t len, uint32_t timeout_ms) {
    (void)ctx;
    (void)timeout_ms;
    if (g_sim.rx_pos >= g_sim.rx_len) {
        return 0;
    }
    size_t avail = g_sim.rx_len - g_sim.rx_pos;
    size_t n = avail < len ? avail : len;
    memcpy(data, g_sim.rx_to_host + g_sim.rx_pos, n);
    g_sim.rx_pos += n;
    if (g_sim.rx_pos >= g_sim.rx_len) {
        g_sim.rx_pos = 0;
        g_sim.rx_len = 0;
    }
    return (int)n;
}

static void sim_uart_flush(void *ctx) {
    (void)ctx;
    g_sim.rx_pos = 0;
    g_sim.rx_len = 0;
}

static const fp_transport_t g_sim_transport = {
    .ctx = NULL,
    .write = sim_uart_write,
    .read = sim_uart_read,
    .flush = sim_uart_flush,
};

/* ---- HAL hooks for GP3 brownout glitch + GP4/GP5 SWD extraction tests ---- */

static bool mock_check_gp3(void *ctx) {
    (void)ctx;
    return g_sim.allow_gp3_glitch;
}

static void mock_power_cycle_gp3(void *ctx, uint32_t off_ms, uint32_t settle_ms) {
    (void)ctx;
    (void)off_ms;
    (void)settle_ms;
    g_sim.authenticated = false;
    g_sim.wrong_vfy_strikes = 0;
    g_sim.uart_muted = g_sim.flash_baud_corrupted;
    g_sim.split_len = 0;
    g_sim.split_reset = false;
}

static void mock_glitch_pulse(void *ctx, uint32_t delay_us, uint32_t width_cycles, bool crowbar_rx) {
    (void)ctx;
    (void)crowbar_rx;
    if (width_cycles >= g_sim.crit_threshold) {
        g_sim.split_reset = true;
    }
    /* If pulse fires inside target boot ParaTableFlag window at ~90..108% of crit_threshold: factory reset! */
    if (g_sim.allow_gp3_glitch &&
        delay_us >= g_sim.glitch_delay_min_us && delay_us <= g_sim.glitch_delay_max_us &&
        width_cycles >= (g_sim.crit_threshold * 90u) / 100u &&
        width_cycles <= (g_sim.crit_threshold * 108u) / 100u) {
        memset(g_sim.password, 0, 4);
        g_sim.chip_addr = FP_FACTORY_ADDRESS;
        g_sim.flash_baud_corrupted = false;
        g_sim.uart_muted = false;
    }
}

static bool mock_uart_raw_mode(void *ctx, int baud, bool even_parity) {
    (void)ctx;
    (void)baud;
    (void)even_parity;
    return true;
}

static int mock_uart_write_raw(void *ctx, const uint8_t *buf, size_t len) {
    (void)ctx;
    if (len == 6 && buf[0] == 0xEF && buf[1] == 0x01) {
        memcpy(g_sim.split_half, buf, 6);
        g_sim.split_len = 6;
        g_sim.split_reset = false;
        return 0;
    }
    if (len == 6 && g_sim.split_len == 6) {
        if (!g_sim.split_reset) {
            memcpy(g_sim.split_half + 6, buf, 6);
            sim_uart_write(NULL, g_sim.split_half, 12);
        }
        g_sim.split_len = 0;
        return 0;
    }
    return 0;
}

static int mock_uart_read_raw(void *ctx, uint8_t *buf, size_t max_len, uint32_t timeout_ms) {
    return sim_uart_read(ctx, buf, max_len, timeout_ms);
}

static bool mock_swd_connect(void *ctx, uint32_t *idcode_out) {
    (void)ctx;
    if (!g_sim.allow_swd) {
        return false;
    }
    *idcode_out = 0x2BA01477u; /* ARM Cortex-M3 SW-DP IDCODE */
    return true;
}

static bool mock_swd_read32(void *ctx, uint32_t addr, uint32_t *val_out) {
    (void)ctx;
    if (addr == 0x20000108u) {
        *val_out = g_sim.chip_addr;
        return true;
    }
    if (addr == 0x20000108u + 0x34u) {
        *val_out = (uint32_t)g_sim.password[0] |
                   ((uint32_t)g_sim.password[1] << 8) |
                   ((uint32_t)g_sim.password[2] << 16) |
                   ((uint32_t)g_sim.password[3] << 24);
        return true;
    }
    *val_out = 0xFFFFFFFFu;
    return true;
}

static bool mock_swd_write32(void *ctx, uint32_t addr, uint32_t val) {
    (void)ctx;
    (void)addr;
    (void)val;
    return true;
}

static const fp_unlock_hal_t g_mock_hal = {
    .check_gp3_power = mock_check_gp3,
    .power_cycle_gp3 = mock_power_cycle_gp3,
    .glitch_pulse = mock_glitch_pulse,
    .uart_raw_mode = mock_uart_raw_mode,
    .uart_write_raw = mock_uart_write_raw,
    .uart_read_raw = mock_uart_read_raw,
    .swd_connect = mock_swd_connect,
    .swd_read32 = mock_swd_read32,
    .swd_write32 = mock_swd_write32,
};

int main(void) {
    fp_unlock_report_t rep;

    /* 1. Stage 1A: AVX-512 OUI key (`0x7BF6B530`) unlocks locked 0x29062D09 sensor to factory state! */
    const uint8_t oui_pwd[4] = { 0x7B, 0xF6, 0xB5, 0x30 };
    sim_reset(0x29062D09u, oui_pwd);
    fp_unlock_run_pass(&g_sim_transport, 0, 0, NULL, false, &rep);
    assert(rep.unlocked_factory == true);
    assert(g_sim.chip_addr == FP_FACTORY_ADDRESS);
    assert(memcmp(g_sim.password, "\x00\x00\x00\x00", 4) == 0);
    printf("  [OK] Stage 1A: AVX-512 OUI password (0x7BF6B530) factory unlock\n");

    /* 2. Stage 1B: PS_ReadINFpage (0x16) 512B flash leak extracts arbitrary random password! */
    const uint8_t rnd_pwd1[4] = { 0xA9, 0x4E, 0x17, 0xC3 };
    sim_reset(0x29062D09u, rnd_pwd1);
    g_sim.allow_inf_leak = true;
    fp_unlock_run_pass(&g_sim_transport, 0, 0, NULL, false, &rep);
    assert(rep.unlocked_factory == true);
    assert(g_sim.chip_addr == FP_FACTORY_ADDRESS);
    assert(memcmp(g_sim.password, "\x00\x00\x00\x00", 4) == 0);
    printf("  [OK] Stage 1B: PS_ReadINFpage (0x16) Table 2-1 +0x3C password leak unlock\n");

    /* 3. Stage 3A: PS_ReadNotepad (0x19) signed int8_t negative page OOB Flash leak! */
    const uint8_t rnd_pwd2[4] = { 0xD4, 0x81, 0x6B, 0x2F };
    sim_reset(0x29062D09u, rnd_pwd2);
    g_sim.allow_notepad_oob = true;
    fp_unlock_run_pass(&g_sim_transport, 0, 0, NULL, false, &rep);
    assert(rep.unlocked_factory == true);
    assert(g_sim.chip_addr == FP_FACTORY_ADDRESS);
    printf("  [OK] Stage 3A: PS_ReadNotepad (0x19) signed negative page OOB unlock\n");

    /* 4. Stage 2: OEM §5 `za` passwordless compatibility bypass when 0x13/0x16/0x19 all return 0x21! */
    const uint8_t unknown_pwd[4] = { 0x91, 0x22, 0x77, 0xEE };
    sim_reset(0x29062D09u, unknown_pwd);
    g_sim.allow_za_bypass = true;
    g_sim.za_match_page = 0;
    fp_unlock_run_pass(&g_sim_transport, 0, 0, NULL, false, &rep);
    assert(rep.unlocked_factory == false);
    assert(rep.za_bypass_available == true);
    assert(fp_za_enroll_finger(&g_sim_transport, 0x29062D09u, 0, 2, NULL, NULL, NULL, NULL) == FP_OK);
    uint16_t matched_slot = 0xFFFFu;
    assert(fp_za_verify_finger(&g_sim_transport, 0x29062D09u, 2000, &matched_slot, NULL, NULL, NULL, NULL) == FP_OK);
    assert(matched_slot == 0u);
    printf("  [OK] Stage 2:  OEM §5 `za` passwordless bypass (0x53/0x54/0x55) enroll + 1:N verify\n");

    /* 5. Stage 4: GP3 Split-Packet binary-search calibration + 240 MHz Boot ParaTableFlag Glitch! */
    sim_reset(0x29062D09u, unknown_pwd);
    g_sim.allow_gp3_glitch = true;
    g_sim.crit_threshold = 9450u;
    g_sim.glitch_delay_min_us = 3400u;
    g_sim.glitch_delay_max_us = 4200u;
    fp_unlock_set_hal(&g_mock_hal, NULL);

    fp_unlock_run_pass(&g_sim_transport, 1, 0, NULL, false, &rep);
    assert(rep.gp3_power_capable == true);
    /* Calibrated crit_cycles must pinpoint 9450 cycles within <= 24 cycles! */
    assert(rep.crit_cycles >= 9440u && rep.crit_cycles <= 9480u);

    bool glitch_unlocked = false;
    for (uint8_t p = 2; p <= 8; p++) {
        fp_unlock_run_pass(&g_sim_transport, p, 0, NULL, false, &rep);
        if (rep.unlocked_factory) {
            glitch_unlocked = true;
            break;
        }
    }
    assert(glitch_unlocked == true);
    assert(g_sim.chip_addr == FP_FACTORY_ADDRESS);
    printf("  [OK] Stage 4:  GP3 Split-Packet calibration (%uc) + Boot ParaTableFlag glitch unlock\n",
           rep.crit_cycles);

    /* 6. Stage 5: GP4/GP5 ARM ADIv5 SWD non-destructive SRAM/Flash password extraction! */
    const uint8_t swd_secret[4] = { 0x3F, 0x8A, 0xC1, 0x5E };
    sim_reset(0x29062D09u, swd_secret);
    g_sim.allow_swd = true;
    fp_unlock_set_hal(&g_mock_hal, NULL);
    fp_unlock_run_pass(&g_sim_transport, 0, 0, NULL, false, &rep);
    assert(rep.swd_detected == true);
    assert(rep.unlocked_factory == true);
    assert(memcmp(rep.recovered_pwd, swd_secret, 4) == 0);
    assert(g_sim.chip_addr == FP_FACTORY_ADDRESS);
    printf("  [OK] Stage 5:  GP4/GP5 ARM ADIv5 SWD SRAM +0x34 password extraction & reset\n");

    /* 7. Full 25-pass (0..24) Zero-VfyPwd-Mute Hardware Regression Test! */
    sim_reset(0x29062D09u, unknown_pwd);
    g_sim.allow_gp3_glitch = true;
    g_sim.crit_threshold = 9450u;
    g_sim.glitch_delay_min_us = 999999u; /* Force full 24-pass sweep without early hit */
    g_sim.glitch_delay_max_us = 999999u;
    g_sim.uart_muted = true; /* Even starting ALREADY MUTED from prior session auto-recovers in Pass 0! */
    fp_unlock_set_hal(&g_mock_hal, NULL);
    for (uint8_t p = 0; p <= FP_UNLOCK_MAX_PASSES; p++) {
        fp_unlock_run_pass(&g_sim_transport, p, 0, NULL, false, &rep);
        assert(g_sim.uart_muted == false);
        assert(rep.target_addr == 0x29062D09u);
        if (p == 1u) {
            g_sim.wrong_vfy_strikes = 0; /* Verify Passes 2..24 emit ZERO wrong VfyPwd strikes! */
        }
        else if (p >= 2u) {
            assert(g_sim.wrong_vfy_strikes == 0u);
        }
    }
    uint8_t post_conf = 0xFF;
    assert(fp_sensor_txn(&g_sim_transport, 0x29062D09u, FP_INS_HANDSHAKE,
                         NULL, 0, NULL, 0, NULL, &post_conf, 40, false) == FP_SENSOR_OK);
    printf("  [OK] Stage 7:  Full 24-pass Dual-Rail sweep -> 0 VfyPwd strikes, auto-unmute, UART live!\n");

    /* 8. Dead-UART / Corrupted Flash BaudRate Recovery (`CAL=645c` preserved + ResetDefaultPara)! */
    sim_reset(0x29062D09u, unknown_pwd);
    g_sim.allow_gp3_glitch = true;
    g_sim.crit_threshold = 645u;
    g_sim.glitch_delay_min_us = 3400u;
    g_sim.glitch_delay_max_us = 4200u;
    g_sim.flash_baud_corrupted = true;
    g_sim.uart_muted = true; /* Remains completely dead even after cold power-cycle! */
    fp_unlock_set_hal(&g_mock_hal, NULL);
    fp_unlock_run_pass(&g_sim_transport, 0, 0x29062D09u, NULL, false, &rep);
    assert(rep.gp3_power_capable == true);
    assert(strstr(rep.summary, "LIVE=NO") != NULL);
    fp_unlock_run_pass(&g_sim_transport, 1, 0x29062D09u, NULL, false, &rep);
    assert(rep.crit_cycles == 645u);
    bool dead_uart_recovered = false;
    for (uint8_t p = 2; p <= 8; p++) {
        fp_unlock_run_pass(&g_sim_transport, p, 0x29062D09u, NULL, false, &rep);
        if (rep.unlocked_factory) {
            dead_uart_recovered = true;
            break;
        }
    }
    assert(dead_uart_recovered == true);
    assert(g_sim.chip_addr == FP_FACTORY_ADDRESS);
    assert(g_sim.uart_muted == false);
    printf("  [OK] Stage 8:  Dead-UART / corrupted ParaTable recovery via 645c silicon landmark sweep!\n");

    fp_unlock_set_hal(NULL, NULL);
    printf("ALL 8 R558-S UNLOCK & BYPASS SUITES PASSED!\n");
    return 0;
}
