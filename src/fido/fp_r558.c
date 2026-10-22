/*
 * Pico FIDO - R558 fingerprint sensor, pairing, verification and template management.
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

#include "picokeys.h"
#include "fido.h"
#include "ctap.h"
#include "files.h"
#include "fp_r558.h"
#include "fp_r558_sensor.h"
#include "fp_r558_uart.h"
#include "fp_led.h"
#include "random.h"
#include "fs/flash.h"
#include "fs/file.h"
#include <inttypes.h>
#include "mbedtls/platform_util.h"
#include "mbedtls/sha256.h"
#include <stdio.h>
#include <string.h>

#if defined(ESP_PLATFORM)
#include "esp_flash_encrypt.h"
#include "esp_mac.h"
#endif

#if defined(ESP_PLATFORM)
#include "compat/esp_compat.h"
#else
#include "compat/board.h"
#endif

/* ------------------------------------------------------------------------- */
/* Persistent configuration (EF_FP_CONF, encrypted by the object store).     */
/* ------------------------------------------------------------------------- */

#if defined(ENABLE_R558_FINGERPRINT)
#define FP_FEATURE_ON 1
#else
#define FP_FEATURE_ON 0
#endif

#define FP_CONF_VERSION   1
#define FP_CONF_BYTES     46
#define FP_CONF_BITMAP    (FP_TEMPLATE_MAX / 8)

#define FP_FLAG_PAIRED    0x01
#define FP_FLAG_LOCKED    0x02
#define FP_FLAG_STAGED    0x04   /* pairing in progress: secrets written, sensor not yet verified */

typedef struct {
    uint8_t flags;
    uint8_t fail_count;
    uint8_t password[4];
    uint32_t address;
    uint16_t capacity;
    uint8_t slots[FP_CONF_BITMAP];
} fp_conf_t;

/* R1: secrets (sensor password and address) may only be created or restored while flash encryption is active. */
static bool flash_encryption_active(void) {
#if defined(ESP_PLATFORM)
    return esp_flash_encryption_enabled();
#else
    return false;
#endif
}

static bool flash_requirement_met(void) {
    return FP_REQUIRE_FLASH_ENCRYPTION == 0 || flash_encryption_active();
}

static void conf_clear(fp_conf_t *c) {
    mbedtls_platform_zeroize(c, sizeof(*c));
}

static void conf_serialize(const fp_conf_t *c, uint8_t out[FP_CONF_BYTES]) {
    out[0] = FP_CONF_VERSION;
    out[1] = c->flags;
    out[2] = c->fail_count;
    out[3] = 0;
    memcpy(out + 4, c->password, 4);
    out[8] = (uint8_t)(c->address >> 24);
    out[9] = (uint8_t)(c->address >> 16);
    out[10] = (uint8_t)(c->address >> 8);
    out[11] = (uint8_t)(c->address);
    out[12] = (uint8_t)(c->capacity >> 8);
    out[13] = (uint8_t)(c->capacity);
    memcpy(out + 14, c->slots, FP_CONF_BITMAP);
}

static bool conf_parse(const uint8_t *in, size_t len, fp_conf_t *c) {
    if (len != FP_CONF_BYTES || in[0] != FP_CONF_VERSION) {
        return false;
    }
    c->flags = in[1];
    c->fail_count = in[2];
    memcpy(c->password, in + 4, 4);
    c->address = ((uint32_t)in[8] << 24) | ((uint32_t)in[9] << 16) | ((uint32_t)in[10] << 8) | in[11];
    c->capacity = (uint16_t)((in[12] << 8) | in[13]);
    memcpy(c->slots, in + 14, FP_CONF_BITMAP);
    return true;
}

/* Weak fallback so standalone host unit tests link without button.c / file_search_by_fid. */
__attribute__((weak)) volatile bool cancel_button = false;
__attribute__((weak)) file_t *file_search_by_fid(const uint16_t fid, const file_t *parent, const uint8_t sp) {
    (void)fid;
    (void)parent;
    (void)sp;
    return NULL;
}

__attribute__((weak)) bool fp_uart_rescue_factory_reset(uint32_t hint_addr) {
    return fp_uart_scan_pins(hint_addr);
}

static bool esp_dev_efuse_session(fp_session_t *out) {
#if defined(ESP_PLATFORM)
    if (flash_encryption_active()) {
        return false;
    }
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
#else
    (void)out;
    return false;
#endif
}

static bool esp_dev_shared_session(fp_session_t *out) {
#if defined(ESP_PLATFORM)
    if (flash_encryption_active()) {
        return false;
    }
    out->address = 0x5049434Fu; /* "PICO" */
    out->password[0] = 0x52;    /* 'R' */
    out->password[1] = 0x35;    /* '5' */
    out->password[2] = 0x35;    /* '5' */
    out->password[3] = 0x38;    /* '8' */
    return true;
#else
    (void)out;
    return false;
#endif
}

static bool is_dev_npwd_conf(const fp_conf_t *c) {
#if defined(ESP_PLATFORM)
    if (!flash_encryption_active() && c != NULL) {
        return c->password[0] == 'N' && c->password[1] == 'P' &&
               c->password[2] == 'W' && c->password[3] == 'D';
    }
#endif
    (void)c;
    return false;
}

typedef struct {
    uint32_t addr;
    uint16_t capacity;
    bool pwd_unlocked;
    bool bio_unlocked;
    bool auto_only;
    uint8_t c35;
    uint8_t c3b;
    uint8_t c12;
    uint8_t c0f;
    uint8_t c3c;
    uint8_t c01;
    uint8_t c0d;
    uint8_t c32;
} esp_dev_xray_t;

static void fp_sleep_ms(uint32_t ms);

static bool esp_dev_xray_probe(uint32_t seen_addr, esp_dev_xray_t *xr) {
#if defined(ESP_PLATFORM)
    if (flash_encryption_active() || xr == NULL) {
        return false;
    }
    memset(xr, 0xFF, sizeof(*xr));
    xr->addr = seen_addr;
    xr->capacity = 100;
    xr->pwd_unlocked = false;
    xr->bio_unlocked = false;
    xr->auto_only = false;

    const fp_transport_t *t = fp_uart_transport();
    fp_sensor_set_accept_any_ack_addr(true);

    char pin_prefix[48] = "";
    const char *raw_pins = fp_uart_active_pins();
    if (raw_pins != NULL && raw_pins[0] != '\0') {
        const char *bar = strchr(raw_pins, '|');
        size_t n = bar != NULL ? (size_t)(bar - raw_pins) : strlen(raw_pins);
        while (n > 0 && raw_pins[n - 1] == ' ') {
            n--;
        }
        if (n >= sizeof(pin_prefix)) {
            n = sizeof(pin_prefix) - 1;
        }
        memcpy(pin_prefix, raw_pins, n);
        pin_prefix[n] = '\0';
    }
    if (pin_prefix[0] == '\0') {
        snprintf(pin_prefix, sizeof(pin_prefix), "TX=GPIO1, RX=GPIO2");
    }

    /* 1. Cold HandShake (0x35) */
    (void)fp_sensor_txn(t, seen_addr, FP_INS_HANDSHAKE, NULL, 0, NULL, 0, NULL, &xr->c35, 35, true);
    if (fp_sensor_has_last_ack()) {
        seen_addr = fp_sensor_last_ack_addr();
        xr->addr = seen_addr;
    }

    /* 2. Cold RestSetting (0x3B) — both 0-byte and 1-byte variants + flash settle */
    if (fp_sensor_rest_setting(t, seen_addr, &xr->c3b) == FP_SENSOR_OK && xr->c3b == FP_CONF_OK) {
        fp_sleep_ms(120);
        seen_addr = FP_FACTORY_ADDRESS;
    }
    else {
        const uint8_t zero_b = 0x00;
        uint8_t alt_3b = 0xFF;
        if (fp_sensor_txn(t, seen_addr, FP_INS_REST_SETTING, &zero_b, 1, NULL, 0, NULL, &alt_3b, 60, true) == FP_SENSOR_OK &&
            alt_3b == FP_CONF_OK) {
            xr->c3b = alt_3b;
            fp_sleep_ms(120);
            seen_addr = FP_FACTORY_ADDRESS;
        }
    }

    /* 3. Cold SetPwd (0x12, {0,0,0,0}) */
    const uint8_t zero_pwd[4] = { 0, 0, 0, 0 };
    if (fp_sensor_set_password(t, seen_addr, zero_pwd, &xr->c12) == FP_SENSOR_OK && xr->c12 == FP_CONF_OK) {
        xr->pwd_unlocked = true;
    }

    /* 4. Check common / default / board-derived passwords */
    const uint8_t cand_pwds[][4] = {
        { 0x00, 0x00, 0x00, 0x00 },
        { 0xFF, 0xFF, 0xFF, 0xFF },
        { 0x52, 0x35, 0x35, 0x38 }, /* "R558" */
        { 0x12, 0x34, 0x56, 0x78 },
        { 0x00, 0x00, 0x00, 0x01 },
        { 0x01, 0x02, 0x03, 0x04 },
    };
    for (size_t i = 0; i < sizeof(cand_pwds) / sizeof(cand_pwds[0]); i++) {
        fp_session_t cs = { .address = seen_addr };
        memcpy(cs.password, cand_pwds[i], 4);
        uint8_t vc = 0xFF;
        if (fp_sensor_verify_password(t, &cs, &vc) == FP_SENSOR_OK && vc == FP_CONF_OK) {
            (void)fp_sensor_set_password(t, seen_addr, zero_pwd, &vc);
            (void)fp_sensor_set_chip_address(t, seen_addr, FP_FACTORY_ADDRESS, &vc);
            if (fp_sensor_has_last_ack()) {
                seen_addr = fp_sensor_last_ack_addr();
            }
            xr->addr = seen_addr;
            xr->pwd_unlocked = true;
            break;
        }
    }
    if (!xr->pwd_unlocked) {
        fp_session_t ef_s;
        if (esp_dev_efuse_session(&ef_s)) {
            ef_s.address = seen_addr;
            uint8_t vc = 0xFF;
            if (fp_sensor_verify_password(t, &ef_s, &vc) == FP_SENSOR_OK && vc == FP_CONF_OK) {
                (void)fp_sensor_set_password(t, seen_addr, zero_pwd, &vc);
                (void)fp_sensor_set_chip_address(t, seen_addr, FP_FACTORY_ADDRESS, &vc);
                xr->pwd_unlocked = true;
            }
        }
    }

    /* 5. Continuous SOLID BLUE ring (func=ON, cycles=0 so user sees LED stay lit!) */
    (void)fp_sensor_control_led(t, seen_addr, FP_LED_FUNC_ON, FP_LED_COLOR_BLUE, FP_LED_COLOR_BLUE, 0, &xr->c3c);

    /* 6. ReadSysPara (0x0F) */
    fp_sysparam_t sp;
    if (fp_sensor_read_sysparam(t, seen_addr, &sp, &xr->c0f) == FP_SENSOR_OK && xr->c0f == FP_CONF_OK) {
        if (sp.capacity > 0 && sp.capacity <= FP_TEMPLATE_MAX) {
            xr->capacity = sp.capacity;
        }
    }

    /* 7. Biometric sensor test WITHOUT VfyPwd: GenImg (0x01) + Empty (0x0D) + AutoIdentify (0x32) */
    fp_session_t npwd_s = { .address = seen_addr, .password = { 'N', 'P', 'W', 'D' } };
    (void)fp_sensor_gen_img(t, &npwd_s, &xr->c01);
    (void)fp_sensor_empty(t, &npwd_s, &xr->c0d);

    const uint8_t ai_params[5] = { 0x01, 0xFF, 0xFF, 0x00, 0x06 };
    uint8_t ai_buf[8] = { 0 };
    uint16_t ai_len = 0;
    fp_sensor_status_t ai_st = fp_sensor_txn(t, seen_addr, FP_INS_AUTO_ID,
                                             ai_params, sizeof(ai_params),
                                             ai_buf, sizeof(ai_buf), &ai_len, &xr->c32, 90, true);
    if (ai_st == FP_SENSOR_TIMEOUT) {
        /* Timeout waiting for finger means R558-S ACCEPTED AutoIdentify (did NOT immediately reject with 0x13)! */
        xr->c32 = 0xAA;
        uint8_t cc = 0xFF;
        (void)fp_sensor_cancel(t, &npwd_s, &cc);
        (void)fp_sensor_txn(t, seen_addr, 0x33, NULL, 0, NULL, 0, NULL, &cc, 25, true);
    }

    bool genimg_works = (xr->c01 == FP_CONF_OK || xr->c01 == FP_CONF_NO_FINGER || xr->c01 == FP_CONF_IMG_MESSY);
    bool auto_works = (xr->c32 == 0xAA || xr->c32 == FP_CONF_OK || xr->c32 == FP_CONF_NOT_FOUND ||
                       xr->c32 == 0x24 || xr->c32 == 0x26);
    if (genimg_works || auto_works) {
        xr->bio_unlocked = true;
        xr->auto_only = (!genimg_works && auto_works);
        (void)fp_sensor_control_led(t, seen_addr, FP_LED_FUNC_ON, FP_LED_COLOR_BLUE, FP_LED_COLOR_BLUE, 0, NULL);
    }

    char diag[160];
    snprintf(diag, sizeof(diag),
             "%s | A=0x%08" PRIX32 " 35=%02X 3B=%02X 12=%02X 0F=%02X 3C=%02X 01=%02X 0D=%02X 32=%02X",
             pin_prefix, seen_addr, xr->c35, xr->c3b, xr->c12, xr->c0f, xr->c3c, xr->c01, xr->c0d, xr->c32);
    fp_uart_set_diag(diag);
    return true;
#else
    (void)seen_addr;
    (void)xr;
    return false;
#endif
}

static volatile bool waiting_finger = false;

static void ensure_fp_conf_file(void) {
    if (ef_fp_conf == NULL) {
        ef_fp_conf = file_search_by_fid(EF_FP_CONF, NULL, SPECIFY_EF);
    }
}

static void sensor_led(uint32_t addr, uint8_t func, uint8_t start_color, uint8_t end_color, uint8_t cycles) {
    const fp_transport_t *t = fp_uart_transport();
    if (t == NULL) {
        return;
    }
    (void)fp_sensor_control_led(t, addr, func, start_color, end_color, cycles, NULL);
}

/* Loads the configuration from flash. Missing or invalid data means "not paired". */
static void conf_load(fp_conf_t *c) {
    conf_clear(c);
    ensure_fp_conf_file();
    if (ef_fp_conf == NULL || !file_has_data(ef_fp_conf)) {
        return;
    }
    if (!conf_parse(file_get_data(ef_fp_conf), file_get_size(ef_fp_conf), c)) {
        conf_clear(c);
    }
}

static bool conf_save(const fp_conf_t *c) {
    uint8_t buf[FP_CONF_BYTES];
    ensure_fp_conf_file();
    if (ef_fp_conf == NULL) {
        return false;
    }
    conf_serialize(c, buf);
    bool ok = file_put_data(ef_fp_conf, CONST_BYTE_ARRAY(buf, sizeof(buf))) == PICOKEYS_OK;
    mbedtls_platform_zeroize(buf, sizeof(buf));
    if (!ok) {
        return false;
    }
    /* Security relevant state must reach flash before the answer is sent. */
    return flash_commit_sync(5000);
}

static bool slot_used(const fp_conf_t *c, uint16_t slot) {
    return slot < c->capacity && slot < FP_TEMPLATE_MAX && (c->slots[slot / 8] & (1u << (slot % 8))) != 0;
}

static void slot_set(fp_conf_t *c, uint16_t slot, bool used) {
    if (used) {
        c->slots[slot / 8] |= (uint8_t)(1u << (slot % 8));
    }
    else {
        c->slots[slot / 8] &= (uint8_t)~(1u << (slot % 8));
    }
}

static uint16_t enrolled_count(const fp_conf_t *c) {
    uint16_t n = 0;
    for (uint16_t i = 0; i < c->capacity && i < FP_TEMPLATE_MAX; i++) {
        if (slot_used(c, i)) {
            n++;
        }
    }
    return n;
}

static fp_session_t session_of(const fp_conf_t *c) {
    fp_session_t s;
    s.address = c->address;
    memcpy(s.password, c->password, 4);
    return s;
}

static void fp_sleep_ms(uint32_t ms) {
#if defined(ESP_PLATFORM)
    sleep_ms(ms);
#else
    uint32_t start = board_millis();
    while (board_millis() - start < ms) {
    }
#endif
}

/* Failure accounting. A tamper signal locks immediately. */
static void register_failure(fp_conf_t *c, bool tamper) {
    if (tamper) {
        c->flags |= FP_FLAG_LOCKED;
        c->fail_count = FP_MAX_FAILED_ATTEMPTS;
    }
    else {
        if (c->fail_count < 255) {
            c->fail_count++;
        }
        if (c->fail_count >= FP_MAX_FAILED_ATTEMPTS) {
            c->flags |= FP_FLAG_LOCKED;
        }
    }
    conf_save(c);
}

static void register_success(fp_conf_t *c) {
    if (c->fail_count != 0) {
        c->fail_count = 0;
        conf_save(c);
    }
}

static bool last_sensor_detected = false;
static bool sensor_probed_once = false;
static bool use_auto_mode = false;
static uint8_t last_err_ins = 0;
static uint8_t last_err_conf = 0;
static uint8_t last_err_transport = 0;

static void fp_diag_reset(void) {
    last_err_ins = 0;
    last_err_conf = 0;
    last_err_transport = 0;
}

static void fp_diag_err(uint8_t ins, uint8_t conf, fp_sensor_status_t transport) {
    last_err_ins = ins;
    last_err_conf = conf;
    last_err_transport = (uint8_t)transport;
}

static void probe_and_init_sensor(const fp_conf_t *c) {
    sensor_probed_once = true;
    uint32_t hint_addr = (c->flags & (FP_FLAG_PAIRED | FP_FLAG_STAGED)) ? c->address : 0;
    fp_uart_scan_pins(hint_addr);

    const fp_transport_t *t = fp_uart_transport();
    uint8_t code = 0xFF;

    if (c->flags & FP_FLAG_PAIRED) {
        if (is_dev_npwd_conf(c)) {
            fp_sensor_set_accept_any_ack_addr(true);
            fp_session_t s = session_of(c);
            fp_sensor_status_t st = fp_sensor_gen_img(t, &s, &code);
            if (st == FP_SENSOR_OK && code != FP_CONF_WRONG_PWD) {
                last_sensor_detected = true;
                fp_diag_reset();
                sensor_led(c->address, FP_LED_FUNC_ON,
                           (c->flags & FP_FLAG_LOCKED) ? FP_LED_COLOR_RED : FP_LED_COLOR_GREEN,
                           (c->flags & FP_FLAG_LOCKED) ? FP_LED_COLOR_RED : FP_LED_COLOR_GREEN, 0);
                return;
            }
        }
        fp_session_t s = session_of(c);
        fp_sensor_status_t st = fp_sensor_verify_password(t, &s, &code);
        if (st == FP_SENSOR_OK) {
            last_sensor_detected = true;
            if (code == FP_CONF_OK) {
                fp_diag_reset();
                if (c->flags & FP_FLAG_LOCKED) {
                    sensor_led(c->address, FP_LED_FUNC_ON, FP_LED_COLOR_RED, FP_LED_COLOR_RED, 0);
                }
                else {
                    sensor_led(c->address, FP_LED_FUNC_ON, FP_LED_COLOR_CYAN, FP_LED_COLOR_CYAN, 0);
                }
            }
            else {
                fp_diag_err(FP_INS_VFY_PWD, code, st);
            }
            return;
        }
    }

    /*
     * On ESP32 dev mode BEFORE any wrong VfyPwd: if the R558-S responded with its own stored ChipAddr,
     * execute cold HandShake + RestSetting + SetPwd + solid-blue LED + passwordless DSP X-ray immediately!
     */
    fp_session_t dev_sh;
    if (esp_dev_shared_session(&dev_sh) && fp_sensor_has_last_ack()) {
        esp_dev_xray_t xr;
        if (esp_dev_xray_probe(fp_sensor_last_ack_addr(), &xr)) {
            last_sensor_detected = true;
            if (xr.pwd_unlocked || xr.bio_unlocked) {
                use_auto_mode = xr.auto_only;
                fp_diag_reset();
                sensor_led(xr.addr, FP_LED_FUNC_ON, FP_LED_COLOR_BLUE, FP_LED_COLOR_BLUE, 0);
            }
            else {
                fp_diag_err(FP_INS_VFY_PWD, xr.c01 != 0xFF ? xr.c01 : FP_CONF_WRONG_PWD, FP_SENSOR_OK);
            }
            return;
        }
    }

    fp_session_t factory = { .address = FP_FACTORY_ADDRESS, .password = { 0, 0, 0, 0 } };
    fp_sensor_status_t fst = fp_sensor_verify_password(t, &factory, &code);
    if (fst == FP_SENSOR_OK) {
        last_sensor_detected = true;
        if (code == FP_CONF_OK) {
            fp_diag_reset();
            if (!(c->flags & FP_FLAG_PAIRED)) {
                sensor_led(FP_FACTORY_ADDRESS, FP_LED_FUNC_FLASH, FP_LED_COLOR_BLUE, FP_LED_COLOR_BLUE, 2);
#if defined(ESP_PLATFORM)
                sensor_led(FP_FACTORY_ADDRESS, FP_LED_FUNC_ON, FP_LED_COLOR_BLUE, FP_LED_COLOR_BLUE, 0);
#endif
            }
        }
        else {
            fp_diag_err(FP_INS_VFY_PWD, code, FP_SENSOR_OK);
        }
        return;
    }

    if (esp_dev_shared_session(&dev_sh)) {
        fp_sensor_status_t dst = fp_sensor_verify_password(t, &dev_sh, &code);
        if (dst == FP_SENSOR_OK) {
            last_sensor_detected = true;
            if (code == FP_CONF_OK) {
                fp_diag_reset();
                sensor_led(dev_sh.address, FP_LED_FUNC_ON, FP_LED_COLOR_BLUE, FP_LED_COLOR_BLUE, 0);
            }
            else {
                fp_diag_err(FP_INS_VFY_PWD, code, FP_SENSOR_OK);
            }
            return;
        }
    }

    fp_session_t ef;
    if (esp_dev_efuse_session(&ef)) {
        fp_sensor_status_t est = fp_sensor_verify_password(t, &ef, &code);
        if (est == FP_SENSOR_OK) {
            last_sensor_detected = true;
            if (code == FP_CONF_OK) {
                fp_diag_reset();
                sensor_led(ef.address, FP_LED_FUNC_ON, FP_LED_COLOR_BLUE, FP_LED_COLOR_BLUE, 0);
            }
            else {
                fp_diag_err(FP_INS_VFY_PWD, code, FP_SENSOR_OK);
            }
            return;
        }
    }

    last_sensor_detected = false;
    fp_diag_err(FP_INS_VFY_PWD, fp_sensor_has_last_ack() ? fp_sensor_last_ack_conf() : 0xFF, fst);
}

/* Checks the stored password at the stored address. Returns FP_OK, or FP_ERR_SENSOR_AUTH on a wrong password. */
static fp_result_t authenticate_sensor(const fp_conf_t *c) {
    fp_session_t s = session_of(c);
    uint8_t code = 0xFF;
    if (is_dev_npwd_conf(c)) {
        fp_sensor_set_accept_any_ack_addr(true);
        fp_sensor_status_t st = fp_sensor_gen_img(fp_uart_transport(), &s, &code);
        if (st != FP_SENSOR_OK) {
            fp_uart_scan_pins(c->address);
            st = fp_sensor_gen_img(fp_uart_transport(), &s, &code);
        }
        if (st != FP_SENSOR_OK) {
            st = fp_sensor_txn(fp_uart_transport(), s.address, FP_INS_HANDSHAKE,
                               NULL, 0, NULL, 0, NULL, &code, 40, true);
        }
        if (st != FP_SENSOR_OK) {
            last_sensor_detected = false;
            fp_diag_err(FP_INS_GEN_IMG, 0xFF, st);
            return FP_ERR_SENSOR;
        }
        last_sensor_detected = true;
        if (code != FP_CONF_WRONG_PWD) {
            return FP_OK;
        }
        fp_diag_err(FP_INS_GEN_IMG, code, FP_SENSOR_OK);
        return FP_ERR_SENSOR_AUTH;
    }
    fp_sensor_status_t st = fp_sensor_verify_password(fp_uart_transport(), &s, &code);
    if (st != FP_SENSOR_OK) {
        fp_uart_scan_pins(c->address);
        st = fp_sensor_verify_password(fp_uart_transport(), &s, &code);
    }
    if (st != FP_SENSOR_OK) {
        last_sensor_detected = false;
        fp_diag_err(FP_INS_VFY_PWD, 0xFF, st);
        return FP_ERR_SENSOR;
    }
    last_sensor_detected = true;
    if (code == FP_CONF_OK) {
        return FP_OK;
    }
    fp_diag_err(FP_INS_VFY_PWD, code, FP_SENSOR_OK);
    if (code == FP_CONF_WRONG_PWD) {
        return FP_ERR_SENSOR_AUTH;
    }
    return FP_ERR_SENSOR;
}

static bool is_retryable_capture_code(uint8_t code) {
    switch (code) {
        case FP_CONF_NO_FINGER:
        case FP_CONF_CAPTURE_FAIL:
        case FP_CONF_IMG_DRY:
        case FP_CONF_IMG_WET:
        case FP_CONF_IMG_MESSY:
        case FP_CONF_IMG_FEW_POINTS:
        case FP_CONF_NO_MATCH:
        case FP_CONF_COMBINE_FAIL:
        case FP_CONF_NO_IMAGE_BUF:
        case FP_CONF_RESIDUAL:
        case FP_CONF_AREA_OVERLAP:
        case FP_CONF_SMALL_AREA:
        case FP_CONF_FOREIGN_IMG:
        case FP_CONF_ILLEGAL_DATA:
        case FP_CONF_REVERSE_MOULD:
        case FP_CONF_FOREIGN_STATIC:
        case FP_CONF_FOREIGN_DYN:
        case FP_CONF_POOR_TEMPLATE:
            return true;
        default:
            return false;
    }
}

/* Waits until the sensor reports a clean finger image and extracts features into buffer. */
static fp_result_t capture_to_buffer(const fp_session_t *s, uint8_t buffer, uint32_t timeout_ms) {
    uint32_t deadline = board_millis() + timeout_ms;
    const fp_transport_t *t = fp_uart_transport();
    waiting_finger = true;
    bool saw_mismatch = false;
    uint8_t last_mismatch_code = 0;
    fp_result_t result = FP_ERR_SENSOR;
    for (;;) {
        if (cancel_button) {
            result = FP_ERR_CANCELLED;
            break;
        }
        if (board_millis() >= deadline) {
            if (saw_mismatch) {
                fp_diag_err(FP_INS_IMG_2_TZ, last_mismatch_code, FP_SENSOR_OK);
                result = FP_ERR_NO_MATCH;
            }
            else {
                result = FP_ERR_TIMEOUT;
            }
            break;
        }
        uint8_t code = 0xFF;
        fp_sensor_status_t st = fp_sensor_gen_img(t, s, &code);
        if (st != FP_SENSOR_OK) {
            fp_diag_err(FP_INS_GEN_IMG, code, st);
            result = FP_ERR_SENSOR;
            break;
        }
        if (code != FP_CONF_OK) {
            if (is_retryable_capture_code(code)) {
                fp_sleep_ms(50);
                continue;
            }
            fp_diag_err(FP_INS_GEN_IMG, code, FP_SENSOR_OK);
            result = FP_ERR_SENSOR;
            break;
        }
#if defined(ESP_PLATFORM)
        /* Allow capacitive pad contact to settle flat across the 8x8 mm array before extracting features. */
        fp_sleep_ms(70);
        uint8_t settled_code = 0xFF;
        if (fp_sensor_gen_img(t, s, &settled_code) == FP_SENSOR_OK && settled_code != FP_CONF_OK) {
            fp_sleep_ms(40);
            continue;
        }
#endif
        st = fp_sensor_img_2_tz(t, s, buffer, &code);
        if (st != FP_SENSOR_OK) {
            fp_diag_err(FP_INS_IMG_2_TZ, code, st);
            result = FP_ERR_SENSOR;
            break;
        }
        if (code == FP_CONF_OK) {
            result = FP_OK;
            break;
        }
        if (code == FP_CONF_NO_MATCH || code == FP_CONF_COMBINE_FAIL || code == FP_CONF_POOR_TEMPLATE) {
            saw_mismatch = true;
            last_mismatch_code = code;
        }
        if (is_retryable_capture_code(code)) {
            /* Partial capacitive touch or angle/overlap feedback (R558-S Manual p. 13, 33): retry frame. */
            fp_sleep_ms(60);
            continue;
        }
        fp_diag_err(FP_INS_IMG_2_TZ, code, FP_SENSOR_OK);
        result = FP_ERR_SENSOR;
        break;
    }
    waiting_finger = false;
    return result;
}

/* Waits until no finger is on the sensor. */
static fp_result_t wait_finger_removed(const fp_session_t *s, uint32_t timeout_ms) {
    uint32_t deadline = board_millis() + timeout_ms;
    const fp_transport_t *t = fp_uart_transport();
    waiting_finger = true;
    fp_result_t result = FP_ERR_SENSOR;
    for (;;) {
        if (cancel_button) {
            result = FP_ERR_CANCELLED;
            break;
        }
        if (board_millis() >= deadline) {
            result = FP_ERR_TIMEOUT;
            break;
        }
        uint8_t code = 0xFF;
        fp_sensor_status_t st = fp_sensor_gen_img(t, s, &code);
        if (st != FP_SENSOR_OK) {
            fp_diag_err(FP_INS_GEN_IMG, code, st);
            result = FP_ERR_SENSOR;
            break;
        }
        if (code == FP_CONF_NO_FINGER) {
            result = FP_OK;
            break;
        }
        fp_sleep_ms(100);
    }
    waiting_finger = false;
    return result;
}

/*
 * Native R558-S PS_AutoEnroll (0x31) state machine (GROW R558-S V1.1 Manual p. 31-34).
 * Used automatically when a module blocks manual RegModel/Store via EncryptionLevel (0x31) or similar.
 */
static fp_result_t fp_enroll_auto(const fp_session_t *s, uint16_t slot, uint8_t entries) {
    const fp_transport_t *t = fp_uart_transport();
    uint8_t tmp = 0xFF;
    (void)fp_sensor_delete_chars(t, s, slot, 1, &tmp);
    sensor_led(s->address, FP_LED_FUNC_BREATHE, FP_LED_COLOR_BLUE, FP_LED_COLOR_PURPLE, 0);

    const uint8_t params[5] = {
        (uint8_t)(slot >> 8),
        (uint8_t)(slot & 0xFF),
        entries,
        0x00,
        0x08 /* bit2=0 (step status ACKs enabled), bit3=1 (allow slot overwrite), bit4=0, bit5=0 (lift finger between scans) */
    };
    fp_sensor_status_t st = fp_sensor_send_cmd(t, s->address, FP_INS_AUTO_ENROLL, params, sizeof(params));
    if (st != FP_SENSOR_OK) {
        fp_diag_err(FP_INS_AUTO_ENROLL, 0xFF, st);
        return FP_ERR_SENSOR;
    }

    uint32_t deadline = board_millis() + (FP_ENROLL_STEP_TIMEOUT_MS * 2u);
    waiting_finger = true;
    fp_result_t res = FP_ERR_SENSOR;

    for (;;) {
        if (cancel_button) {
            (void)fp_sensor_cancel(t, s, &tmp);
            res = FP_ERR_CANCELLED;
            break;
        }
        if (board_millis() >= deadline) {
            (void)fp_sensor_cancel(t, s, &tmp);
            res = FP_ERR_TIMEOUT;
            break;
        }
        uint8_t ack[8] = { 0 };
        uint16_t ack_len = 0;
        uint8_t conf = 0xFF;
        st = fp_sensor_recv_ack(t, s->address, ack, sizeof(ack), &ack_len, &conf, 400, true);
        if (st == FP_SENSOR_TIMEOUT) {
            continue;
        }
        if (st != FP_SENSOR_OK) {
            fp_diag_err(FP_INS_AUTO_ENROLL, conf, st);
            (void)fp_sensor_cancel(t, s, &tmp);
            res = FP_ERR_SENSOR;
            break;
        }
        uint8_t step = ack_len >= 2 ? ack[1] : 0xFF;
        if (conf == FP_CONF_OK) {
            if (step == 0x06) {
                /* Step 0x06 (00 06 F2): template stored in sensor flash. */
                res = FP_OK;
                break;
            }
            /* Steps 0x00..0x05 succeeded: continue reading next progress ACK. */
            continue;
        }
        if ((step == 0x01 || step == 0x02 || step == 0x03) && is_retryable_capture_code(conf)) {
            /* Module stays inside AutoEnroll waiting for cleaner touch / lift. */
            continue;
        }
        if (conf == FP_CONF_MOD_TIMEOUT) {
            res = FP_ERR_TIMEOUT;
            break;
        }
        if (conf == FP_CONF_COMBINE_FAIL || conf == FP_CONF_POOR_TEMPLATE || conf == FP_CONF_NO_MATCH) {
            fp_diag_err(FP_INS_AUTO_ENROLL, conf, FP_SENSOR_OK);
            res = FP_ERR_NO_MATCH;
            break;
        }
        if (conf == FP_CONF_LIB_FULL) {
            fp_diag_err(FP_INS_AUTO_ENROLL, conf, FP_SENSOR_OK);
            res = FP_ERR_FULL;
            break;
        }
        fp_diag_err(FP_INS_AUTO_ENROLL, conf, FP_SENSOR_OK);
        (void)fp_sensor_cancel(t, s, &tmp);
        res = FP_ERR_SENSOR;
        break;
    }

    waiting_finger = false;
    return res;
}

/*
 * Native R558-S PS_AutoIdentify (0x32) 1:N verification (GROW R558-S V1.1 Manual p. 34-35).
 */
static fp_result_t fp_verify_auto(const fp_session_t *s, uint32_t timeout_ms, uint16_t *page_out) {
    const fp_transport_t *t = fp_uart_transport();
    uint8_t tmp = 0xFF;
    const uint8_t params[5] = {
        3,          /* security level 3 */
        0xFF, 0xFF, /* 0xFFFF = 1:N search across database */
        0x00, 0x00  /* bit2=0 = emit step status ACKs */
    };
    fp_sensor_status_t st = fp_sensor_send_cmd(t, s->address, FP_INS_AUTO_ID, params, sizeof(params));
    if (st != FP_SENSOR_OK) {
        fp_diag_err(FP_INS_AUTO_ID, 0xFF, st);
        return FP_ERR_SENSOR;
    }

    uint32_t deadline = board_millis() + timeout_ms;
    waiting_finger = true;
    fp_result_t res = FP_ERR_SENSOR;

    for (;;) {
        if (cancel_button) {
            (void)fp_sensor_cancel(t, s, &tmp);
            res = FP_ERR_CANCELLED;
            break;
        }
        if (board_millis() >= deadline) {
            (void)fp_sensor_cancel(t, s, &tmp);
            res = FP_ERR_TIMEOUT;
            break;
        }
        uint8_t ack[10] = { 0 };
        uint16_t ack_len = 0;
        uint8_t conf = 0xFF;
        st = fp_sensor_recv_ack(t, s->address, ack, sizeof(ack), &ack_len, &conf, 400, true);
        if (st == FP_SENSOR_TIMEOUT) {
            continue;
        }
        if (st != FP_SENSOR_OK) {
            fp_diag_err(FP_INS_AUTO_ID, conf, st);
            (void)fp_sensor_cancel(t, s, &tmp);
            res = FP_ERR_SENSOR;
            break;
        }
        uint8_t step = ack_len >= 2 ? ack[1] : 0xFF;
        if (conf == FP_CONF_OK) {
            if (step == 0x05 && ack_len >= 4) {
                *page_out = (uint16_t)((ack[2] << 8) | ack[3]);
                res = FP_OK;
                break;
            }
            continue;
        }
        if (step == 0x01 && is_retryable_capture_code(conf)) {
            continue;
        }
        if (conf == FP_CONF_MOD_TIMEOUT) {
            res = FP_ERR_TIMEOUT;
            break;
        }
        if (conf == FP_CONF_NOT_FOUND || conf == FP_CONF_NO_MATCH ||
            conf == FP_CONF_SLOT_EMPTY || conf == FP_CONF_LIB_EMPTY) {
            fp_diag_err(FP_INS_AUTO_ID, conf, FP_SENSOR_OK);
            res = FP_ERR_NO_MATCH;
            break;
        }
        fp_diag_err(FP_INS_AUTO_ID, conf, FP_SENSOR_OK);
        (void)fp_sensor_cancel(t, s, &tmp);
        res = FP_ERR_SENSOR;
        break;
    }

    waiting_finger = false;
    return res;
}

/* ------------------------------------------------------------------------- */
/* Public API                                                                */
/* ------------------------------------------------------------------------- */

int fp_result_to_ctap(fp_result_t res) {
    switch (res) {
        case FP_OK:
            return 0;
        case FP_ERR_NOT_PAIRED:
            return CTAP2_ERR_NOT_ALLOWED;
        case FP_ERR_LOCKED:
        case FP_ERR_SENSOR_AUTH:
            return CTAP2_ERR_UV_BLOCKED;
        case FP_ERR_NO_TEMPLATE:
            return CTAP2_ERR_INVALID_OPTION;
        case FP_ERR_CANCELLED:
            return CTAP2_ERR_KEEPALIVE_CANCEL;
        case FP_ERR_TIMEOUT:
            return CTAP2_ERR_USER_ACTION_TIMEOUT;
        case FP_ERR_NO_MATCH:
            return CTAP2_ERR_UV_INVALID;
        case FP_ERR_FULL:
            return CTAP2_ERR_KEY_STORE_FULL;
        case FP_ERR_ALREADY_PAIRED:
        case FP_ERR_NOT_FACTORY:
            return CTAP2_ERR_NOT_ALLOWED;
        case FP_ERR_BAD_PARAM:
        case FP_ERR_BACKUP_FORMAT:
            return CTAP1_ERR_INVALID_PARAMETER;
        case FP_ERR_NOT_SECURE:
        case FP_ERR_BACKUP_MISMATCH:
            return CTAP2_ERR_NOT_ALLOWED;
        case FP_ERR_SENSOR:
        case FP_ERR_STORAGE:
        default:
            return CTAP2_ERR_PROCESSING;
    }
}

int fp_uv_ctap_status(void) {
    return fp_result_to_ctap(fp_verify(FP_VERIFY_TIMEOUT_MS));
}

bool fp_is_waiting_finger(void) {
    return waiting_finger;
}

bool fp_get_wrap_secret(uint8_t secret8[8]) {
    if (!FP_FEATURE_ON || secret8 == NULL) {
        return false;
    }
    fp_conf_t c;
    conf_load(&c);
    if (!(c.flags & FP_FLAG_PAIRED)) {
        conf_clear(&c);
        return false;
    }
    memcpy(secret8, c.password, 4);
    secret8[4] = (uint8_t)(c.address >> 24);
    secret8[5] = (uint8_t)(c.address >> 16);
    secret8[6] = (uint8_t)(c.address >> 8);
    secret8[7] = (uint8_t)(c.address);
    conf_clear(&c);
    return true;
}

void fp_init(void) {
    waiting_finger = false;
    last_sensor_detected = false;
    use_auto_mode = false;
    fp_diag_reset();
    if (!FP_FEATURE_ON) {
        return;
    }
    if (fp_uart_init() != 0) {
        printf("R558: UART init failed, fingerprint UV unavailable\r\n");
        return;
    }
    fp_led_init();
    fp_conf_t c;
    conf_load(&c);
    probe_and_init_sensor(&c);
    printf("R558: paired=%d locked=%d enrolled=%u detected=%d pins=%s\r\n",
           (c.flags & FP_FLAG_PAIRED) != 0, (c.flags & FP_FLAG_LOCKED) != 0,
           enrolled_count(&c), last_sensor_detected, fp_uart_active_pins());
    conf_clear(&c);
}

bool fp_probe(void) {
    if (!FP_FEATURE_ON) {
        return false;
    }
    fp_conf_t c;
    conf_load(&c);
    probe_and_init_sensor(&c);
    conf_clear(&c);
    return last_sensor_detected;
}

fp_result_t fp_factory_reset_sensor(void) {
    if (!FP_FEATURE_ON) {
        return FP_ERR_NOT_PAIRED;
    }
    fp_conf_t c;
    conf_load(&c);
    if (c.flags & FP_FLAG_PAIRED) {
        if (!is_dev_npwd_conf(&c)) {
            fp_session_t s = session_of(&c);
            uint8_t code = 0xFF;
            if (fp_sensor_verify_password(fp_uart_transport(), &s, &code) == FP_SENSOR_OK && code == FP_CONF_OK) {
                conf_clear(&c);
                return FP_ERR_ALREADY_PAIRED;
            }
        }
    }
    uint32_t hint = (c.flags & (FP_FLAG_PAIRED | FP_FLAG_STAGED)) ? c.address : 0;
    if (c.flags & (FP_FLAG_PAIRED | FP_FLAG_STAGED)) {
        const uint8_t zero_pwd[4] = { 0, 0, 0, 0 };
        fp_session_t s = session_of(&c);
        uint8_t code = 0xFF;
        if (fp_uart_scan_pins(s.address) &&
            fp_sensor_verify_password(fp_uart_transport(), &s, &code) == FP_SENSOR_OK && code == FP_CONF_OK) {
            (void)fp_sensor_empty(fp_uart_transport(), &s, &code);
            (void)fp_sensor_set_password(fp_uart_transport(), s.address, zero_pwd, &code);
            (void)fp_sensor_set_chip_address(fp_uart_transport(), s.address, FP_FACTORY_ADDRESS, &code);
        }
        memset(&c, 0, sizeof(c));
        (void)conf_save(&c);
    }
    (void)fp_uart_rescue_factory_reset(hint);
    conf_clear(&c);
    conf_load(&c);
    probe_and_init_sensor(&c);
    conf_clear(&c);
    return last_sensor_detected ? FP_OK : FP_ERR_SENSOR;
}

bool fp_uv_available(void) {
    if (!FP_FEATURE_ON) {
        return false;
    }
    fp_conf_t c;
    conf_load(&c);
    bool ok = (c.flags & FP_FLAG_PAIRED) && !(c.flags & FP_FLAG_LOCKED) && enrolled_count(&c) > 0;
    conf_clear(&c);
    return ok;
}

void fp_get_status(fp_status_t *st) {
    memset(st, 0, sizeof(*st));
    st->supported = FP_FEATURE_ON;
    st->flash_encrypted = flash_encryption_active();
    if (!FP_FEATURE_ON) {
        return;
    }
    fp_conf_t c;
    conf_load(&c);
    if (!sensor_probed_once) {
        probe_and_init_sensor(&c);
    }
    st->paired = (c.flags & FP_FLAG_PAIRED) != 0;
    st->locked = (c.flags & FP_FLAG_LOCKED) != 0;
    st->capacity = c.capacity;
    st->enrolled = enrolled_count(&c);
    st->failed_attempts = c.fail_count;
    st->sensor_detected = last_sensor_detected;
    st->last_step = last_err_ins;
    st->last_conf = last_err_conf;
    st->last_transport = last_err_transport;
    const char *pins = fp_uart_active_pins();
    if (pins != NULL) {
        snprintf(st->sensor_pins, sizeof(st->sensor_pins), "%s", pins);
    }
    conf_clear(&c);
}

bool fp_is_slot_used(uint16_t slot) {
    if (!FP_FEATURE_ON) {
        return false;
    }
    fp_conf_t c;
    conf_load(&c);
    bool used = slot_used(&c, slot);
    conf_clear(&c);
    return used;
}

fp_result_t fp_verify(uint32_t timeout_ms) {
    if (!FP_FEATURE_ON) {
        return FP_ERR_NOT_PAIRED;
    }
    fp_diag_reset();
    fp_conf_t c;
    conf_load(&c);
    fp_result_t res = FP_OK;

    if (!(c.flags & FP_FLAG_PAIRED)) {
        res = FP_ERR_NOT_PAIRED;
    }
    else if (c.flags & FP_FLAG_LOCKED) {
        res = FP_ERR_LOCKED;
    }
    else if (enrolled_count(&c) == 0) {
        res = FP_ERR_NO_TEMPLATE;
    }
    else {
        /* Sensor must still hold our password and address. */
        res = authenticate_sensor(&c);
        if (res == FP_ERR_SENSOR_AUTH) {
            register_failure(&c, true);
        }
    }

    if (res == FP_OK) {
        fp_session_t s = session_of(&c);
        uint16_t page = 0;
        fp_led_op_begin();
        sensor_led(s.address, FP_LED_FUNC_BREATHE, FP_LED_COLOR_BLUE, FP_LED_COLOR_BLUE, 0);

        if (use_auto_mode) {
            res = fp_verify_auto(&s, timeout_ms, &page);
            if (res == FP_ERR_NO_MATCH) {
                register_failure(&c, false);
            }
            else if (res == FP_OK) {
                if (!slot_used(&c, page)) {
                    res = FP_ERR_SENSOR_AUTH;
                    register_failure(&c, true);
                }
                else {
                    register_success(&c);
                }
            }
        }
        else {
            res = capture_to_buffer(&s, FP_BUF_1, timeout_ms);
            if (res == FP_OK) {
                uint8_t code = 0xFF;
                uint16_t score = 0;
                fp_sensor_status_t st = fp_sensor_search(fp_uart_transport(), &s, FP_BUF_1, 0, c.capacity, &code, &page, &score);
                if (st != FP_SENSOR_OK) {
                    fp_diag_err(FP_INS_SEARCH, code, st);
                    res = FP_ERR_SENSOR;
                }
                else if (code == FP_CONF_ENC_MISMATCH) {
                    /* R558-S has EncryptionLevel > 0: switch transparently to PS_AutoIdentify (0x32). */
                    use_auto_mode = true;
                    fp_diag_reset();
                    res = fp_verify_auto(&s, timeout_ms, &page);
                    if (res == FP_ERR_NO_MATCH) {
                        register_failure(&c, false);
                    }
                    else if (res == FP_OK) {
                        if (!slot_used(&c, page)) {
                            res = FP_ERR_SENSOR_AUTH;
                            register_failure(&c, true);
                        }
                        else {
                            register_success(&c);
                        }
                    }
                }
                else if (code == FP_CONF_NOT_FOUND || code == FP_CONF_NO_MATCH ||
                         code == FP_CONF_SLOT_EMPTY || code == FP_CONF_LIB_EMPTY) {
                    fp_diag_err(FP_INS_SEARCH, code, FP_SENSOR_OK);
                    res = FP_ERR_NO_MATCH;
                    register_failure(&c, false);
                }
                else if (code != FP_CONF_OK) {
                    fp_diag_err(FP_INS_SEARCH, code, FP_SENSOR_OK);
                    res = FP_ERR_SENSOR;
                }
                else if (!slot_used(&c, page)) {
                    /* A template we did not enroll: the module content was changed. */
                    res = FP_ERR_SENSOR_AUTH;
                    register_failure(&c, true);
                }
                else {
                    register_success(&c);
                }
            }
        }
        fp_led_op_end(res == FP_OK);
        if (res == FP_OK) {
            fp_diag_reset();
            sensor_led(s.address, FP_LED_FUNC_FLASH, FP_LED_COLOR_GREEN, FP_LED_COLOR_GREEN, 2);
        }
        else if (c.flags & FP_FLAG_LOCKED) {
            sensor_led(s.address, FP_LED_FUNC_ON, FP_LED_COLOR_RED, FP_LED_COLOR_RED, 0);
        }
        else if (res == FP_ERR_NO_MATCH) {
            sensor_led(s.address, FP_LED_FUNC_FLASH, FP_LED_COLOR_RED, FP_LED_COLOR_RED, 2);
        }
        else {
            sensor_led(s.address, FP_LED_FUNC_OFF, FP_LED_COLOR_OFF, FP_LED_COLOR_OFF, 0);
        }
    }
    conf_clear(&c);
    return res;
}

fp_result_t fp_pair(uint16_t *capacity_out) {
    if (!flash_requirement_met()) {
        return FP_ERR_NOT_SECURE;
    }
    fp_diag_reset();
    fp_conf_t c;
    conf_load(&c);
    const fp_transport_t *t = fp_uart_transport();
    fp_result_t res = FP_OK;
    uint8_t code = 0xFF;

    fp_uart_scan_pins((c.flags & (FP_FLAG_PAIRED | FP_FLAG_STAGED)) ? c.address : 0);

    /* A sensor that is still trusted cannot be replaced. */
    if (c.flags & FP_FLAG_PAIRED) {
        if (is_dev_npwd_conf(&c) && authenticate_sensor(&c) == FP_OK) {
            conf_clear(&c);
            return FP_ERR_ALREADY_PAIRED;
        }
        fp_session_t s = session_of(&c);
        if (fp_sensor_verify_password(t, &s, &code) == FP_SENSOR_OK && code == FP_CONF_OK) {
            last_sensor_detected = true;
            conf_clear(&c);
            return FP_ERR_ALREADY_PAIRED;
        }
    }

    /*
     * Interrupted pairing. The staged secrets were written to flash before the sensor was touched, so the
     * sensor can be recognised by them: either fully configured (resume at the final checks) or with the
     * password set but the address still at the factory value (continue with SetChipAddr).
     */
    bool resumed = false;
    bool password_set_already = false;
    if (c.flags & FP_FLAG_STAGED) {
        fp_session_t s = session_of(&c);
        if (fp_sensor_verify_password(t, &s, &code) == FP_SENSOR_OK && code == FP_CONF_OK) {
            last_sensor_detected = true;
            resumed = true;
        }
        else {
            fp_session_t f = { .address = FP_FACTORY_ADDRESS };
            memcpy(f.password, c.password, 4);
            if (fp_sensor_verify_password(t, &f, &code) == FP_SENSOR_OK && code == FP_CONF_OK) {
                last_sensor_detected = true;
                password_set_already = true;
            }
        }
    }

    if (!resumed && !password_set_already) {
        /*
         * Check whether this R558-S module already holds universal dev-mode credentials ("PICO"/"R558")
         * or this physical ESP32-S3 board's eFuse MAC credentials from before a flash erase.
         */
        fp_session_t known[2];
        size_t known_n = 0;
        if (esp_dev_shared_session(&known[known_n])) {
            known_n++;
        }
        if (esp_dev_efuse_session(&known[known_n])) {
            known_n++;
        }
        for (size_t k = 0; k < known_n; k++) {
            if (fp_sensor_verify_password(t, &known[k], &code) == FP_SENSOR_OK && code == FP_CONF_OK) {
                fp_sysparam_t ef_sp;
                if (fp_sensor_read_sysparam(t, known[k].address, &ef_sp, &code) == FP_SENSOR_OK &&
                    code == FP_CONF_OK && ef_sp.capacity > 0) {
                    last_sensor_detected = true;
                    memset(&c, 0, sizeof(c));
                    c.flags = FP_FLAG_STAGED;
                    c.capacity = ef_sp.capacity > FP_TEMPLATE_MAX ? FP_TEMPLATE_MAX : ef_sp.capacity;
                    memcpy(c.password, known[k].password, 4);
                    c.address = known[k].address;
                    if (!conf_save(&c)) {
                        conf_clear(&c);
                        return FP_ERR_STORAGE;
                    }
                    resumed = true;
                    break;
                }
            }
        }
    }

    if (!resumed && !password_set_already) {
        fp_session_t dev_chk;
        if (esp_dev_shared_session(&dev_chk) && fp_sensor_has_last_ack()) {
            esp_dev_xray_t xr;
            if (esp_dev_xray_probe(fp_sensor_last_ack_addr(), &xr)) {
                last_sensor_detected = true;
                if (xr.pwd_unlocked || xr.bio_unlocked) {
                    use_auto_mode = xr.auto_only;
                    memset(&c, 0, sizeof(c));
                    c.flags = FP_FLAG_PAIRED;
                    c.fail_count = 0;
                    c.capacity = xr.capacity > 0 && xr.capacity <= FP_TEMPLATE_MAX ? xr.capacity : 100;
                    c.address = xr.addr;
                    if (xr.pwd_unlocked) {
                        (void)fp_sensor_set_password(t, xr.addr, dev_chk.password, &code);
                        memcpy(c.password, dev_chk.password, 4);
                        fp_session_t ds = session_of(&c);
                        (void)fp_sensor_empty(t, &ds, &code);
                    }
                    else {
                        const uint8_t npwd[4] = { 'N', 'P', 'W', 'D' };
                        memcpy(c.password, npwd, 4);
                        fp_session_t ns = session_of(&c);
                        if (fp_sensor_empty(t, &ns, &code) != FP_SENSOR_OK || code != FP_CONF_OK) {
                            for (uint16_t sl = 0; sl < 16; sl++) {
                                (void)fp_sensor_delete_chars(t, &ns, sl, 8, &code);
                            }
                        }
                    }
                    if (!conf_save(&c)) {
                        conf_clear(&c);
                        return FP_ERR_STORAGE;
                    }
                    fp_diag_reset();
                    sensor_led(c.address, FP_LED_FUNC_ON, FP_LED_COLOR_GREEN, FP_LED_COLOR_GREEN, 0);
                    if (capacity_out != NULL) {
                        *capacity_out = c.capacity;
                    }
                    conf_clear(&c);
                    return FP_OK;
                }
                fp_diag_err(FP_INS_VFY_PWD, xr.c01 != 0xFF ? xr.c01 : FP_CONF_WRONG_PWD, FP_SENSOR_OK);
                conf_clear(&c);
                return FP_ERR_NOT_FACTORY;
            }
        }

        /*
         * R558-S Manual V1.1: VfyPwd (0x13) MUST be sent BEFORE ReadSysPara (0x0F) or any other command
         * after power-on, otherwise real R558-S hardware rejects ReadSysPara.
         */
        fp_session_t factory = { .address = FP_FACTORY_ADDRESS, .password = { 0, 0, 0, 0 } };
        fp_sensor_status_t st = fp_sensor_verify_password(t, &factory, &code);
        if (st != FP_SENSOR_OK) {
            last_sensor_detected = false;
            fp_diag_err(FP_INS_VFY_PWD, fp_sensor_has_last_ack() ? fp_sensor_last_ack_conf() : 0xFF, st);
            conf_clear(&c);
            return FP_ERR_SENSOR;
        }
        last_sensor_detected = true;
        if (code != FP_CONF_OK) {
            fp_diag_err(FP_INS_VFY_PWD, code, FP_SENSOR_OK);
            conf_clear(&c);
            return FP_ERR_NOT_FACTORY;
        }
    }

    if (!resumed && !password_set_already) {
        fp_sysparam_t sp;
        if (fp_sensor_read_sysparam(t, FP_FACTORY_ADDRESS, &sp, &code) != FP_SENSOR_OK || code != FP_CONF_OK) {
            conf_clear(&c);
            return FP_ERR_SENSOR;
        }
        if (sp.capacity == 0) {
            conf_clear(&c);
            return FP_ERR_NOT_FACTORY;
        }
        uint16_t usable_cap = sp.capacity > FP_TEMPLATE_MAX ? FP_TEMPLATE_MAX : sp.capacity;

        uint8_t new_pwd[4];
        uint32_t addr = 0;
        fp_session_t dev_bind;
        if (esp_dev_shared_session(&dev_bind)) {
            /* Universal dev-mode pairing credentials survive flash erases and board swaps while remaining restorable. */
            memcpy(new_pwd, dev_bind.password, 4);
            addr = dev_bind.address;
        }
        else {
            uint8_t new_addr[4];
            do {
                random_fill_buffer(BYTE_ARRAY(new_pwd, sizeof(new_pwd)));
            } while (new_pwd[0] == 0 && new_pwd[1] == 0 && new_pwd[2] == 0 && new_pwd[3] == 0);
            do {
                random_fill_buffer(BYTE_ARRAY(new_addr, sizeof(new_addr)));
                addr = ((uint32_t)new_addr[0] << 24) | ((uint32_t)new_addr[1] << 16) | ((uint32_t)new_addr[2] << 8) | new_addr[3];
            } while (addr == 0 || addr == FP_FACTORY_ADDRESS);
        }

        /* Stage the secrets before the sensor is changed. */
        memset(&c, 0, sizeof(c));
        c.flags = FP_FLAG_STAGED;
        c.capacity = usable_cap;
        memcpy(c.password, new_pwd, 4);
        c.address = addr;
        if (!conf_save(&c)) {
            conf_clear(&c);
            return FP_ERR_STORAGE;
        }
        if (fp_sensor_set_password(t, FP_FACTORY_ADDRESS, c.password, &code) != FP_SENSOR_OK || code != FP_CONF_OK) {
            conf_clear(&c);
            return FP_ERR_SENSOR;
        }
    }

    if (!resumed) {
        /* Move the module to the stored address. Before that, the password must verify at the factory address. */
        fp_session_t f = { .address = FP_FACTORY_ADDRESS };
        memcpy(f.password, c.password, 4);
        if (fp_sensor_verify_password(t, &f, &code) != FP_SENSOR_OK || code != FP_CONF_OK) {
            res = FP_ERR_SENSOR;
        }
        if (res == FP_OK && fp_sensor_set_chip_address(t, FP_FACTORY_ADDRESS, c.address, &code) != FP_SENSOR_OK) {
            res = FP_ERR_SENSOR;
        }
        if (res == FP_OK && code != FP_CONF_OK) {
            res = FP_ERR_SENSOR;
        }
    }

    if (res == FP_OK) {
        /* From here on, all traffic uses the stored address and password. */
        fp_session_t s = session_of(&c);
        fp_sysparam_t sp;
        if (fp_sensor_verify_password(t, &s, &code) != FP_SENSOR_OK || code != FP_CONF_OK) {
            res = FP_ERR_SENSOR;
        }
        if (res == FP_OK && (fp_sensor_read_sysparam(t, s.address, &sp, &code) != FP_SENSOR_OK || code != FP_CONF_OK || sp.address != s.address)) {
            res = FP_ERR_SENSOR;
        }
        if (res == FP_OK && (fp_sensor_empty(t, &s, &code) != FP_SENSOR_OK || code != FP_CONF_OK)) {
            /* Templates from before pairing must not survive: the sensor may have been handled by someone else. */
            res = FP_ERR_SENSOR;
        }
        if (res == FP_OK) {
            c.flags = FP_FLAG_PAIRED;
            c.fail_count = 0;
            memset(c.slots, 0, sizeof(c.slots));
            if (!conf_save(&c)) {
                res = FP_ERR_STORAGE;
            }
            else {
                sensor_led(c.address, FP_LED_FUNC_FLASH, FP_LED_COLOR_GREEN, FP_LED_COLOR_GREEN, 3);
                if (capacity_out != NULL) {
                    *capacity_out = c.capacity;
                }
            }
        }
    }
    conf_clear(&c);
    return res;
}

fp_result_t fp_enroll(uint16_t *slot_out) {
    if (!FP_FEATURE_ON) {
        return FP_ERR_NOT_PAIRED;
    }
    fp_diag_reset();
    fp_conf_t c;
    conf_load(&c);
    fp_result_t res = FP_OK;

    if (!(c.flags & FP_FLAG_PAIRED)) {
        res = FP_ERR_NOT_PAIRED;
    }
    else if (c.flags & FP_FLAG_LOCKED) {
        res = FP_ERR_LOCKED;
    }
    else {
        res = authenticate_sensor(&c);
        if (res == FP_ERR_SENSOR_AUTH) {
            register_failure(&c, true);
        }
    }

    uint16_t slot = 0;
    if (res == FP_OK) {
        bool found = false;
        for (uint16_t i = 0; i < c.capacity && i < FP_TEMPLATE_MAX; i++) {
            if (!slot_used(&c, i)) {
                slot = i;
                found = true;
                break;
            }
        }
        if (!found) {
            res = FP_ERR_FULL;
        }
    }

    if (res == FP_OK) {
        const fp_transport_t *t = fp_uart_transport();
        fp_session_t s = session_of(&c);

        if (use_auto_mode) {
            res = fp_enroll_auto(&s, slot, 2);
        }
        else {
            uint8_t max_scans = 2;
#if defined(ESP_PLATFORM)
            max_scans = 4;
#endif
            fp_sysparam_t sp;
            uint8_t sp_code = 0xFF;
            if (fp_sensor_read_sysparam(t, s.address, &sp, &sp_code) == FP_SENSOR_OK && sp_code == FP_CONF_OK) {
                if (sp.status_reg >= 2 && sp.status_reg <= 6 && sp.status_reg > max_scans) {
                    max_scans = (uint8_t)sp.status_reg;
                }
            }

            bool need_auto_fallback = false;
            sensor_led(s.address, FP_LED_FUNC_BREATHE, FP_LED_COLOR_BLUE, FP_LED_COLOR_BLUE, 0);
            res = capture_to_buffer(&s, FP_BUF_1, FP_ENROLL_STEP_TIMEOUT_MS);
            if (res == FP_OK) {
                sensor_led(s.address, FP_LED_FUNC_ON, FP_LED_COLOR_CYAN, FP_LED_COLOR_CYAN, 0);
                res = wait_finger_removed(&s, FP_ENROLL_STEP_TIMEOUT_MS);
            }
            if (res == FP_OK) {
                sensor_led(s.address, FP_LED_FUNC_BREATHE, FP_LED_COLOR_PURPLE, FP_LED_COLOR_BLUE, 0);
                res = capture_to_buffer(&s, FP_BUF_2, FP_ENROLL_STEP_TIMEOUT_MS);
            }

            if (res == FP_OK) {
                for (uint8_t scan = 2;; scan++) {
                    uint8_t reg_code = 0xFF;
                    fp_sensor_status_t rst = fp_sensor_reg_model(t, &s, &reg_code);
                    if (rst != FP_SENSOR_OK) {
                        fp_diag_err(FP_INS_REG_MODEL, reg_code, rst);
                        res = FP_ERR_SENSOR;
                        break;
                    }
                    if (reg_code == FP_CONF_OK) {
                        res = FP_OK;
                        break;
                    }
                    if (reg_code == FP_CONF_ENC_MISMATCH) {
                        need_auto_fallback = true;
                        break;
                    }
                    if (scan < max_scans) {
                        /* R558-S EnrollTimes requires additional scans (e.g. 4-buffer merge). */
                        sensor_led(s.address, FP_LED_FUNC_ON, FP_LED_COLOR_CYAN, FP_LED_COLOR_CYAN, 0);
                        res = wait_finger_removed(&s, FP_ENROLL_STEP_TIMEOUT_MS);
                        if (res != FP_OK) {
                            break;
                        }
                        uint8_t next_color = (scan == 2) ? FP_LED_COLOR_YELLOW : FP_LED_COLOR_WHITE;
                        sensor_led(s.address, FP_LED_FUNC_BREATHE, next_color, FP_LED_COLOR_BLUE, 0);
                        res = capture_to_buffer(&s, (uint8_t)(scan + 1u), FP_ENROLL_STEP_TIMEOUT_MS);
                        if (res != FP_OK) {
                            break;
                        }
                        continue;
                    }
                    if (reg_code == FP_CONF_COMBINE_FAIL || reg_code == FP_CONF_POOR_TEMPLATE) {
                        fp_diag_err(FP_INS_REG_MODEL, reg_code, FP_SENSOR_OK);
                        res = FP_ERR_NO_MATCH;
                    }
                    else {
                        fp_diag_err(FP_INS_REG_MODEL, reg_code, FP_SENSOR_OK);
                        need_auto_fallback = true;
                    }
                    break;
                }
            }

            if (res == FP_OK && !need_auto_fallback) {
                uint8_t store_code = 0xFF;
                fp_sensor_status_t st = fp_sensor_store(t, &s, FP_BUF_1, slot, &store_code);
                if (st == FP_SENSOR_OK && store_code == FP_CONF_ENC_MISMATCH) {
                    need_auto_fallback = true;
                }
                else if (st == FP_SENSOR_OK && store_code != FP_CONF_OK) {
                    /* Ensure slot is clear in module flash (e.g. 0x22 occupied) and retry Store once. */
                    uint8_t del_code = 0xFF;
                    (void)fp_sensor_delete_chars(t, &s, slot, 1, &del_code);
                    st = fp_sensor_store(t, &s, FP_BUF_1, slot, &store_code);
                    if ((st != FP_SENSOR_OK || store_code != FP_CONF_OK) && is_dev_npwd_conf(&c)) {
                        for (uint16_t alt = (uint16_t)(slot + 1u); alt < c.capacity && alt < FP_TEMPLATE_MAX; alt++) {
                            if (slot_used(&c, alt)) {
                                continue;
                            }
                            st = fp_sensor_store(t, &s, FP_BUF_1, alt, &store_code);
                            if (st == FP_SENSOR_OK && store_code == FP_CONF_OK) {
                                slot = alt;
                                break;
                            }
                        }
                    }
                    if (st != FP_SENSOR_OK || store_code != FP_CONF_OK) {
                        fp_diag_err(FP_INS_STORE, store_code, st);
#if defined(ESP_PLATFORM)
                        need_auto_fallback = true;
#else
                        res = FP_ERR_SENSOR;
#endif
                    }
                }
                else if (st != FP_SENSOR_OK) {
                    fp_diag_err(FP_INS_STORE, store_code, st);
                    res = FP_ERR_SENSOR;
                }
            }

            if (need_auto_fallback) {
                use_auto_mode = true;
                fp_diag_reset();
                sensor_led(s.address, FP_LED_FUNC_ON, FP_LED_COLOR_CYAN, FP_LED_COLOR_CYAN, 0);
                (void)wait_finger_removed(&s, FP_ENROLL_STEP_TIMEOUT_MS);
                res = fp_enroll_auto(&s, slot, 2);
            }
        }

        if (res == FP_OK) {
            slot_set(&c, slot, true);
            if (!conf_save(&c)) {
                res = FP_ERR_STORAGE;
            }
            else if (slot_out != NULL) {
                *slot_out = slot;
            }
        }
        if (res == FP_OK) {
            fp_diag_reset();
            sensor_led(s.address, FP_LED_FUNC_FLASH, FP_LED_COLOR_GREEN, FP_LED_COLOR_GREEN, 3);
        }
        else if (res == FP_ERR_NO_MATCH) {
            sensor_led(s.address, FP_LED_FUNC_FLASH, FP_LED_COLOR_RED, FP_LED_COLOR_RED, 2);
        }
        else {
            sensor_led(s.address, FP_LED_FUNC_OFF, FP_LED_COLOR_OFF, FP_LED_COLOR_OFF, 0);
        }
    }
    conf_clear(&c);
    return res;
}

fp_result_t fp_delete(uint16_t slot) {
    if (!FP_FEATURE_ON) {
        return FP_ERR_NOT_PAIRED;
    }
    fp_conf_t c;
    conf_load(&c);
    fp_result_t res = FP_OK;
    if (!(c.flags & FP_FLAG_PAIRED)) {
        res = FP_ERR_NOT_PAIRED;
    }
    else {
        res = authenticate_sensor(&c);
    }
    if (res == FP_OK) {
        fp_session_t s = session_of(&c);
        uint8_t code = 0xFF;
        if (slot == FP_ALL_SLOTS) {
            if ((fp_sensor_empty(fp_uart_transport(), &s, &code) != FP_SENSOR_OK || code != FP_CONF_OK) &&
                !is_dev_npwd_conf(&c)) {
                res = FP_ERR_SENSOR;
            }
            else {
                memset(c.slots, 0, sizeof(c.slots));
            }
        }
        else if (slot >= c.capacity) {
            res = FP_ERR_BAD_PARAM;
        }
        else if (!slot_used(&c, slot)) {
            res = FP_ERR_NO_TEMPLATE;
        }
        else if ((fp_sensor_delete_chars(fp_uart_transport(), &s, slot, 1, &code) != FP_SENSOR_OK || code != FP_CONF_OK) &&
                 !is_dev_npwd_conf(&c)) {
            res = FP_ERR_SENSOR;
        }
        else {
            slot_set(&c, slot, false);
        }
        if (res == FP_OK && !conf_save(&c)) {
            res = FP_ERR_STORAGE;
        }
    }
    conf_clear(&c);
    return res;
}

fp_result_t fp_unlock(void) {
    if (!FP_FEATURE_ON) {
        return FP_ERR_NOT_PAIRED;
    }
    fp_conf_t c;
    conf_load(&c);
    fp_result_t res = FP_OK;
    if (!(c.flags & FP_FLAG_PAIRED)) {
        res = FP_ERR_NOT_PAIRED;
    }
    else {
        c.flags &= (uint8_t)~FP_FLAG_LOCKED;
        c.fail_count = 0;
        if (!conf_save(&c)) {
            res = FP_ERR_STORAGE;
        }
        else if (authenticate_sensor(&c) == FP_OK) {
            sensor_led(c.address, FP_LED_FUNC_FLASH, FP_LED_COLOR_GREEN, FP_LED_COLOR_GREEN, 2);
        }
    }
    conf_clear(&c);
    return res;
}

/* ---- R3: backup and restore of the trusted sensor configuration ---- */

#define FP_BACKUP_VERSION 1
_Static_assert(FP_BACKUP_BYTES == FP_BACKUP_HEADER + FP_CONF_BITMAP, "backup size matches the slot bitmap");

fp_result_t fp_backup(uint8_t out[FP_BACKUP_BYTES]) {
    if (!FP_FEATURE_ON) {
        return FP_ERR_NOT_PAIRED;
    }
    fp_conf_t c;
    conf_load(&c);
    if ((c.flags & FP_FLAG_PAIRED) == 0) {
        conf_clear(&c);
        return FP_ERR_NOT_PAIRED;
    }
    out[0] = FP_BACKUP_VERSION;
    memcpy(out + 1, c.password, 4);
    out[5] = (uint8_t)(c.address >> 24);
    out[6] = (uint8_t)(c.address >> 16);
    out[7] = (uint8_t)(c.address >> 8);
    out[8] = (uint8_t)(c.address);
    out[9] = (uint8_t)(c.capacity >> 8);
    out[10] = (uint8_t)(c.capacity);
    memcpy(out + FP_BACKUP_HEADER, c.slots, FP_CONF_BITMAP);
    conf_clear(&c);
    return FP_OK;
}

fp_result_t fp_restore(const uint8_t *blob, size_t len) {
    if (!FP_FEATURE_ON) {
        return FP_ERR_NOT_PAIRED;
    }
    if (!flash_requirement_met()) {
        return FP_ERR_NOT_SECURE;
    }
    if (blob == NULL || len != FP_BACKUP_BYTES || blob[0] != FP_BACKUP_VERSION) {
        return FP_ERR_BACKUP_FORMAT;
    }

    fp_conf_t n;
    conf_clear(&n);
    memcpy(n.password, blob + 1, 4);
    n.address = ((uint32_t)blob[5] << 24) | ((uint32_t)blob[6] << 16) | ((uint32_t)blob[7] << 8) | blob[8];
    n.capacity = (uint16_t)((blob[9] << 8) | blob[10]);
    memcpy(n.slots, blob + FP_BACKUP_HEADER, FP_CONF_BITMAP);

    /* Format checks: no all-zero password, no factory address, capacity in range, no slot beyond capacity. */
    bool pwd_zero = n.password[0] == 0 && n.password[1] == 0 && n.password[2] == 0 && n.password[3] == 0;
    uint16_t used = 0;
    bool slots_ok = true;
    for (uint16_t i = 0; i < FP_TEMPLATE_MAX; i++) {
        if (slot_used(&n, i)) {
            used++;
        }
    }
    for (uint16_t i = n.capacity; i < FP_TEMPLATE_MAX; i++) {
        if ((n.slots[i / 8] & (1u << (i % 8))) != 0) {
            slots_ok = false;
        }
    }
    if (pwd_zero || n.address == FP_FACTORY_ADDRESS || n.capacity == 0 || n.capacity > FP_TEMPLATE_MAX || !slots_ok || used > n.capacity) {
        conf_clear(&n);
        return FP_ERR_BACKUP_FORMAT;
    }

    fp_conf_t cur;
    conf_load(&cur);
    if (cur.flags & FP_FLAG_PAIRED) {
        /* Already paired: the same sensor is a no-op, another sensor is refused (replacement needs pairing rules). */
        bool same = memcmp(cur.password, n.password, 4) == 0 && cur.address == n.address;
        conf_clear(&cur);
        conf_clear(&n);
        return same ? FP_OK : FP_ERR_ALREADY_PAIRED;
    }
    conf_clear(&cur);

    /* The backup is only trusted if the connected sensor accepts its password and address. */
    fp_result_t res = authenticate_sensor(&n);
    if (res == FP_ERR_SENSOR_AUTH) {
        res = FP_ERR_BACKUP_MISMATCH;
    }
    if (res != FP_OK) {
        conf_clear(&n);
        return res;
    }
    uint16_t sensor_count = 0;
    uint8_t code = 0xFF;
    fp_session_t s = session_of(&n);
    if (fp_sensor_template_num(fp_uart_transport(), &s, &sensor_count, &code) != FP_SENSOR_OK || code != FP_CONF_OK) {
        conf_clear(&n);
        return FP_ERR_SENSOR;
    }
    if (sensor_count != used) {
        conf_clear(&n);
        return FP_ERR_BACKUP_MISMATCH;
    }

    /* Restored state: paired, not locked, no failures. Lock state is not restored from the blob. */
    n.flags = FP_FLAG_PAIRED;
    n.fail_count = 0;
    bool saved = conf_save(&n);
    conf_clear(&n);
    return saved ? FP_OK : FP_ERR_STORAGE;
}
