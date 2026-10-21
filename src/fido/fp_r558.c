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
#include "mbedtls/platform_util.h"
#include <stdio.h>
#include <string.h>

#if defined(ESP_PLATFORM)
#include "esp_flash_encrypt.h"
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

static void probe_and_init_sensor(const fp_conf_t *c) {
    uint32_t hint_addr = (c->flags & (FP_FLAG_PAIRED | FP_FLAG_STAGED)) ? c->address : 0;
    fp_uart_scan_pins(hint_addr);

    const fp_transport_t *t = fp_uart_transport();
    uint8_t code = 0xFF;

    if (c->flags & FP_FLAG_PAIRED) {
        fp_session_t s = session_of(c);
        if (fp_sensor_verify_password(t, &s, &code) == FP_SENSOR_OK) {
            last_sensor_detected = true;
            if (code == FP_CONF_OK) {
                if (c->flags & FP_FLAG_LOCKED) {
                    sensor_led(c->address, FP_LED_FUNC_ON, FP_LED_COLOR_RED, FP_LED_COLOR_RED, 0);
                }
                else {
                    sensor_led(c->address, FP_LED_FUNC_FLASH, FP_LED_COLOR_CYAN, FP_LED_COLOR_CYAN, 2);
                }
            }
            return;
        }
    }

    fp_session_t factory = { .address = FP_FACTORY_ADDRESS, .password = { 0, 0, 0, 0 } };
    if (fp_sensor_verify_password(t, &factory, &code) == FP_SENSOR_OK) {
        last_sensor_detected = true;
        if (code == FP_CONF_OK && !(c->flags & FP_FLAG_PAIRED)) {
            sensor_led(FP_FACTORY_ADDRESS, FP_LED_FUNC_FLASH, FP_LED_COLOR_BLUE, FP_LED_COLOR_BLUE, 2);
        }
        return;
    }

    last_sensor_detected = false;
}

/* Checks the stored password at the stored address. Returns FP_OK, or FP_ERR_SENSOR_AUTH on a wrong password. */
static fp_result_t authenticate_sensor(const fp_conf_t *c) {
    fp_session_t s = session_of(c);
    uint8_t code = 0xFF;
    fp_sensor_status_t st = fp_sensor_verify_password(fp_uart_transport(), &s, &code);
    if (st != FP_SENSOR_OK) {
        fp_uart_scan_pins(c->address);
        st = fp_sensor_verify_password(fp_uart_transport(), &s, &code);
    }
    if (st != FP_SENSOR_OK) {
        last_sensor_detected = false;
        return FP_ERR_SENSOR;
    }
    last_sensor_detected = true;
    if (code == FP_CONF_OK) {
        return FP_OK;
    }
    if (code == FP_CONF_WRONG_PWD) {
        return FP_ERR_SENSOR_AUTH;
    }
    return FP_ERR_SENSOR;
}

/* Waits until the sensor reports a finger and turns it into characteristics in buffer. */
static fp_result_t capture_to_buffer(const fp_session_t *s, uint8_t buffer, uint32_t timeout_ms) {
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
            result = FP_ERR_SENSOR;
            break;
        }
        if (code == FP_CONF_NO_FINGER || code == FP_CONF_CAPTURE_FAIL || code == FP_CONF_SMALL_AREA) {
            fp_sleep_ms(50);
            continue;
        }
        if (code != FP_CONF_OK) {
            result = FP_ERR_SENSOR;
            break;
        }
        st = fp_sensor_img_2_tz(t, s, buffer, &code);
        if (st != FP_SENSOR_OK) {
            result = FP_ERR_SENSOR;
            break;
        }
        if (code == FP_CONF_OK) {
            result = FP_OK;
            break;
        }
        if (code == FP_CONF_IMG_MESSY || code == FP_CONF_IMG_FEW_POINTS ||
            code == FP_CONF_NO_IMAGE_BUF || code == FP_CONF_SMALL_AREA) {
            /* Poor or partial capacitive touch: let the user adjust finger and try again. */
            fp_sleep_ms(50);
            continue;
        }
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
        if (fp_sensor_gen_img(t, s, &code) != FP_SENSOR_OK) {
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
    st->paired = (c.flags & FP_FLAG_PAIRED) != 0;
    st->locked = (c.flags & FP_FLAG_LOCKED) != 0;
    st->capacity = c.capacity;
    st->enrolled = enrolled_count(&c);
    st->failed_attempts = c.fail_count;
    st->sensor_detected = last_sensor_detected;
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
        fp_led_op_begin();
        sensor_led(s.address, FP_LED_FUNC_BREATHE, FP_LED_COLOR_BLUE, FP_LED_COLOR_BLUE, 0);
        res = capture_to_buffer(&s, FP_BUF_1, timeout_ms);
        if (res == FP_OK) {
            uint8_t code = 0xFF;
            uint16_t page = 0, score = 0;
            fp_sensor_status_t st = fp_sensor_search(fp_uart_transport(), &s, FP_BUF_1, 0, c.capacity, &code, &page, &score);
            if (st != FP_SENSOR_OK) {
                res = FP_ERR_SENSOR;
            }
            else if (code == FP_CONF_NOT_FOUND) {
                res = FP_ERR_NO_MATCH;
                register_failure(&c, false);
            }
            else if (code != FP_CONF_OK) {
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
        fp_led_op_end(res == FP_OK);
        if (res == FP_OK) {
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
    fp_conf_t c;
    conf_load(&c);
    const fp_transport_t *t = fp_uart_transport();
    fp_result_t res = FP_OK;
    uint8_t code = 0xFF;

    fp_uart_scan_pins((c.flags & (FP_FLAG_PAIRED | FP_FLAG_STAGED)) ? c.address : 0);

    /* A sensor that is still trusted cannot be replaced. */
    if (c.flags & FP_FLAG_PAIRED) {
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
         * R558-S Manual V1.1: VfyPwd (0x13) MUST be sent BEFORE ReadSysPara (0x0F) or any other command
         * after power-on, otherwise real R558-S hardware rejects ReadSysPara.
         */
        fp_session_t factory = { .address = FP_FACTORY_ADDRESS, .password = { 0, 0, 0, 0 } };
        fp_sensor_status_t st = fp_sensor_verify_password(t, &factory, &code);
        if (st != FP_SENSOR_OK) {
            last_sensor_detected = false;
            conf_clear(&c);
            return FP_ERR_SENSOR;
        }
        last_sensor_detected = true;
        if (code != FP_CONF_OK) {
            conf_clear(&c);
            return FP_ERR_NOT_FACTORY;
        }

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
        uint8_t new_addr[4];
        do {
            random_fill_buffer(BYTE_ARRAY(new_pwd, sizeof(new_pwd)));
        } while (new_pwd[0] == 0 && new_pwd[1] == 0 && new_pwd[2] == 0 && new_pwd[3] == 0);
        uint32_t addr = 0;
        do {
            random_fill_buffer(BYTE_ARRAY(new_addr, sizeof(new_addr)));
            addr = ((uint32_t)new_addr[0] << 24) | ((uint32_t)new_addr[1] << 16) | ((uint32_t)new_addr[2] << 8) | new_addr[3];
        } while (addr == 0 || addr == FP_FACTORY_ADDRESS);

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
        fp_session_t s = session_of(&c);
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
            uint8_t code = 0xFF;
            if (fp_sensor_reg_model(fp_uart_transport(), &s, &code) != FP_SENSOR_OK) {
                res = FP_ERR_SENSOR;
            }
            else if (code == FP_CONF_COMBINE_FAIL || code == FP_CONF_POOR_TEMPLATE) {
                res = FP_ERR_NO_MATCH;
            }
            else if (code != FP_CONF_OK) {
                res = FP_ERR_SENSOR;
            }
        }
        if (res == FP_OK) {
            uint8_t code = 0xFF;
            fp_sensor_status_t st = fp_sensor_store(fp_uart_transport(), &s, FP_BUF_1, slot, &code);
            if (st != FP_SENSOR_OK || code != FP_CONF_OK) {
                res = FP_ERR_SENSOR;
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
            if (fp_sensor_empty(fp_uart_transport(), &s, &code) != FP_SENSOR_OK || code != FP_CONF_OK) {
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
        else if (fp_sensor_delete_chars(fp_uart_transport(), &s, slot, 1, &code) != FP_SENSOR_OK || code != FP_CONF_OK) {
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
