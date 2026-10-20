/*
 * Pico FIDO - R558 fingerprint sensor, UART packet layer.
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

#include "fp_r558_sensor.h"

#include <string.h>

#define FP_BYTE_TIMEOUT_MS      100u
#define FP_HUNT_LIMIT           512u   /* junk bytes accepted while looking for a header */

static void put_u16_be(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xFF);
}

static void put_u32_be(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v & 0xFF);
}

static uint16_t get_u16_be(const uint8_t *p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

static uint32_t get_u32_be(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

uint16_t fp_sensor_checksum(uint8_t pid, uint16_t length, const uint8_t *payload, uint16_t payload_len) {
    uint32_t sum = pid + (length >> 8) + (length & 0xFF);
    for (uint16_t i = 0; i < payload_len; i++) {
        sum += payload[i];
    }
    return (uint16_t)(sum & 0xFFFF);
}

size_t fp_sensor_encode_packet(uint8_t *out, size_t out_cap, uint32_t addr, uint8_t pid,
                               const uint8_t *payload, uint16_t payload_len) {
    if (out == NULL || (payload == NULL && payload_len != 0)) {
        return 0;
    }
    if (payload_len > FP_PACKET_MAX_PAYLOAD) {
        return 0;
    }
    size_t total = FP_PACKET_HEADER_LEN + payload_len + 2u;
    if (out_cap < total) {
        return 0;
    }
    uint16_t length = (uint16_t)(payload_len + 2u);
    out[0] = 0xEF;
    out[1] = 0x01;
    put_u32_be(out + 2, addr);
    out[6] = pid;
    put_u16_be(out + 7, length);
    if (payload_len > 0) {
        memcpy(out + FP_PACKET_HEADER_LEN, payload, payload_len);
    }
    put_u16_be(out + FP_PACKET_HEADER_LEN + payload_len, fp_sensor_checksum(pid, length, payload, payload_len));
    return total;
}

/* Reads exactly n bytes. The first byte may wait first_timeout_ms, later bytes FP_BYTE_TIMEOUT_MS. */
static bool read_exact(const fp_transport_t *t, uint8_t *buf, size_t n, uint32_t first_timeout_ms, bool *io_error) {
    size_t got = 0;
    uint32_t timeout = first_timeout_ms;
    while (got < n) {
        int r = t->read(t->ctx, buf + got, n - got, timeout);
        if (r < 0) {
            *io_error = true;
            return false;
        }
        if (r == 0) {
            return false;
        }
        got += (size_t)r;
        timeout = FP_BYTE_TIMEOUT_MS;
    }
    return true;
}

fp_sensor_status_t fp_sensor_txn(const fp_transport_t *t, uint32_t addr, uint8_t ins,
                                 const uint8_t *params, uint16_t params_len,
                                 uint8_t *out, uint16_t out_cap, uint16_t *out_len,
                                 uint8_t *code, uint32_t timeout_ms, bool check_address) {
    if (t == NULL || t->read == NULL || t->write == NULL) {
        return FP_SENSOR_IO_ERROR;
    }
    if (params_len > FP_PACKET_MAX_PAYLOAD - 1u) {
        return FP_SENSOR_IO_ERROR;
    }

    uint8_t payload[FP_PACKET_MAX_PAYLOAD];
    uint8_t packet[FP_PACKET_HEADER_LEN + FP_PACKET_MAX_PAYLOAD + 2u];
    payload[0] = ins;
    if (params_len > 0) {
        memcpy(payload + 1, params, params_len);
    }
    size_t n = fp_sensor_encode_packet(packet, sizeof(packet), addr, FP_PID_COMMAND, payload, (uint16_t)(params_len + 1u));
    if (n == 0) {
        return FP_SENSOR_IO_ERROR;
    }
    if (t->flush != NULL) {
        t->flush(t->ctx);
    }
    if (t->write(t->ctx, packet, n) != 0) {
        return FP_SENSOR_IO_ERROR;
    }

    bool io_error = false;
    uint8_t b = 0;
    uint32_t junk = 0;
    /* Hunt for the 0xEF 0x01 header. Unrelated bytes are skipped. */
    for (;;) {
        if (!read_exact(t, &b, 1, timeout_ms, &io_error)) {
            return io_error ? FP_SENSOR_IO_ERROR : FP_SENSOR_TIMEOUT;
        }
        if (b != 0xEF) {
            if (++junk > FP_HUNT_LIMIT) {
                return FP_SENSOR_BAD_FRAME;
            }
            continue;
        }
        /* Saw 0xEF. Read the following byte; another 0xEF keeps us here, 0x01 completes the header. */
        bool header_found = false;
        for (;;) {
            if (!read_exact(t, &b, 1, FP_BYTE_TIMEOUT_MS, &io_error)) {
                return io_error ? FP_SENSOR_IO_ERROR : FP_SENSOR_TIMEOUT;
            }
            if (b == 0xEF) {
                continue;
            }
            header_found = (b == 0x01);
            break;
        }
        if (header_found) {
            break;
        }
        if (++junk > FP_HUNT_LIMIT) {
            return FP_SENSOR_BAD_FRAME;
        }
    }

    /* Address (4) + PID (1) + length (2). */
    uint8_t rest[7];
    if (!read_exact(t, rest, sizeof(rest), FP_BYTE_TIMEOUT_MS, &io_error)) {
        return io_error ? FP_SENSOR_IO_ERROR : FP_SENSOR_TIMEOUT;
    }
    uint32_t resp_addr = get_u32_be(rest);
    uint8_t pid = rest[4];
    uint16_t length = get_u16_be(rest + 5);
    if (length < 2u || (uint32_t)(length - 2u) > FP_PACKET_MAX_PAYLOAD) {
        return FP_SENSOR_BAD_FRAME;
    }
    uint16_t body_len = (uint16_t)(length - 2u);
    uint8_t body[FP_PACKET_MAX_PAYLOAD + 2u];
    if (!read_exact(t, body, length, FP_BYTE_TIMEOUT_MS, &io_error)) {
        return io_error ? FP_SENSOR_IO_ERROR : FP_SENSOR_TIMEOUT;
    }
    uint16_t received_sum = get_u16_be(body + body_len);
    if (pid != FP_PID_ACK || received_sum != fp_sensor_checksum(pid, length, body, body_len)) {
        return FP_SENSOR_BAD_FRAME;
    }
    if (check_address && resp_addr != addr) {
        return FP_SENSOR_BAD_ADDRESS;
    }

    if (body_len == 0) {
        /* A valid ack without confirmation code is treated as a protocol violation. */
        return FP_SENSOR_BAD_FRAME;
    }
    if (out != NULL) {
        uint16_t copy = body_len < out_cap ? body_len : out_cap;
        memcpy(out, body, copy);
    }
    if (out_len != NULL) {
        *out_len = body_len;
    }
    if (code != NULL) {
        *code = body[0];
    }
    return FP_SENSOR_OK;
}

fp_sensor_status_t fp_sensor_read_sysparam(const fp_transport_t *t, uint32_t addr, fp_sysparam_t *out, uint8_t *code) {
    uint8_t buf[17];
    uint16_t len = 0;
    uint8_t c = 0xFF;
    fp_sensor_status_t st = fp_sensor_txn(t, addr, FP_INS_READ_SYS_PARA, NULL, 0, buf, sizeof(buf), &len, &c, 500, true);
    if (code != NULL) {
        *code = c;
    }
    if (st != FP_SENSOR_OK || c != FP_CONF_OK) {
        return st;
    }
    if (len < 17 || out == NULL) {
        return FP_SENSOR_BAD_FRAME;
    }
    out->status_reg = get_u16_be(buf + 1);
    out->system_id = get_u16_be(buf + 3);
    out->capacity = get_u16_be(buf + 5);
    out->security_level = get_u16_be(buf + 7);
    out->address = get_u32_be(buf + 9);
    out->packet_size_code = get_u16_be(buf + 13);
    out->baud_multiplier = get_u16_be(buf + 15);
    return FP_SENSOR_OK;
}

static fp_sensor_status_t simple_cmd(const fp_transport_t *t, const fp_session_t *s, uint8_t ins,
                                     const uint8_t *params, uint16_t params_len, uint32_t timeout_ms, uint8_t *code) {
    uint8_t c = 0xFF;
    fp_sensor_status_t st = fp_sensor_txn(t, s->address, ins, params, params_len, NULL, 0, NULL, &c, timeout_ms, true);
    if (code != NULL) {
        *code = c;
    }
    return st;
}

fp_sensor_status_t fp_sensor_verify_password(const fp_transport_t *t, const fp_session_t *s, uint8_t *code) {
    return simple_cmd(t, s, FP_INS_VFY_PWD, s->password, 4, 500, code);
}

fp_sensor_status_t fp_sensor_set_password(const fp_transport_t *t, uint32_t addr, const uint8_t pwd[4], uint8_t *code) {
    fp_session_t s = { .address = addr };
    memcpy(s.password, pwd, 4);
    return simple_cmd(t, &s, FP_INS_SET_PWD, pwd, 4, 500, code);
}

fp_sensor_status_t fp_sensor_set_chip_address(const fp_transport_t *t, uint32_t addr, uint32_t new_addr, uint8_t *code) {
    uint8_t p[4];
    put_u32_be(p, new_addr);
    uint8_t c = 0xFF;
    /* The module may already answer from the new address, so the ack address is not checked here. */
    fp_sensor_status_t st = fp_sensor_txn(t, addr, FP_INS_SET_CHIP_ADDR, p, 4, NULL, 0, NULL, &c, 500, false);
    if (code != NULL) {
        *code = c;
    }
    return st;
}

fp_sensor_status_t fp_sensor_gen_img(const fp_transport_t *t, const fp_session_t *s, uint8_t *code) {
    return simple_cmd(t, s, FP_INS_GEN_IMG, NULL, 0, 1000, code);
}

fp_sensor_status_t fp_sensor_img_2_tz(const fp_transport_t *t, const fp_session_t *s, uint8_t buffer, uint8_t *code) {
    return simple_cmd(t, s, FP_INS_IMG_2_TZ, &buffer, 1, 1000, code);
}

fp_sensor_status_t fp_sensor_search(const fp_transport_t *t, const fp_session_t *s, uint8_t buffer,
                                    uint16_t start_page, uint16_t page_count,
                                    uint8_t *code, uint16_t *page_id, uint16_t *score) {
    uint8_t p[5];
    p[0] = buffer;
    put_u16_be(p + 1, start_page);
    put_u16_be(p + 3, page_count);
    uint8_t buf[8];
    uint16_t len = 0;
    uint8_t c = 0xFF;
    fp_sensor_status_t st = fp_sensor_txn(t, s->address, FP_INS_SEARCH, p, sizeof(p), buf, sizeof(buf), &len, &c, 2000, true);
    if (code != NULL) {
        *code = c;
    }
    if (st == FP_SENSOR_OK && c == FP_CONF_OK) {
        if (len < 5) {
            return FP_SENSOR_BAD_FRAME;
        }
        if (page_id != NULL) {
            *page_id = get_u16_be(buf + 1);
        }
        if (score != NULL) {
            *score = get_u16_be(buf + 3);
        }
    }
    return st;
}

fp_sensor_status_t fp_sensor_reg_model(const fp_transport_t *t, const fp_session_t *s, uint8_t *code) {
    return simple_cmd(t, s, FP_INS_REG_MODEL, NULL, 0, 1000, code);
}

fp_sensor_status_t fp_sensor_store(const fp_transport_t *t, const fp_session_t *s, uint8_t buffer, uint16_t page_id, uint8_t *code) {
    uint8_t p[3];
    p[0] = buffer;
    put_u16_be(p + 1, page_id);
    return simple_cmd(t, s, FP_INS_STORE, p, sizeof(p), 2000, code);
}

fp_sensor_status_t fp_sensor_delete_chars(const fp_transport_t *t, const fp_session_t *s, uint16_t page_id, uint16_t count, uint8_t *code) {
    uint8_t p[4];
    put_u16_be(p, page_id);
    put_u16_be(p + 2, count);
    return simple_cmd(t, s, FP_INS_DELET_CHAR, p, sizeof(p), 2000, code);
}

fp_sensor_status_t fp_sensor_empty(const fp_transport_t *t, const fp_session_t *s, uint8_t *code) {
    return simple_cmd(t, s, FP_INS_EMPTY, NULL, 0, 3000, code);
}

/* TemplateNum: ack carries the confirmation code and the number of valid templates (2 bytes, BE). */
fp_sensor_status_t fp_sensor_template_num(const fp_transport_t *t, const fp_session_t *s, uint16_t *count, uint8_t *code) {
    uint8_t buf[3];   /* confirmation code, then the count (same layout as ReadSysPara) */
    uint16_t len = 0;
    uint8_t c = 0xFF;
    fp_sensor_status_t st = fp_sensor_txn(t, s->address, FP_INS_TEMPLATE_NUM, NULL, 0, buf, sizeof(buf), &len, &c, 1000, true);
    if (code != NULL) {
        *code = c;
    }
    if (st != FP_SENSOR_OK || c != FP_CONF_OK) {
        return st;
    }
    if (len < 3 || count == NULL) {
        return FP_SENSOR_BAD_FRAME;
    }
    *count = get_u16_be(buf + 1);
    return FP_SENSOR_OK;
}

/* PS_ControlBLN (0x3C): controls the R558-S built-in RGB ring LED over UART. */
fp_sensor_status_t fp_sensor_control_led(const fp_transport_t *t, uint32_t addr,
                                         uint8_t func, uint8_t start_color, uint8_t end_color,
                                         uint8_t cycles, uint8_t *code) {
    uint8_t p[4] = { func, start_color, end_color, cycles };
    uint8_t c = 0xFF;
    fp_sensor_status_t st = fp_sensor_txn(t, addr, FP_INS_CONTROL_BLN, p, sizeof(p), NULL, 0, NULL, &c, 150, false);
    if (code != NULL) {
        *code = c;
    }
    return st;
}
