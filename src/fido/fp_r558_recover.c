/*
 * Pico FIDO - R558-S password recovery ladder.
 *
 * This file is part of the Pico FIDO distribution (https://github.com/polhenarejos/pico-fido).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include "fp_r558_recover.h"

#include <stdio.h>
#include <string.h>

const char *fp_recover_source_name(fp_recover_source_t src) {
    switch (src) {
        case FP_RECOVER_SRC_STORED:
            return "stored";
        case FP_RECOVER_SRC_DERIVED:
            return "derived";
        case FP_RECOVER_SRC_SHARED:
            return "shared";
        case FP_RECOVER_SRC_USER:
            return "user";
        case FP_RECOVER_SRC_FACTORY:
            return "factory";
        case FP_RECOVER_SRC_FLASH:
            return "flash";
        default:
            return "none";
    }
}

size_t fp_recover_add_candidate(fp_recover_candidate_t *list, size_t count, size_t cap,
                                fp_recover_source_t source, uint32_t address,
                                const uint8_t password[4]) {
    if (list == NULL || password == NULL || count >= cap) {
        return count;
    }
    if (address == 0u) {
        return count;
    }
    for (size_t i = 0; i < count; i++) {
        if (list[i].address == address && memcmp(list[i].password, password, 4) == 0) {
            return count; /* same credential pair, keep the earlier (higher priority) source */
        }
    }
    list[count].source = source;
    list[count].address = address;
    memcpy(list[count].password, password, 4);
    return count + 1u;
}

size_t fp_recover_add_password_variants(fp_recover_candidate_t *list, size_t count, size_t cap,
                                        fp_recover_source_t source, const uint8_t password[4],
                                        const uint32_t *addresses, size_t address_count) {
    if (addresses == NULL) {
        return count;
    }
    for (size_t i = 0; i < address_count && count < cap; i++) {
        count = fp_recover_add_candidate(list, count, cap, source, addresses[i], password);
    }
    return count;
}

static uint16_t rd_be16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t rd_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static bool pwd_plausible(const uint8_t pwd[4]) {
    /* Reject erased flash (0xFFFFFFFF) and the zero password (covered by the factory stage). */
    return !(pwd[0] == 0xFF && pwd[1] == 0xFF && pwd[2] == 0xFF && pwd[3] == 0xFF) &&
           !(pwd[0] == 0 && pwd[1] == 0 && pwd[2] == 0 && pwd[3] == 0);
}

size_t fp_recover_scan_image(const uint8_t *img, size_t img_len,
                             fp_recover_candidate_t *list, size_t count, size_t cap) {
    if (img == NULL || list == NULL || img_len < 46u) {
        return count;
    }
    /* Known EF_FP_CONF flag bits: PAIRED|LOCKED|STAGED|ZA_BYPASS (see fp_r558.c). */
    const uint8_t known_flags = 0x01u | 0x02u | 0x04u | 0x08u;
    for (size_t off = 0; off + 46u <= img_len && count < cap; off++) {
        const uint8_t *p = img + off;
        if (p[0] != 0x01u) {
            continue;
        }
        /* Layout A: EF_FP_CONF payload (46 bytes). */
        if (p[3] == 0x00u && p[1] != 0u && (p[1] & (uint8_t)~known_flags) == 0u) {
            uint16_t capacity = rd_be16(p + 12);
            uint32_t addr = rd_be32(p + 8);
            if (capacity >= 1u && capacity <= 512u && addr != 0u && pwd_plausible(p + 4)) {
                count = fp_recover_add_candidate(list, count, cap, FP_RECOVER_SRC_FLASH,
                                                 addr, p + 4);
                continue;
            }
        }
        /* Layout B: backup blob (43 bytes, needs bytes up to +10 only for the signature). */
        if (off + 43u <= img_len) {
            uint16_t capacity = rd_be16(p + 9);
            uint32_t addr = rd_be32(p + 5);
            if (capacity >= 1u && capacity <= 512u && addr != 0u &&
                addr != FP_FACTORY_ADDRESS && pwd_plausible(p + 1)) {
                count = fp_recover_add_candidate(list, count, cap, FP_RECOVER_SRC_FLASH,
                                                 addr, p + 1);
            }
        }
    }
    return count;
}

/*
 * Sends exactly one VfyPwd per candidate and stops at the first 0x00. Nothing is written to the
 * module, so an unsuccessful run leaves the module bit-for-bit as it was.
 */
bool fp_recover_run(const fp_transport_t *t, const fp_recover_candidate_t *list, size_t count,
                    fp_recover_report_t *out) {
    if (out == NULL) {
        return false;
    }
    memset(out, 0, sizeof(*out));
    out->source = FP_RECOVER_SRC_NONE;
    out->last_conf = 0xFF;
    if (t == NULL || list == NULL || count == 0u) {
        snprintf(out->summary, sizeof(out->summary), "recover: no candidates");
        return false;
    }
    if (count > FP_RECOVER_MAX_CANDIDATES) {
        count = FP_RECOVER_MAX_CANDIDATES;
    }

    uint8_t wrong_pwd = 0;
    for (size_t i = 0; i < count; i++) {
        fp_session_t s;
        s.address = list[i].address;
        memcpy(s.password, list[i].password, 4);
        uint8_t code = 0xFF;
        out->attempts++;
        fp_sensor_status_t st = fp_sensor_verify_password(t, &s, &code);
        if (st == FP_SENSOR_OK || st == FP_SENSOR_BAD_ADDRESS) {
            out->sensor_present = true;
        }
        if (st == FP_SENSOR_OK) {
            out->last_conf = code;
        }
        if (st == FP_SENSOR_OK && code == FP_CONF_OK) {
            out->found = true;
            out->source = list[i].source;
            out->address = list[i].address;
            memcpy(out->password, list[i].password, 4);
            snprintf(out->summary, sizeof(out->summary),
                     "recover: OK src=%s A=%08X try=%u/%u",
                     fp_recover_source_name(list[i].source), (unsigned)list[i].address,
                     (unsigned)out->attempts, (unsigned)count);
            return true;
        }
        if (st == FP_SENSOR_OK && (code == FP_CONF_WRONG_PWD || code == 0x21)) {
            wrong_pwd++;
        }
    }

    /*
     * No candidate matched. Say *why* instead of a generic error: silence means wiring/power or a
     * module that no longer boots, 0x13/0x21 means the module is alive but the password is unknown.
     */
    snprintf(out->summary, sizeof(out->summary),
             "recover: no match (try=%u wrong=%u last=%02X %s)",
             (unsigned)out->attempts, (unsigned)wrong_pwd, (unsigned)out->last_conf,
             out->sensor_present ? "alive" : "silent");
    return false;
}
