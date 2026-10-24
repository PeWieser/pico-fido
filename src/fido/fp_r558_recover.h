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
 *
 * Why this exists
 * ---------------
 * The R558-S stores its module password and chip address in its own NOR flash. Once a password is
 * set, every instruction except VfyPwd (0x13) is answered with 0x21 until that password is verified.
 * A module whose password is unknown is therefore unusable over UART - by design, there is no
 * "read the password back" or "reset without password" instruction in the protocol.
 *
 * The only reliable way back is to *know* the password again. This module implements that as a
 * deterministic ladder over the credentials the device can still produce itself:
 *
 *   1. FP_RECOVER_SRC_STORED   - what is stored in EF_FP_CONF (survives reboots, resets of the sensor)
 *   2. FP_RECOVER_SRC_DERIVED  - re-derived from this ESP32-S3 die (SHA-256 over eFuse MAC + domain)
 *   3. FP_RECOVER_SRC_SHARED   - fixed development credentials ("R558" @ "PICO")
 *   4. FP_RECOVER_SRC_USER     - 4-byte candidates supplied by the owner (e.g. from an old note/backup)
 *   5. FP_RECOVER_SRC_FACTORY  - factory default 0x00000000 @ 0xFFFFFFFF
 *
 * Each password is tried at every plausible address (stored address, last observed address, factory
 * address), because a lost SetChipAddr (0x15) leaves the password set but the address at the factory
 * value. The ladder only ever reads: it sends VfyPwd and nothing else. It never issues SetPwd,
 * SetChipAddr, RestSetting or any erasing/glitching operation.
 *
 * This file is deliberately free of firmware dependencies so it can be unit tested on a host.
 */

#ifndef FP_R558_RECOVER_H_
#define FP_R558_RECOVER_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "fp_r558_sensor.h"

/* Bounded on purpose: every wrong VfyPwd is one more chance for the module to lock the UART. */
#define FP_RECOVER_MAX_CANDIDATES 16u
#define FP_RECOVER_SUMMARY_LEN    160u

typedef enum {
    FP_RECOVER_SRC_NONE = 0,
    FP_RECOVER_SRC_STORED = 1,   /* password/address from the authenticator configuration */
    FP_RECOVER_SRC_DERIVED = 2,  /* re-derived from this die (eFuse MAC, SHA-256) */
    FP_RECOVER_SRC_SHARED = 3,   /* fixed development-mode credentials */
    FP_RECOVER_SRC_USER = 4,     /* candidate supplied by the owner/webapp */
    FP_RECOVER_SRC_FACTORY = 5,  /* factory default 0x00000000 @ 0xFFFFFFFF */
} fp_recover_source_t;

typedef struct {
    fp_recover_source_t source;
    uint32_t address;
    uint8_t password[4];
} fp_recover_candidate_t;

typedef struct {
    bool found;                  /* a candidate verified against the connected module */
    fp_recover_source_t source;  /* which stage produced the working credentials */
    uint32_t address;            /* module address that answered */
    uint8_t password[4];         /* verified password (caller stores it, never prints it) */
    uint8_t attempts;            /* VfyPwd frames sent */
    uint8_t last_conf;           /* last confirmation code seen (0x00, 0x13, 0x21, ...) */
    bool sensor_present;         /* at least one well-formed frame came back */
    char summary[FP_RECOVER_SUMMARY_LEN];
} fp_recover_report_t;

/* Appends one candidate unless it is a duplicate or the list is full. Returns the new count. */
size_t fp_recover_add_candidate(fp_recover_candidate_t *list, size_t count, size_t cap,
                                fp_recover_source_t source, uint32_t address,
                                const uint8_t password[4]);

/* Appends one password at every address in `addresses` (duplicates are dropped). */
size_t fp_recover_add_password_variants(fp_recover_candidate_t *list, size_t count, size_t cap,
                                        fp_recover_source_t source, const uint8_t password[4],
                                        const uint32_t *addresses, size_t address_count);

/* Runs the ladder. Bounded, non-destructive, safe to call repeatedly. */
bool fp_recover_run(const fp_transport_t *t, const fp_recover_candidate_t *list, size_t count,
                    fp_recover_report_t *out);

/* Stable identifier for telemetry/UI ("stored", "derived", "shared", "user", "factory", "none"). */
const char *fp_recover_source_name(fp_recover_source_t src);

#endif /* FP_R558_RECOVER_H_ */
