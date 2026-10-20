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
 *
 * Security model (summary, see docs/fingerprint/R558_PLAN.md for the full discussion):
 *  - A sensor is only trusted after pairing. Pairing needs the device PIN (authenticatorConfig permission)
 *    and sets a random 4-byte module password and a random 4-byte module address. Both are stored in the
 *    encrypted object store (MKEK), never in plain flash.
 *  - Before every verification the stored password is checked at the stored address. A replacement
 *    sensor is factory-fresh (address 0xFFFFFFFF, no password) and cannot answer, so it is rejected.
 *  - A module that answers at our address with a wrong password is treated as tampering and locks UV.
 *  - Only templates in slots this firmware enrolled are accepted; the module cannot introduce new ones.
 *  - Repeated non-matching fingers lock UV until the PIN is entered again (CTAP_VENDOR_FP unlock).
 */

#ifndef FP_R558_H_
#define FP_R558_H_

#include <stdbool.h>
#include <stdint.h>

#include "fp_r558_config.h"

#define FP_ALL_SLOTS 0xFFFFu

typedef enum {
    FP_OK = 0,
    FP_ERR_NOT_PAIRED,     /* no trusted sensor configured */
    FP_ERR_LOCKED,         /* UV locked after failed attempts or tampering */
    FP_ERR_NO_TEMPLATE,    /* no finger enrolled */
    FP_ERR_TIMEOUT,        /* user did not place / remove a finger in time */
    FP_ERR_NO_MATCH,       /* finger unknown, or the two enrollment scans differ */
    FP_ERR_SENSOR,         /* sensor missing, wrong frame, or module reported an error */
    FP_ERR_SENSOR_AUTH,    /* module password/address check failed, treated as tampering */
    FP_ERR_FULL,           /* no free template slot */
    FP_ERR_ALREADY_PAIRED, /* a trusted sensor is still present */
    FP_ERR_NOT_FACTORY,    /* new sensor is not in factory state, reset it first */
    FP_ERR_BAD_PARAM,
    FP_ERR_STORAGE,
    FP_ERR_NOT_SECURE,       /* flash encryption required but not active (R1) */
    FP_ERR_BACKUP_FORMAT,    /* malformed backup blob */
    FP_ERR_BACKUP_MISMATCH,  /* backup does not match the connected sensor */
    FP_ERR_CANCELLED,        /* host sent CTAPHID_CANCEL during scan wait */
} fp_result_t;

/* Backup blob (R3): 1 version | 4 password | 4 address (BE) | 2 capacity (BE) | 32 slot bitmap. */
#define FP_BACKUP_HEADER 11u
#define FP_BACKUP_BYTES  43u

typedef struct {
    bool paired;
    bool locked;
    uint16_t capacity;
    uint16_t enrolled;
    uint8_t failed_attempts;
    bool supported;       /* firmware built with the R558 feature */
    bool flash_encrypted; /* ESP32 flash encryption active (R1) */
} fp_status_t;

/* Call once at boot (after the file system is scanned). Initialises UART and loads configuration. */
void fp_init(void);

/* True if a passkey request can be verified with a finger right now. Cheap, no sensor I/O. */
bool fp_uv_available(void);

/* Blocks until a finger matches, the timeout expires, or an error occurs. */
fp_result_t fp_verify(uint32_t timeout_ms);

/* Pairs a factory-fresh sensor. Requires a PIN to be set (checked by the caller). */
fp_result_t fp_pair(uint16_t *capacity_out);

/* Enrolls one finger (two scans) into the first free slot. Blocks until done or failed. */
fp_result_t fp_enroll(uint16_t *slot_out);

/* Deletes one slot, or all slots with FP_ALL_SLOTS. */
fp_result_t fp_delete(uint16_t slot);

/* Clears the lock state after failed attempts. Caller must have authenticated with the PIN. */
fp_result_t fp_unlock(void);

void fp_get_status(fp_status_t *st);

/* Backup of the trusted sensor configuration (password, address, slots). Needs a PIN token in the vendor layer. */
fp_result_t fp_backup(uint8_t out[FP_BACKUP_BYTES]);
/* Restores a backup after an authenticator reset. Checks the sensor before it is trusted. */
fp_result_t fp_restore(const uint8_t *blob, size_t len);
bool fp_is_slot_used(uint16_t slot);

/* Maps an engine result to a CTAP status code (0 = CTAP2_OK). */
int fp_result_to_ctap(fp_result_t res);

/* Runs a fingerprint verification for a CTAP request and returns a CTAP status code (0 = verified). */
int fp_uv_ctap_status(void);

/* True while the firmware is actively waiting for a finger to be placed or lifted on the R558-S. */
bool fp_is_waiting_finger(void);

/* Writes password[4] || BE32(address) to secret8 if paired; returns false if unpaired. */
bool fp_get_wrap_secret(uint8_t secret8[8]);

#endif /* FP_R558_H_ */
