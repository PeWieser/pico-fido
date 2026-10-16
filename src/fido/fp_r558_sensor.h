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
 *
 * Framing and instruction layer for the R558(-S) optical fingerprint module.
 * The module uses the ZFM/R30x style packet protocol:
 *
 *   Header(2)=0xEF01 | Address(4, BE) | PID(1) | Length(2, BE) | Payload | Checksum(2, BE)
 *
 * Length = len(Payload) + 2 (checksum). Checksum = sum of PID, Length and Payload bytes (mod 65536).
 * Responses use PID 0x07 and carry a confirmation code as first payload byte (0x00 = OK).
 *
 * The layer is deliberately free of firmware dependencies so it can be unit tested on a host.
 */

#ifndef FP_R558_SENSOR_H_
#define FP_R558_SENSOR_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define FP_FACTORY_ADDRESS      0xFFFFFFFFu
#define FP_PACKET_HEADER_LEN    9u     /* header + address + pid + length */
#define FP_PACKET_MAX_PAYLOAD   128u   /* generous upper bound for the R558 default of 128 bytes */

#define FP_PID_COMMAND          0x01
#define FP_PID_DATA             0x02
#define FP_PID_ACK              0x07
#define FP_PID_END_DATA         0x08

/* Instruction codes (ZFM/R558 family). */
#define FP_INS_GEN_IMG          0x01
#define FP_INS_IMG_2_TZ         0x02
#define FP_INS_SEARCH           0x04
#define FP_INS_REG_MODEL        0x05
#define FP_INS_STORE            0x06
#define FP_INS_DELET_CHAR       0x0C
#define FP_INS_EMPTY            0x0D
#define FP_INS_READ_SYS_PARA    0x0F
#define FP_INS_SET_PWD          0x12
#define FP_INS_VFY_PWD          0x13
#define FP_INS_SET_CHIP_ADDR    0x15

/* Confirmation codes. */
#define FP_CONF_OK              0x00
#define FP_CONF_PACKET_ERR      0x01
#define FP_CONF_NO_FINGER       0x02
#define FP_CONF_CAPTURE_FAIL    0x03
#define FP_CONF_IMG_MESSY       0x06
#define FP_CONF_IMG_FEW_POINTS  0x07
#define FP_CONF_NO_MATCH        0x08  /* 1:1 match failed */
#define FP_CONF_NOT_FOUND       0x09  /* search: no template found */
#define FP_CONF_COMBINE_FAIL    0x0A  /* the two scans do not belong to the same finger */
#define FP_CONF_PAGE_RANGE      0x0B
#define FP_CONF_NO_IMAGE_BUF    0x15
#define FP_CONF_FLASH_ERR       0x18
#define FP_CONF_WRONG_PWD       0x13

#define FP_BUF_1                0x01
#define FP_BUF_2                0x02

typedef struct fp_transport {
    void *ctx;
    /* Writes all bytes. Returns 0 on success, negative on error. */
    int (*write)(void *ctx, const uint8_t *data, size_t len);
    /* Reads up to len bytes, waits at most timeout_ms for the first byte. Returns bytes read (0 = timeout), negative on error. */
    int (*read)(void *ctx, uint8_t *data, size_t len, uint32_t timeout_ms);
    /* Drops pending input. May be NULL. */
    void (*flush)(void *ctx);
} fp_transport_t;

typedef enum {
    FP_SENSOR_OK = 0,
    FP_SENSOR_TIMEOUT,     /* nothing answered (absent sensor, or packets for another address) */
    FP_SENSOR_IO_ERROR,    /* transport failure */
    FP_SENSOR_BAD_FRAME,   /* wrong header, length or checksum */
    FP_SENSOR_BAD_ADDRESS  /* answer came from an unexpected address */
} fp_sensor_status_t;
/* FP_SENSOR_OK only means "valid frame received". The module's answer is in *code (0 = accepted). */

typedef struct fp_sysparam {
    uint16_t status_reg;
    uint16_t system_id;
    uint16_t capacity;
    uint16_t security_level;
    uint32_t address;
    uint16_t packet_size_code;
    uint16_t baud_multiplier;
} fp_sysparam_t;

/* Session = the address every packet is sent to, plus the module password. */
typedef struct fp_session {
    uint32_t address;
    uint8_t password[4];
} fp_session_t;

/*
 * Sends one command and waits for its acknowledge packet.
 * On a valid frame the full ack payload (confirmation code first) is copied to out.
 * If check_address is true, the ack address must equal addr.
 */
fp_sensor_status_t fp_sensor_txn(const fp_transport_t *t, uint32_t addr, uint8_t ins,
                                 const uint8_t *params, uint16_t params_len,
                                 uint8_t *out, uint16_t out_cap, uint16_t *out_len,
                                 uint8_t *code, uint32_t timeout_ms, bool check_address);

/* Encodes one packet into out. Returns number of bytes written or 0 if out is too small. */
size_t fp_sensor_encode_packet(uint8_t *out, size_t out_cap, uint32_t addr, uint8_t pid,
                               const uint8_t *payload, uint16_t payload_len);

/* Checksum over PID, length and payload as defined by the protocol. */
uint16_t fp_sensor_checksum(uint8_t pid, uint16_t length, const uint8_t *payload, uint16_t payload_len);

/* Higher level instructions. All return the sensor status; *code receives the confirmation code if present. */
fp_sensor_status_t fp_sensor_read_sysparam(const fp_transport_t *t, uint32_t addr, fp_sysparam_t *out, uint8_t *code);
fp_sensor_status_t fp_sensor_verify_password(const fp_transport_t *t, const fp_session_t *s, uint8_t *code);
fp_sensor_status_t fp_sensor_set_password(const fp_transport_t *t, uint32_t addr, const uint8_t pwd[4], uint8_t *code);
fp_sensor_status_t fp_sensor_set_chip_address(const fp_transport_t *t, uint32_t addr, uint32_t new_addr, uint8_t *code);
fp_sensor_status_t fp_sensor_gen_img(const fp_transport_t *t, const fp_session_t *s, uint8_t *code);
fp_sensor_status_t fp_sensor_img_2_tz(const fp_transport_t *t, const fp_session_t *s, uint8_t buffer, uint8_t *code);
fp_sensor_status_t fp_sensor_search(const fp_transport_t *t, const fp_session_t *s, uint8_t buffer,
                                    uint16_t start_page, uint16_t page_count,
                                    uint8_t *code, uint16_t *page_id, uint16_t *score);
fp_sensor_status_t fp_sensor_reg_model(const fp_transport_t *t, const fp_session_t *s, uint8_t *code);
fp_sensor_status_t fp_sensor_store(const fp_transport_t *t, const fp_session_t *s, uint8_t buffer, uint16_t page_id, uint8_t *code);
fp_sensor_status_t fp_sensor_delete_chars(const fp_transport_t *t, const fp_session_t *s, uint16_t page_id, uint16_t count, uint8_t *code);
fp_sensor_status_t fp_sensor_empty(const fp_transport_t *t, const fp_session_t *s, uint8_t *code);

#endif /* FP_R558_SENSOR_H_ */
