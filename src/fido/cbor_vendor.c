/*
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
#include "serial.h"
#include "ctap2_cbor.h"
#include "fido.h"
#include "ctap.h"
#include "fp_r558.h"
#include "fp_led.h"
#include "hid/ctap_hid.h"
#include "files.h"
#include "credential.h"
#include "apdu.h"
#include "random.h"
#include "button.h"
#include "led/led.h"
#if defined(ESP_PLATFORM)
#include "compat/esp_compat.h"
#else
#include "compat/board.h"
#endif
#include "crypto_utils.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/chachapoly.h"
#include "mbedtls/gcm.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "mbedtls/pk.h"
#include "mbedtls/constant_time.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/x509_crt.h"

#include "fido_vault.h"

extern uint8_t keydev_dec[32];
extern bool has_keydev_dec;

mse_t mse = { .init = false };

static void mse_clear(void) {
    mbedtls_platform_zeroize(mse.Qpt, sizeof(mse.Qpt));
    mbedtls_platform_zeroize(mse.key_enc, sizeof(mse.key_enc));
    mse.init = false;
}

int mse_decrypt_ct(uint8_t *data, size_t len) {
    if (data == NULL || len < 16) {
        mse_clear();
        return -1;
    }
    mbedtls_chachapoly_context chatx;
    mbedtls_chachapoly_init(&chatx);
    mbedtls_chachapoly_setkey(&chatx, mse.key_enc + 12);
    int ret = mbedtls_chachapoly_auth_decrypt(&chatx, len - 16, mse.key_enc, mse.Qpt, 65, data + len - 16, data, data);
    mbedtls_chachapoly_free(&chatx);
    mse_clear();
    return ret;
}

/*
 * Authorises a CTAP_VENDOR_FP subcommand with the PIN token (authenticatorConfig permission).
 * Payload: 32 x 0xFF || 0x0D || subcommand || raw parameter bytes, same construction as the vault commands.
 */
static int fp_pin_auth(uint64_t protocol, const CborByteString *auth, const uint8_t *raw_params, size_t raw_params_len, uint64_t subcommand) {
    if (auth->present == false || auth->data == NULL) {
        return CTAP2_ERR_PUAT_REQUIRED;
    }
    if ((protocol != 1 && protocol != 2) || auth->len != (protocol == 1 ? 16u : 32u)) {
        return CTAP2_ERR_PIN_AUTH_INVALID;
    }
    if (!file_has_data(ef_pin)) {
        return CTAP2_ERR_PIN_NOT_SET;
    }
    if (raw_params_len > CTAP_MAX_CBOR_PAYLOAD - 34u) {
        return CTAP2_ERR_LIMIT_EXCEEDED;
    }
    uint8_t *payload = calloc(1, 34u + raw_params_len);
    if (!payload) {
        return CTAP2_ERR_PROCESSING;
    }
    memset(payload, 0xff, 32);
    payload[32] = 0x0d;
    payload[33] = (uint8_t)subcommand;
    if (raw_params_len) {
        memcpy(payload + 34, raw_params, raw_params_len);
    }
    int ret = verify((uint8_t)protocol, paut.data, payload, (uint16_t)(34u + raw_params_len), auth->data);
    free(payload);
    if (ret != 0 || !(paut.permissions & CTAP_PERMISSION_ACFG)) {
        return CTAP2_ERR_PIN_AUTH_INVALID;
    }
    return 0;
}

static int cbor_vendor_generic(uint8_t cmd, const uint8_t *data, size_t len) {
    CborParser parser;
    CborValue map;
    CborError error = CborNoError;
    CborByteString pinUvAuthParam = { 0 }, vendorParam = { 0 }, kax = { 0 }, kay = { 0 };
    size_t resp_size = 0;
    uint64_t vendorCmd = 0, pinUvAuthProtocol = 0;
    uint64_t vault_algorithm = 0;
    bool vault_algorithm_present = false;
    int64_t kty = 0, alg = 0, crv = 0;
    CborEncoder encoder, mapEncoder, mapEncoder2, arrEncoder;
    uint8_t *raw_vendor_params = NULL;
    size_t raw_vendor_params_len = 0;
    bool vault_response_handled = false;

    CBOR_CHECK(cbor_parser_init(data, len, 0, &parser, &map));
    uint64_t val_c = 1;
    CBOR_PARSE_MAP_START(map, 1)
    {
        uint64_t val_u = 0;
        CBOR_FIELD_GET_UINT(val_u, 1);
        if (val_c <= 1 && val_c != val_u) {
            CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
        }
        if (val_u < val_c) {
            CBOR_ERROR(CTAP2_ERR_INVALID_CBOR);
        }
        val_c = val_u + 1;
        if (val_u == 0x01) {
            CBOR_FIELD_GET_UINT(vendorCmd, 1);
        }
        else if (val_u == 0x02) {
            uint64_t subpara = 0;
            raw_vendor_params = (uint8_t *)cbor_value_get_next_byte(&_f1);
            CBOR_PARSE_MAP_START(_f1, 2)
            {
                CBOR_FIELD_GET_UINT(subpara, 2);
                if (subpara == 0x01) {
                    CBOR_FIELD_GET_BYTES(vendorParam, 2);
                }
                else if (subpara == 0x02) {
                    CBOR_CHECK(COSE_read_key(&_f2, &kty, &alg, &crv, &kax, &kay));
                }
                else if (subpara == 0x03) {
                    CBOR_FIELD_GET_UINT(vault_algorithm, 2);
                    vault_algorithm_present = true;
                }
                else {
                    CBOR_ADVANCE(2);
                }
            }
            CBOR_PARSE_MAP_END(_f1, 2);
            raw_vendor_params_len = cbor_value_get_next_byte(&_f1) - raw_vendor_params;
        }
        else if (val_u == 0x03) {
            CBOR_FIELD_GET_UINT(pinUvAuthProtocol, 1);
        }
        else if (val_u == 0x04) {
            CBOR_FIELD_GET_BYTES(pinUvAuthParam, 1);
        }
    }
    CBOR_PARSE_MAP_END(map, 1);
    cbor_encoder_init(&encoder, ctap_resp->init.data + 1, CTAP_MAX_CBOR_PAYLOAD, 0);

    if (cmd == CTAP_VENDOR_BACKUP) {
        if (vendorCmd == 0x01) {
            if (has_keydev_dec == false) {
                CBOR_ERROR(CTAP2_ERR_PIN_AUTH_INVALID);
            }

            CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, 1));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x01));

            CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, file_get_data(ef_keydev_enc), file_get_size(ef_keydev_enc)));
        }
        else if (vendorCmd == 0x02) {
            if (vendorParam.present == false) {
                CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
            }
            if (check_user_presence() == false) {
                CBOR_ERROR(CTAP2_ERR_OPERATION_DENIED);
            }
            uint8_t zeros[32];
            memset(zeros, 0, sizeof(zeros));
            file_put_data(ef_keydev_enc, CONST_BYTE_ARRAY(vendorParam.data, vendorParam.len));
            file_put_data(ef_keydev, CONST_BYTE_ARRAY(zeros, file_get_size(ef_keydev))); // Overwrite ef with 0
            file_put_data(ef_keydev, CONST_BYTE_ARRAY(NULL, 0)); // Set ef to 0 bytes
            flash_commit();
            goto err;
        }
        else {
            CBOR_ERROR(CTAP2_ERR_INVALID_SUBCOMMAND);
        }
    }
    else if (cmd == CTAP_VENDOR_MSE) {
        if (vendorCmd == 0x01) { // KeyAgreement
            if (mse.init) {
                mse_clear();
                CBOR_ERROR(CTAP2_ERR_NOT_ALLOWED);
            }
            if (kax.present == false || kay.present == false || alg == 0) {
                CBOR_ERROR(CTAP2_ERR_MISSING_PARAMETER);
            }

            mbedtls_ecdh_context hkey;
            mbedtls_ecdh_init(&hkey);
            mbedtls_ecdh_setup(&hkey, MBEDTLS_ECP_DP_SECP256R1);
            int ret = mbedtls_ecdh_gen_public(&hkey.ctx.mbed_ecdh.grp, &hkey.ctx.mbed_ecdh.d, &hkey.ctx.mbed_ecdh.Q, random_fill_iterator, NULL);
            mbedtls_mpi_lset(&hkey.ctx.mbed_ecdh.Qp.Z, 1);
            if (ret != 0) {
                CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
            }
            if (mbedtls_mpi_read_binary(&hkey.ctx.mbed_ecdh.Qp.X, kax.data, kax.len) != 0) {
                mbedtls_ecdh_free(&hkey);
                CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
            }
            if (mbedtls_mpi_read_binary(&hkey.ctx.mbed_ecdh.Qp.Y, kay.data, kay.len) != 0) {
                mbedtls_ecdh_free(&hkey);
                CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
            }

            uint8_t buf[MBEDTLS_ECP_MAX_BYTES];
            size_t olen = 0;
            ret = mbedtls_ecp_point_write_binary(&hkey.ctx.mbed_ecdh.grp, &hkey.ctx.mbed_ecdh.Qp, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, mse.Qpt,sizeof(mse.Qpt));
            if (ret != 0) {
                mbedtls_ecdh_free(&hkey);
                CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
            }

            ret = mbedtls_ecdh_calc_secret(&hkey, &olen, buf, MBEDTLS_ECP_MAX_BYTES, random_fill_iterator, NULL);
            if (ret != 0) {
                mbedtls_ecdh_free(&hkey);
                mbedtls_platform_zeroize(buf, sizeof(buf));
                CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
            }
            ret = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), NULL, 0, buf, olen, mse.Qpt, sizeof(mse.Qpt), mse.key_enc, sizeof(mse.key_enc));
            mbedtls_platform_zeroize(buf, sizeof(buf));
            if (ret != 0) {
                mbedtls_ecdh_free(&hkey);
                CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
            }
            mse.init = true;

            CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, 1));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x01));
            CBOR_CHECK(COSE_key_shared(&hkey, &mapEncoder, &mapEncoder2));
            mbedtls_ecdh_free(&hkey);
        }
    }
    else if (cmd == CTAP_VENDOR_UNLOCK) {
        if (mse.init == false) {
            CBOR_ERROR(CTAP2_ERR_NOT_ALLOWED);
        }
        if (vendorParam.present == false || vendorParam.len != sizeof(keydev_dec) + 16) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }

        mbedtls_chachapoly_context chatx;
        int ret = mse_decrypt_ct(vendorParam.data, vendorParam.len);
        if (ret != PICOKEYS_OK) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }

        if (!file_has_data(ef_keydev_enc)) {
            CBOR_ERROR(CTAP2_ERR_INTEGRITY_FAILURE);
        }

        uint8_t *keyenc = file_get_data(ef_keydev_enc);
        size_t keyenc_len = file_get_size(ef_keydev_enc);
        mbedtls_chachapoly_init(&chatx);
        mbedtls_chachapoly_setkey(&chatx, vendorParam.data);
        ret = mbedtls_chachapoly_auth_decrypt(&chatx, sizeof(keydev_dec), keyenc, NULL, 0, keyenc + keyenc_len - 16, keyenc + 12, keydev_dec);
        mbedtls_chachapoly_free(&chatx);
        if (ret != 0) {
            CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
        }
        has_keydev_dec = true;
        goto err;
    }
    else if (cmd == CTAP_VENDOR_EA) {
        if (vendorCmd == 0x01) {
            uint8_t buffer[1024];
            mbedtls_ecdsa_context ekey;
            mbedtls_ecdsa_init(&ekey);
            uint8_t keydev[32] = {0};
            if (load_keydev(keydev) != 0) {
                CBOR_ERROR(CTAP1_ERR_OTHER);
            }
            int ret = mbedtls_ecp_read_key(MBEDTLS_ECP_DP_SECP256R1, &ekey, keydev, 32);
            mbedtls_platform_zeroize(keydev, sizeof(keydev));
            if (ret != PICOKEYS_OK) {
                mbedtls_ecdsa_free(&ekey);
                CBOR_ERROR(CTAP2_ERR_PROCESSING);
            }
            ret = mbedtls_ecp_keypair_calc_public(&ekey, random_fill_iterator, NULL);
            if (ret != 0) {
                mbedtls_ecdsa_free(&ekey);
                CBOR_ERROR(CTAP2_ERR_PROCESSING);
            }
            mbedtls_x509write_csr ctx;
            mbedtls_x509write_csr_init(&ctx);
            snprintf((char *) buffer, sizeof(buffer), "C=ES,O=Pico Keys,OU=Authenticator Attestation,CN=Pico Fido EE Serial %s", pico_serial_str);
            mbedtls_x509write_csr_set_subject_name(&ctx, (char *) buffer);
            mbedtls_pk_context key;
            mbedtls_pk_init(&key);
            key.pk_info = mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY);
            key.pk_ctx = &ekey;
            mbedtls_x509write_csr_set_key(&ctx, &key);
            mbedtls_x509write_csr_set_md_alg(&ctx, MBEDTLS_MD_SHA256);
            mbedtls_x509write_csr_set_extension(&ctx, "\x2B\x06\x01\x04\x01\x82\xE5\x1C\x01\x01\x04", 0xB, 0, aaguid, sizeof(aaguid));
            ret = mbedtls_x509write_csr_der(&ctx, buffer, sizeof(buffer), random_fill_iterator, NULL);
            mbedtls_ecdsa_free(&ekey);
            if (ret <= 0) {
                mbedtls_x509write_csr_free(&ctx);
                CBOR_ERROR(CTAP2_ERR_PROCESSING);
            }
            CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, 1));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x01));
            CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, buffer + sizeof(buffer) - ret, ret));
        }
    }
    else if (cmd == CTAP_VENDOR_VAULT) {
        int vault_ctap_error = 0;
        CborError vault_error = vault_vendor_command(vendorCmd, vendorParam, pinUvAuthParam, pinUvAuthProtocol, raw_vendor_params, raw_vendor_params_len, vault_algorithm, vault_algorithm_present, encoder, &resp_size, &vault_response_handled, &vault_ctap_error);
        if (vault_ctap_error != 0) {
            CBOR_ERROR(vault_ctap_error);
        }
        if (vault_error != CborNoError) {
            error = vault_error;
            goto err;
        }
    }
    else if (cmd == CTAP_VENDOR_FP) {
        /*
         * Subcommands (key 1). 0x01 and 0x08 are read-only. The others need a PIN token with the
         * authenticatorConfig permission and a user presence check.
         *   0x01 status            -> {1: paired, 2: locked, 3: capacity, 4: [enrolled slots], 5: failed attempts,
         *                              6: supported (R558 feature built in), 7: flash encrypted,
         *                              8: build type ("prod" | "dev"), 9: sensor detected, 10: active UART pins}
         *   0x02 pair              -> {1: capacity}          (PIN token, needs flash encryption in "prod", R1)
         *   0x03 enroll            -> {1: slot}
         *   0x04 delete            -> key 2 param {1: slot as 2 bytes BE, 0xFFFF = all}, or no param = all
         *   0x05 unlock            -> {}
         *   0x06 backup            -> {1: bytes(43) backup blob}   (R3, plaintext: the caller must encrypt it)
         *   0x07 restore           -> key 2 param {1: bytes(43)}, {}  (R3, checks the sensor before trusting it)
         *   0x08 probe             -> live UART multi-pin scan + LED ring flash + full status map {1..10}
         * Subcommands 0x02-0x07 need a PIN token (ACFG). No button: the sensor is the only interaction.
         */
        if (vendorCmd == 0x01 || vendorCmd == 0x08 || vendorCmd == 0x09 || vendorCmd == 0x0A) {
            if (vendorCmd == 0x08) {
                fp_probe();
            }
            else if (vendorCmd == 0x09) {
                fp_result_t rres = fp_factory_reset_sensor();
                if (rres == FP_ERR_ALREADY_PAIRED) {
                    CBOR_ERROR(CTAP2_ERR_NOT_ALLOWED);
                }
            }
            else if (vendorCmd == 0x0A) {
                uint8_t unlock_pass = 0;
                if (vendorParam.present == true && vendorParam.len >= 1) {
                    unlock_pass = vendorParam.data[0];
                }
                fp_result_t ures = fp_unlock_sensor_pass(unlock_pass);
                if (ures == FP_ERR_ALREADY_PAIRED) {
                    CBOR_ERROR(CTAP2_ERR_NOT_ALLOWED);
                }
            }
            fp_status_t st;
            fp_get_status(&st);
            CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, 13));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x01));
            CBOR_CHECK(cbor_encode_boolean(&mapEncoder, st.paired));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x02));
            CBOR_CHECK(cbor_encode_boolean(&mapEncoder, st.locked));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x03));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, st.capacity));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x04));
            CBOR_CHECK(cbor_encoder_create_array(&mapEncoder, &arrEncoder, st.enrolled));
            for (uint16_t i = 0; i < st.capacity; i++) {
                if (fp_is_slot_used(i)) {
                    CBOR_CHECK(cbor_encode_uint(&arrEncoder, i));
                }
            }
            CBOR_CHECK(cbor_encoder_close_container(&mapEncoder, &arrEncoder));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x05));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, st.failed_attempts));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x06));
            CBOR_CHECK(cbor_encode_boolean(&mapEncoder, st.supported));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x07));
            CBOR_CHECK(cbor_encode_boolean(&mapEncoder, st.flash_encrypted));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x08));
            CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder, FP_REQUIRE_FLASH_ENCRYPTION ? "prod" : "dev"));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x09));
            CBOR_CHECK(cbor_encode_boolean(&mapEncoder, st.sensor_detected));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x0A));
            CBOR_CHECK(cbor_encode_text_stringz(&mapEncoder, st.sensor_pins));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x0B));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, st.last_step));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x0C));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, st.last_conf));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x0D));
            CBOR_CHECK(cbor_encode_uint(&mapEncoder, st.last_transport));
        }
        else if (vendorCmd >= 0x02 && vendorCmd <= 0x07) {
            int auth_ret = fp_pin_auth((uint8_t)pinUvAuthProtocol, &pinUvAuthParam, raw_vendor_params, raw_vendor_params_len, vendorCmd);
            if (auth_ret != 0) {
                CBOR_ERROR(auth_ret);
            }
            /* No button: the PIN token is the authorisation, the fingerprint sensor is the only user interaction. */
            fp_result_t fres = FP_OK;
            uint16_t value = 0;
            uint8_t fp_blob[FP_BACKUP_BYTES];
            if (vendorCmd == 0x02) {
                fp_led_op_begin();
                fres = fp_pair(&value);
                fp_led_op_end(fres == FP_OK);
            }
            else if (vendorCmd == 0x03) {
                fp_led_op_begin();
                fp_led_enrolling(true);
                fres = fp_enroll(&value);
                fp_led_enrolling(false);
                fp_led_op_end(fres == FP_OK);
            }
            else if (vendorCmd == 0x04) {
                uint16_t slot = FP_ALL_SLOTS;
                if (vendorParam.present == true) {
                    if (vendorParam.len != 2) {
                        CBOR_ERROR(CTAP1_ERR_INVALID_LEN);
                    }
                    slot = (uint16_t)((vendorParam.data[0] << 8) | vendorParam.data[1]);
                }
                fres = fp_delete(slot);
            }
            else if (vendorCmd == 0x05) {
                fres = fp_unlock();
            }
            else if (vendorCmd == 0x06) {
                fres = fp_backup(fp_blob);
            }
            else {
                /* 0x07 restore: the blob is the vendor parameter (key 2, sub key 1). */
                if (vendorParam.present == false) {
                    CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
                }
                fres = fp_restore(vendorParam.data, vendorParam.len);
            }
            if (fres != FP_OK) {
                mbedtls_platform_zeroize(fp_blob, sizeof(fp_blob));
                CBOR_ERROR(fp_result_to_ctap(fres));
            }
            if (vendorCmd == 0x02 || vendorCmd == 0x03 || vendorCmd == 0x05 || vendorCmd == 0x07) {
                /* PIN token authentication succeeded: ensure session_pin is sealed for cold-boot UV. */
                fp_pinwrap_seal();
            }
            if (vendorCmd == 0x02) {
                CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, 1));
                CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x01));
                CBOR_CHECK(cbor_encode_uint(&mapEncoder, value));
            }
            else if (vendorCmd == 0x03) {
                CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, 1));
                CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x01));
                CBOR_CHECK(cbor_encode_uint(&mapEncoder, value));
            }
            else if (vendorCmd == 0x06) {
                CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, 1));
                CBOR_CHECK(cbor_encode_uint(&mapEncoder, 0x01));
                CBOR_CHECK(cbor_encode_byte_string(&mapEncoder, fp_blob, sizeof(fp_blob)));
                mbedtls_platform_zeroize(fp_blob, sizeof(fp_blob));
            }
            else {
                CBOR_CHECK(cbor_encoder_create_map(&encoder, &mapEncoder, 0));
            }
        }
        else {
            CBOR_ERROR(CTAP2_ERR_INVALID_SUBCOMMAND);
        }
    }
    else {
        CBOR_ERROR(CTAP1_ERR_INVALID_PARAMETER);
    }
    if (!vault_response_handled) {
        CBOR_CHECK(cbor_encoder_close_container(&encoder, &mapEncoder));
        resp_size = cbor_encoder_get_buffer_size(&encoder, ctap_resp->init.data + 1);
    }
err:
    CBOR_FREE_BYTE_STRING(pinUvAuthParam);
    CBOR_FREE_BYTE_STRING(vendorParam);

    if (error != CborNoError) {
        if (error == CborErrorImproperValue) {
            return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        }
        return error;
    }
    res_APDU_size = (uint16_t)resp_size;
    return 0;
}

int cbor_vendor(const uint8_t *data, size_t len) {
    if (len == 0) {
        return CTAP1_ERR_INVALID_LEN;
    }
    if (data[0] >= CTAP_VENDOR_BACKUP) {
        return cbor_vendor_generic(data[0], data + 1, len - 1);
    }
    return CTAP2_ERR_INVALID_CBOR;
}
