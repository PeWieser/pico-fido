/*
 * Host test for the R558 engine (src/fido/fp_r558.c): pairing, enrollment, verification,
 * lockout, sensor replacement, tampering and interrupted pairing.
 *
 * Flash, RNG and UART are replaced by test doubles. The simulated module follows the
 * instruction behaviour of the R558 family (see r558_sensor_test.c).
 *
 * Build and run: tests/fingerprint/run_r558_engine_test.sh
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "picokeys.h"
#include "files.h"
#include "fs/file.h"
#include "fs/flash.h"
#include "random.h"
#include "fp_r558.h"
#include "fp_r558_sensor.h"
#include "fp_r558_uart.h"

/* ---------------- test doubles: flash, rng, mbedtls ---------------- */

static uint8_t ef_buf[64];
static uint32_t ef_len = 0;
static file_t ef_dummy;
file_t *ef_fp_conf = &ef_dummy;

bool file_has_data(const file_t *f) { (void)f; return ef_len > 0; }
uint8_t *file_get_data(const file_t *f) { (void)f; return ef_buf; }
uint32_t file_get_size(const file_t *f) { (void)f; return ef_len; }
int file_put_data(file_t *f, const_byte_array_t d) {
    (void)f;
    if (d.len > sizeof(ef_buf)) { return -1; }
    memcpy(ef_buf, d.data, d.len);
    ef_len = (uint32_t)d.len;
    return PICOKEYS_OK;
}
bool flash_commit_sync(uint32_t timeout_ms) { (void)timeout_ms; return true; }
int random_fill_buffer(byte_array_t buffer) {
    for (size_t i = 0; i < buffer.len; i++) { buffer.data[i] = (uint8_t)(rand() & 0xFF); }
    return 0;
}
void mbedtls_platform_zeroize(void *buf, size_t len) { memset(buf, 0, len); }

/* ---------------- simulated module ---------------- */

#define SCHED_MAX 16
typedef struct {
    uint32_t address;
    uint8_t password[4];
    int password_set;
    int used[256];
    int templ[256];
    int buf[3];
    int last_finger;
    int sched[SCHED_MAX];   /* finger shown at each GenImg: -1 = none */
    int sched_len, sched_pos;
    int fail_set_addr;
    int present;            /* 0 = nothing answers on the bus */
    int calls_genimg;
} module_t;

static module_t mod_a, mod_b;
static module_t *active = &mod_a;

static void module_reset(module_t *m, uint32_t addr) {
    memset(m, 0, sizeof(*m));
    m->address = addr;
    m->present = 1;
}

static void sched_set(int n, ...) {
    va_list ap; va_start(ap, n);
    active->sched_len = n; active->sched_pos = 0;
    for (int i = 0; i < n; i++) { active->sched[i] = va_arg(ap, int); }
    va_end(ap);
}

static void reply(const module_t *m, uint32_t addr, uint8_t code, const uint8_t *extra, uint16_t extra_len, uint8_t *out, uint16_t *out_len) {
    (void)m; (void)addr;
    out[0] = code;
    if (extra_len) { memcpy(out + 1, extra, extra_len); }
    *out_len = (uint16_t)(1 + extra_len);
}

/* Synthesises the acknowledge for one command and places it into the rx queue of the transport. */
static uint8_t rx_pkt[256];
static size_t rx_len = 0, rx_pos = 0;

static void send_ack(uint32_t addr, const uint8_t *payload, uint16_t plen) {
    uint8_t pkt[160];
    size_t n = fp_sensor_encode_packet(pkt, sizeof(pkt), addr, FP_PID_ACK, payload, plen);
    memcpy(rx_pkt + rx_len, pkt, n);
    rx_len += n;
}

static void module_command(module_t *m, const uint8_t *cmd, size_t n) {
    if (!m->present || n < 11) { return; }
    uint32_t addr = ((uint32_t)cmd[2] << 24) | ((uint32_t)cmd[3] << 16) | ((uint32_t)cmd[4] << 8) | cmd[5];
    if (addr != m->address) { return; }                      /* packets for other addresses are ignored */
    uint16_t len = (uint16_t)((cmd[7] << 8) | cmd[8]);
    if (n != (size_t)(9 + len)) { return; }
    uint8_t ins = cmd[9];
    const uint8_t *p = cmd + 10;
    uint8_t out[40]; uint16_t ol = 0;
    switch (ins) {
        case FP_INS_READ_SYS_PARA: {
            /* status(2) sysid(2) capacity(2) security(2) address(4) packet size(2) baud(2); the confirmation code is added by reply() */
            uint8_t d[16] = { 0, 0, 0, 9, 0, 200, 0, 3, 0, 0, 0, 0, 0, 2, 0, 6 };
            d[8] = (uint8_t)(m->address >> 24); d[9] = (uint8_t)(m->address >> 16); d[10] = (uint8_t)(m->address >> 8); d[11] = (uint8_t)m->address;
            reply(m, addr, 0x00, d, 16, out, &ol); break;
        }
        case FP_INS_SET_PWD:
            memcpy(m->password, p, 4); m->password_set = 1;
            reply(m, addr, 0x00, NULL, 0, out, &ol); break;
        case FP_INS_VFY_PWD:
            if (m->password_set && memcmp(m->password, p, 4) != 0) { reply(m, addr, FP_CONF_WRONG_PWD, NULL, 0, out, &ol); }
            else { reply(m, addr, 0x00, NULL, 0, out, &ol); }
            break;
        case FP_INS_SET_CHIP_ADDR: {
            if (m->fail_set_addr) { reply(m, addr, 0x01, NULL, 0, out, &ol); break; }
            uint32_t na = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
            m->address = na;
            reply(m, na, 0x00, NULL, 0, out, &ol);
            addr = na;
            break;
        }
        case FP_INS_GEN_IMG: {
            m->calls_genimg++;
            int f = -1;
            if (active == m && m->sched_pos < m->sched_len) { f = m->sched[m->sched_pos++]; }
            if (f < 0) { reply(m, addr, FP_CONF_NO_FINGER, NULL, 0, out, &ol); }
            else { m->last_finger = f; reply(m, addr, 0x00, NULL, 0, out, &ol); }
            break;
        }
        case FP_INS_IMG_2_TZ:
            m->buf[p[0]] = m->last_finger;
            reply(m, addr, 0x00, NULL, 0, out, &ol); break;
        case FP_INS_REG_MODEL:
            reply(m, addr, m->buf[1] == m->buf[2] ? 0x00 : 0x0A, NULL, 0, out, &ol); break;
        case FP_INS_STORE: {
            uint16_t page = (uint16_t)((p[1] << 8) | p[2]);
            m->templ[page] = m->buf[p[0]]; m->used[page] = 1;
            reply(m, addr, 0x00, NULL, 0, out, &ol); break;
        }
        case FP_INS_SEARCH: {
            uint16_t start = (uint16_t)((p[1] << 8) | p[2]);
            uint16_t count = (uint16_t)((p[3] << 8) | p[4]);
            int found = -1;
            for (uint16_t i = start; i < start + count && i < 256; i++) {
                if (m->used[i] && m->templ[i] == m->buf[p[0]]) { found = i; break; }
            }
            if (found < 0) { reply(m, addr, FP_CONF_NOT_FOUND, NULL, 0, out, &ol); }
            else {
                uint8_t d[4] = { (uint8_t)(found >> 8), (uint8_t)found, 0, 100 };
                reply(m, addr, 0x00, d, 4, out, &ol);
            }
            break;
        }
        case FP_INS_DELET_CHAR: {
            uint16_t page = (uint16_t)((p[0] << 8) | p[1]);
            uint16_t count = (uint16_t)((p[2] << 8) | p[3]);
            for (uint16_t i = page; i < page + count && i < 256; i++) { m->used[i] = 0; }
            reply(m, addr, 0x00, NULL, 0, out, &ol); break;
        }
        case FP_INS_EMPTY:
            memset(m->used, 0, sizeof(m->used));
            reply(m, addr, 0x00, NULL, 0, out, &ol); break;
        case FP_INS_TEMPLATE_NUM: {
            uint16_t n = 0;
            for (int i = 0; i < 256; i++) { if (m->used[i]) { n++; } }
            uint8_t d2[2] = { (uint8_t)(n >> 8), (uint8_t)n };
            reply(m, addr, 0x00, d2, 2, out, &ol); break;
        }
        default:
            reply(m, addr, 0x01, NULL, 0, out, &ol); break;
    }
    send_ack(addr, out, ol);
}

static int t_write(void *ctx, const uint8_t *data, size_t len) {
    (void)ctx;
    rx_len = 0; rx_pos = 0;                     /* a new command replaces any unread answer */
    module_command(active, data, len);
    return 0;
}
static int t_read(void *ctx, uint8_t *data, size_t len, uint32_t timeout_ms) {
    (void)ctx; (void)timeout_ms;
    if (rx_pos >= rx_len) { return 0; }
    size_t n = rx_len - rx_pos; if (n > len) { n = len; }
    memcpy(data, rx_pkt + rx_pos, n); rx_pos += n;
    return (int)n;
}
static void t_flush(void *ctx) { (void)ctx; rx_len = rx_pos = 0; }
static const fp_transport_t transport = { .ctx = NULL, .write = t_write, .read = t_read, .flush = t_flush };

const fp_transport_t *fp_uart_transport(void) { return &transport; }
int fp_uart_init(void) { return 0; }

/* ---------------- test helpers ---------------- */

static int failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { printf("FAIL: %s (line %d)\n", msg, __LINE__); failures++; } else { printf("ok:   %s\n", msg); } } while (0)

static void reset_all(void) {
    ef_len = 0;
    memset(ef_buf, 0, sizeof(ef_buf));
    module_reset(&mod_a, FP_FACTORY_ADDRESS);
    module_reset(&mod_b, FP_FACTORY_ADDRESS);
    mod_b.present = 0;
    active = &mod_a;
    sched_set(0);
}

int main(void) {
    srand(1234);

    /* 1. Nothing configured. */
    reset_all();
    CHECK(!fp_uv_available(), "fresh device: no UV available");
    CHECK(fp_verify(200) == FP_ERR_NOT_PAIRED, "fresh device: verify refused (not paired)");

    /* 2. Absent sensor: pairing fails before anything is written. */
    reset_all(); mod_a.present = 0;
    CHECK(fp_pair(NULL) == FP_ERR_SENSOR, "pairing without a sensor fails");
    CHECK(ef_len == 0, "no state written when the sensor is absent");

    /* 3. Pairing a factory-fresh sensor. Pre-existing templates on it must be removed. */
    reset_all();
    mod_a.used[3] = 1; mod_a.templ[3] = 99;
    uint16_t cap = 0;
    CHECK(fp_pair(&cap) == FP_OK && cap == 200, "factory sensor pairs, capacity 200");
    CHECK(mod_a.address != FP_FACTORY_ADDRESS && mod_a.password_set, "module address and password were changed");
    CHECK(mod_a.used[3] == 0, "templates from before pairing were erased");
    fp_status_t st;
    fp_get_status(&st);
    CHECK(st.paired && !st.locked && st.enrolled == 0, "status: paired, not locked, nothing enrolled");
    CHECK(fp_pair(NULL) == FP_ERR_ALREADY_PAIRED, "a present trusted sensor cannot be replaced");

    /* 4. Enrollment: finger 7 scanned, lifted, scanned again. */
    sched_set(3, 7, -1, 7);
    uint16_t slot = 99;
    CHECK(fp_enroll(&slot) == FP_OK && slot == 0, "enrollment stores finger in slot 0");
    CHECK(fp_uv_available() && fp_is_slot_used(0), "UV available after enrollment");

    /* 5. Verification. */
    sched_set(1, 7);
    CHECK(fp_verify(300) == FP_OK, "enrolled finger verifies");
    sched_set(1, 9);
    CHECK(fp_verify(300) == FP_ERR_NO_MATCH, "unknown finger is rejected");
    fp_get_status(&st);
    CHECK(st.failed_attempts == 1 && !st.locked, "one failed attempt is counted, not locked");
    sched_set(0);
    CHECK(fp_verify(200) == FP_ERR_TIMEOUT, "no finger within timeout is a timeout, not a failure");
    fp_get_status(&st);
    CHECK(st.failed_attempts == 1, "timeouts do not count as failed attempts");
    sched_set(1, 7);
    CHECK(fp_verify(300) == FP_OK, "successful match resets the failure counter");
    fp_get_status(&st);
    CHECK(st.failed_attempts == 0, "failure counter reset");

    /* 6. Lockout after repeated non-matching fingers. */
    for (int i = 0; i < FP_MAX_FAILED_ATTEMPTS; i++) {
        sched_set(1, 9);
        fp_verify(300);
    }
    fp_get_status(&st);
    CHECK(st.locked, "UV locks after repeated non-matching fingers");
    sched_set(1, 7);
    CHECK(fp_verify(300) == FP_ERR_LOCKED, "locked device refuses the correct finger too");
    CHECK(!fp_uv_available(), "locked device reports UV unavailable");
    CHECK(fp_unlock() == FP_OK, "unlock (PIN checked by caller) clears the lock");
    CHECK(fp_verify(300) == FP_OK, "correct finger verifies after unlock");

    /* 7. Sensor swapped for a factory-fresh one: no UV, no tamper lock, and no silent re-pairing with the old sensor. */
    reset_all();
    fp_pair(NULL);
    sched_set(3, 7, -1, 7);
    fp_enroll(NULL);
    module_reset(&mod_b, FP_FACTORY_ADDRESS);
    active = &mod_b;                             /* the old module is physically gone */
    mod_a.present = 0;
    sched_set(1, 7);
    CHECK(fp_verify(200) == FP_ERR_SENSOR, "replacement sensor cannot verify with stored secrets");
    fp_get_status(&st);
    CHECK(!st.locked, "absent old sensor does not lock UV by itself");
    CHECK(!mod_b.password_set, "replacement sensor was not touched by verification");

    /* 8. Tampering: a module answers at our address with a different password. */
    reset_all();
    fp_pair(NULL);
    sched_set(3, 7, -1, 7);
    fp_enroll(NULL);
    mod_a.password[0] ^= 0xFF;                   /* attacker module with our address but other password */
    sched_set(1, 7);
    CHECK(fp_verify(200) == FP_ERR_SENSOR_AUTH, "wrong password at our address is detected");
    fp_get_status(&st);
    CHECK(st.locked, "tampering locks UV immediately");
    mod_a.password[0] ^= 0xFF;

    /* 9. Template the firmware did not enroll appears in the module. */
    reset_all();
    fp_pair(NULL);
    sched_set(3, 7, -1, 7);
    fp_enroll(NULL);
    mod_a.used[0] = 0;                           /* our slot disappears ... */
    mod_a.used[5] = 1; mod_a.templ[5] = 7;       /* ... and an attacker-stored template for the same finger appears */
    sched_set(1, 7);
    CHECK(fp_verify(200) == FP_ERR_SENSOR_AUTH, "template in a slot not written by this firmware is rejected");
    fp_get_status(&st);
    CHECK(st.locked, "unknown template locks UV");

    /* 10. Interrupted pairing after SetPwd: the staged secrets allow a clean resume. */
    reset_all();
    mod_a.fail_set_addr = 1;
    CHECK(fp_pair(NULL) == FP_ERR_SENSOR, "pairing interrupted at SetChipAddr");
    fp_get_status(&st);
    CHECK(!st.paired, "interrupted pairing is not reported as paired");
    mod_a.fail_set_addr = 0;
    CHECK(fp_pair(&cap) == FP_OK && cap == 200, "interrupted pairing resumes");
    CHECK(mod_a.address != FP_FACTORY_ADDRESS, "resumed pairing moved the module address");

    /* 11. Sensor with a password set by someone else (not factory fresh). */
    reset_all();
    mod_a.password_set = 1; memset(mod_a.password, 0x5A, 4);
    CHECK(fp_pair(NULL) == FP_ERR_NOT_FACTORY, "non-factory sensor is refused");
    CHECK(!fp_is_slot_used(0), "nothing enrolled on refused sensor");

    /* 12. Deleting slots. */
    reset_all();
    fp_pair(NULL);
    sched_set(3, 7, -1, 7);
    fp_enroll(NULL);
    CHECK(fp_delete(0) == FP_OK && !fp_is_slot_used(0), "single slot deleted");
    CHECK(fp_delete(0) == FP_ERR_NO_TEMPLATE, "deleting an empty slot reports no template");
    CHECK(fp_delete(300) == FP_ERR_BAD_PARAM, "slot outside capacity is refused");

    /* 13. R3 backup and restore after an authenticator reset. */
    reset_all();
    CHECK(fp_pair(&cap) == FP_OK, "backup test: pair");
    sched_set(3, 7, -1, 7);
    CHECK(fp_enroll(&slot) == FP_OK, "backup test: enroll one finger");
    uint8_t blob[FP_BACKUP_BYTES];
    CHECK(fp_backup(blob) == FP_OK && blob[0] == 1, "backup of a paired device succeeds");
    CHECK(memcmp(blob + 1, mod_a.password, 4) == 0, "backup holds the sensor password");
    CHECK(((uint32_t)blob[5] << 24 | (uint32_t)blob[6] << 16 | blob[7] << 8 | blob[8]) == mod_a.address, "backup holds the sensor address");
    uint8_t blob_saved[FP_BACKUP_BYTES];
    memcpy(blob_saved, blob, sizeof(blob));

    ef_len = 0;                                      /* authenticator reset: EF_FP_CONF is gone */
    fp_get_status(&st);
    CHECK(!st.paired, "after reset: not paired");
    CHECK(fp_restore(blob_saved, sizeof(blob_saved)) == FP_OK, "restore after reset with the same sensor succeeds");
    fp_get_status(&st);
    CHECK(st.paired && !st.locked && st.enrolled == 1, "restored: paired, not locked, one template");
    CHECK(fp_restore(blob_saved, sizeof(blob_saved)) == FP_OK, "restore of the same sensor again is a no-op");

    /* Wrong password in the blob: sensor refuses, nothing is trusted. */
    ef_len = 0;
    uint8_t bad[FP_BACKUP_BYTES];
    memcpy(bad, blob_saved, sizeof(bad));
    bad[1] ^= 0x01;
    CHECK(fp_restore(bad, sizeof(bad)) == FP_ERR_BACKUP_MISMATCH, "wrong password in backup is a mismatch");
    CHECK(ef_len == 0, "mismatched backup writes nothing");

    /* Backup says a template exists that the sensor does not have. */
    memcpy(bad, blob_saved, sizeof(bad));
    bad[FP_BACKUP_HEADER + 5] |= 0x01;               /* extra slot 40 */
    CHECK(fp_restore(bad, sizeof(bad)) == FP_ERR_BACKUP_MISMATCH, "slot count mismatch is refused");
    CHECK(ef_len == 0, "slot mismatch writes nothing");

    /* Sensor not answering: restore fails without writing. */
    mod_a.present = 0;
    CHECK(fp_restore(blob_saved, sizeof(blob_saved)) == FP_ERR_SENSOR, "absent sensor: restore fails");
    CHECK(ef_len == 0, "absent sensor writes nothing");
    mod_a.present = 1;

    /* Malformed blobs. */
    uint8_t mal[FP_BACKUP_BYTES];
    memcpy(mal, blob_saved, sizeof(mal)); mal[0] = 2;
    CHECK(fp_restore(mal, sizeof(mal)) == FP_ERR_BACKUP_FORMAT, "unknown backup version is refused");
    CHECK(fp_restore(blob_saved, FP_BACKUP_BYTES - 1) == FP_ERR_BACKUP_FORMAT, "short backup is refused");
    memcpy(mal, blob_saved, sizeof(mal)); memset(mal + 1, 0, 4);
    CHECK(fp_restore(mal, sizeof(mal)) == FP_ERR_BACKUP_FORMAT, "all-zero password is refused");
    memcpy(mal, blob_saved, sizeof(mal)); mal[5] = mal[6] = mal[7] = mal[8] = 0xFF;
    CHECK(fp_restore(mal, sizeof(mal)) == FP_ERR_BACKUP_FORMAT, "factory address is refused");
    memcpy(mal, blob_saved, sizeof(mal)); mal[FP_BACKUP_HEADER] |= 0x20;   /* slot 5 set, capacity lowered to 3 */
    mal[9] = 0; mal[10] = 3;
    CHECK(fp_restore(mal, sizeof(mal)) == FP_ERR_BACKUP_FORMAT, "slot beyond capacity is refused");
    CHECK(fp_restore(NULL, 0) == FP_ERR_BACKUP_FORMAT, "null blob is refused");

    /* Already paired: same sensor is a no-op, another sensor is refused. */
    fp_restore(blob_saved, sizeof(blob_saved));
    memcpy(bad, blob_saved, sizeof(bad)); bad[1] ^= 0x10; bad[8] ^= 0x01;
    CHECK(fp_restore(bad, sizeof(bad)) == FP_ERR_ALREADY_PAIRED, "restore over a different trusted sensor is refused");

    /* Backup needs a pairing. */
    ef_len = 0;
    CHECK(fp_backup(blob) == FP_ERR_NOT_PAIRED, "backup without a pairing is refused");

    /* Status reports flash encryption. Host builds have none. */
    fp_get_status(&st);
    CHECK(!st.flash_encrypted, "host build: flash encryption not active");

    if (failures) {
        printf("%d FAILURE(S)\n", failures);
        return 1;
    }
    printf("ALL PASSED\n");
    return 0;
}
