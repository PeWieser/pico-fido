/*
 * Host test for the R558 UART packet layer (src/fido/fp_r558_sensor.c).
 * Runs against a simulated module that implements the instructions used by the firmware.
 *
 * Build and run: tests/fingerprint/run_r558_sensor_test.sh
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fp_r558_sensor.h"

static int failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { printf("FAIL: %s (line %d)\n", msg, __LINE__); failures++; } else { printf("ok:   %s\n", msg); } } while (0)

/* ---------------- simulated R558 ---------------- */

typedef struct {
    uint8_t rx[4096];
    size_t rx_len, rx_pos;
    uint8_t password[4];
    int password_set;
    uint32_t address;
    uint32_t sim_addr_default;
    int templates[256];
    int tx_corrupt_checksum;   /* 1 = corrupt the next ack checksum */
    int tx_junk_prefix;        /* 1 = prepend junk bytes incl. a lone 0xEF to the next ack */
    int tx_wrong_address;      /* 1 = answer the next command from another address */
    int silent;                /* 1 = ignore all commands */
    uint8_t last_ins;
    int writes;
} sim_t;

static void sim_push(sim_t *s, const uint8_t *data, size_t n) {
    if (s->rx_len + n > sizeof(s->rx)) { printf("sim overflow\n"); exit(2); }
    memcpy(s->rx + s->rx_len, data, n);
    s->rx_len += n;
}

static void sim_ack(sim_t *s, uint32_t addr, const uint8_t *payload, uint16_t plen) {
    uint8_t pkt[64];
    size_t n = fp_sensor_encode_packet(pkt, sizeof(pkt), addr, FP_PID_ACK, payload, plen);
    if (s->tx_corrupt_checksum) {
        pkt[n - 1] ^= 0x55;
        s->tx_corrupt_checksum = 0;
    }
    if (s->tx_junk_prefix) {
        const uint8_t junk[] = { 0x00, 0xAA, 0xEF, 0x77, 0xEF };
        sim_push(s, junk, sizeof(junk));
        s->tx_junk_prefix = 0;
    }
    sim_push(s, pkt, n);
}

/* Sim receives one full command written by the firmware. */
static void sim_handle(sim_t *s, const uint8_t *cmd, size_t n) {
    s->writes++;
    if (n < 11 || cmd[0] != 0xEF || cmd[1] != 0x01 || cmd[6] != FP_PID_COMMAND) { return; }
    uint32_t addr = ((uint32_t)cmd[2] << 24) | ((uint32_t)cmd[3] << 16) | ((uint32_t)cmd[4] << 8) | cmd[5];
    uint16_t len = (uint16_t)((cmd[7] << 8) | cmd[8]);
    if (n != (size_t)(9 + len)) { return; }
    uint8_t ins = cmd[9];
    const uint8_t *p = cmd + 10;
    uint16_t plen = (uint16_t)(len - 3);
    s->last_ins = ins;
    if (s->silent) { return; }
    uint32_t cur = s->address;
    if (addr != cur && !(ins == FP_INS_READ_SYS_PARA || ins == FP_INS_SET_PWD || ins == FP_INS_VFY_PWD || ins == FP_INS_SET_CHIP_ADDR) ) { return; }
    /* Before any password is set, only the factory address is served. */
    if (addr != cur && addr != FP_FACTORY_ADDRESS) { return; }
    if (addr == FP_FACTORY_ADDRESS && cur != FP_FACTORY_ADDRESS && ins != FP_INS_VFY_PWD) { return; }
    uint32_t reply_addr = s->tx_wrong_address ? 0x12345678u : addr;
    s->tx_wrong_address = 0;
    uint8_t out[32]; uint16_t ol = 0;
    switch (ins) {
        case FP_INS_READ_SYS_PARA:
            memset(out, 0, sizeof(out));
            out[0] = 0x00;
            out[1] = 0x00; out[2] = 0x00; /* status */
            out[3] = 0x00; out[4] = 0x09; /* system id */
            out[5] = 0x00; out[6] = 0xC8; /* capacity 200 */
            out[7] = 0x00; out[8] = 0x03; /* security */
            out[9] = (uint8_t)(cur >> 24); out[10] = (uint8_t)(cur >> 16); out[11] = (uint8_t)(cur >> 8); out[12] = (uint8_t)cur;
            out[13] = 0x00; out[14] = 0x02; out[15] = 0x00; out[16] = 0x06;
            ol = 17;
            sim_ack(s, reply_addr, out, ol);
            return;
        case FP_INS_SET_PWD:
            if (s->password_set && memcmp(s->password, p, 4) != 0) { out[0] = 0x13; sim_ack(s, reply_addr, out, 1); return; }
            memcpy(s->password, p, 4); s->password_set = 1;
            out[0] = 0x00; sim_ack(s, reply_addr, out, 1); return;
        case FP_INS_VFY_PWD:
            if (s->password_set) {
                if (memcmp(s->password, p, 4) != 0) { out[0] = FP_CONF_WRONG_PWD; sim_ack(s, reply_addr, out, 1); return; }
            }
            out[0] = 0x00; sim_ack(s, reply_addr, out, 1); return;
        case FP_INS_SET_CHIP_ADDR:
            s->address = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
            out[0] = 0x00; sim_ack(s, s->address, out, 1); return;
        case FP_INS_GEN_IMG:
            out[0] = 0x02; sim_ack(s, reply_addr, out, 1); return; /* no finger */
        case FP_INS_SEARCH: {
            out[0] = 0x09; sim_ack(s, reply_addr, out, 1); return; /* not found */
        }
        case FP_INS_EMPTY:
            memset(s->templates, 0, sizeof(s->templates));
            out[0] = 0x00; sim_ack(s, reply_addr, out, 1); return;
        default:
            (void)plen;
            out[0] = 0x01; sim_ack(s, reply_addr, out, 1); return;
    }
}

/* Transport: firmware writes go into the sim, reads come from the sim's rx buffer. */
static int sim_write(void *ctx, const uint8_t *data, size_t len) {
    sim_t *s = (sim_t *)ctx;
    sim_handle(s, data, len);
    return 0;
}
static int sim_read(void *ctx, uint8_t *data, size_t len, uint32_t timeout_ms) {
    sim_t *s = (sim_t *)ctx;
    (void)timeout_ms;
    if (s->rx_pos >= s->rx_len) { return 0; }
    size_t n = s->rx_len - s->rx_pos;
    if (n > len) { n = len; }
    memcpy(data, s->rx + s->rx_pos, n);
    s->rx_pos += n;
    if (s->rx_pos == s->rx_len) { s->rx_pos = s->rx_len = 0; }
    return (int)n;
}
static void sim_flush(void *ctx) {
    sim_t *s = (sim_t *)ctx;
    s->rx_pos = s->rx_len = 0;
}

static fp_transport_t make_transport(sim_t *s) {
    fp_transport_t t = { .ctx = s, .write = sim_write, .read = sim_read, .flush = sim_flush };
    return t;
}

static void sim_init(sim_t *s) {
    memset(s, 0, sizeof(*s));
    s->address = FP_FACTORY_ADDRESS;
}

/* ---------------- tests ---------------- */

static void test_encoding(void) {
    /* VfyPwd with default password, factory address: EF01 FFFFFFFF 01 0007 13 00000000 001B */
    uint8_t expect[] = { 0xEF, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x00, 0x07, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1B };
    uint8_t pkt[32] = { 0 };
    uint8_t pw[4] = { 0, 0, 0, 0 };
    size_t n = fp_sensor_encode_packet(pkt, sizeof(pkt), FP_FACTORY_ADDRESS, FP_PID_COMMAND, (uint8_t[]){ FP_INS_VFY_PWD, 0, 0, 0, 0 }, 5);
    CHECK(n == sizeof(expect) && memcmp(pkt, expect, sizeof(expect)) == 0, "VfyPwd packet matches the datasheet layout");
    (void)pw;
    CHECK(fp_sensor_encode_packet(pkt, 10, FP_FACTORY_ADDRESS, FP_PID_COMMAND, NULL, 0) == 0, "encoder rejects a too small buffer");
    CHECK(fp_sensor_checksum(0x01, 0x0003, (uint8_t[]){0x0F}, 1) == 0x0013, "checksum over pid, length, payload (1+0+3+15)");
}

static void test_session(void) {
    sim_t s; sim_init(&s);
    fp_transport_t t = make_transport(&s);

    fp_sysparam_t sp; uint8_t code = 0xFF;
    fp_sensor_status_t st = fp_sensor_read_sysparam(&t, FP_FACTORY_ADDRESS, &sp, &code);
    CHECK(st == FP_SENSOR_OK && code == 0 && sp.capacity == 200 && sp.address == FP_FACTORY_ADDRESS, "ReadSysPara at factory address");

    uint8_t pwd[4] = { 0x12, 0x34, 0x56, 0x78 };
    st = fp_sensor_set_password(&t, FP_FACTORY_ADDRESS, pwd, &code);
    CHECK(st == FP_SENSOR_OK && code == 0, "SetPwd accepted");

    fp_session_t fs = { .address = FP_FACTORY_ADDRESS };
    memcpy(fs.password, pwd, 4);
    st = fp_sensor_verify_password(&t, &fs, &code);
    CHECK(st == FP_SENSOR_OK && code == 0, "VfyPwd with new password");

    st = fp_sensor_set_chip_address(&t, FP_FACTORY_ADDRESS, 0xA1B2C3D4u, &code);
    CHECK(st == FP_SENSOR_OK && code == 0 && s.address == 0xA1B2C3D4u, "SetChipAddr changes the module address");

    fp_session_t ns = { .address = 0xA1B2C3D4u };
    memcpy(ns.password, pwd, 4);
    st = fp_sensor_read_sysparam(&t, 0xA1B2C3D4u, &sp, &code);
    CHECK(st == FP_SENSOR_OK && sp.address == 0xA1B2C3D4u, "ReadSysPara at new address");

    st = fp_sensor_verify_password(&t, &ns, &code);
    CHECK(st == FP_SENSOR_OK && code == 0, "VfyPwd at new address");

    fp_session_t wrong = ns;
    wrong.password[0] ^= 0xFF;
    st = fp_sensor_verify_password(&t, &wrong, &code);
    CHECK(st == FP_SENSOR_OK && code == FP_CONF_WRONG_PWD, "wrong password is reported with confirmation 0x13");

    st = fp_sensor_gen_img(&t, &ns, &code);
    CHECK(st == FP_SENSOR_OK && code == FP_CONF_NO_FINGER, "GenImg without finger returns 0x02");

    uint16_t page = 0xFFFF, score = 0;
    st = fp_sensor_search(&t, &ns, FP_BUF_1, 0, 200, &code, &page, &score);
    CHECK(st == FP_SENSOR_OK && code == FP_CONF_NOT_FOUND, "Search reports not found (0x09)");

    st = fp_sensor_empty(&t, &ns, &code);
    CHECK(st == FP_SENSOR_OK && code == 0, "Empty accepted");
}

static void test_wire_faults(void) {
    sim_t s; sim_init(&s);
    fp_transport_t t = make_transport(&s);
    fp_session_t f = { .address = FP_FACTORY_ADDRESS };
    uint8_t code = 0xFF;

    s.tx_junk_prefix = 1;
    fp_sensor_status_t st = fp_sensor_verify_password(&t, &f, &code);
    CHECK(st == FP_SENSOR_OK && code == 0, "junk bytes and a lone 0xEF before the header are skipped");

    s.tx_corrupt_checksum = 1;
    st = fp_sensor_verify_password(&t, &f, &code);
    CHECK(st == FP_SENSOR_BAD_FRAME, "corrupted checksum is rejected");

    fp_sensor_clear_last_ack();
    s.tx_wrong_address = 1;
    st = fp_sensor_txn(&t, FP_FACTORY_ADDRESS, FP_INS_GEN_IMG, NULL, 0, NULL, 0, NULL, &code, 100, true);
    CHECK(st == FP_SENSOR_BAD_ADDRESS, "ack from a different address is rejected when checked");
    CHECK(fp_sensor_has_last_ack() && fp_sensor_last_ack_addr() != FP_FACTORY_ADDRESS,
          "self-reported module ChipAddr is captured before address rejection");

    s.silent = 1;
    st = fp_sensor_verify_password(&t, &f, &code);
    CHECK(st == FP_SENSOR_TIMEOUT, "silent module results in timeout (absent sensor)");
    s.silent = 0;

    uint8_t big[200] = { 0 };
    st = fp_sensor_txn(&t, FP_FACTORY_ADDRESS, FP_INS_VFY_PWD, big, sizeof(big), NULL, 0, NULL, &code, 100, true);
    CHECK(st == FP_SENSOR_IO_ERROR, "oversized parameter block is refused before sending");
}

static void test_wrong_device_address(void) {
    /* A replacement sensor has the factory address. Our stored address must not answer it. */
    sim_t s; sim_init(&s);
    fp_transport_t t = make_transport(&s);
    fp_session_t stored = { .address = 0x00C0FFEEu };
    memset(stored.password, 0x42, 4);
    uint8_t code = 0xFF;
    fp_sensor_status_t st = fp_sensor_verify_password(&t, &stored, &code);
    CHECK(st == FP_SENSOR_TIMEOUT, "factory sensor does not answer on a foreign stored address");
}

typedef struct { const uint8_t *buf; size_t len; size_t off; } raw_rx_t;
static int raw_write_cb(void *ctx, const uint8_t *d, size_t l) { (void)ctx; (void)d; (void)l; return 0; }
static int raw_read_cb(void *ctx, uint8_t *d, size_t l, uint32_t ms) {
    (void)ms;
    raw_rx_t *r = (raw_rx_t *)ctx;
    if (r->off >= r->len) return 0;
    size_t take = r->len - r->off < l ? r->len - r->off : l;
    memcpy(d, r->buf + r->off, take);
    r->off += take;
    return (int)take;
}

static void test_ack_addr_override(void) {
    /* Build 60: when R558-S answers 0xFFFFFFFF with its internal ChipAddr in the 0xEF01 ACK header,
     * strict mode returns FP_SENSOR_BAD_ADDRESS while recording last_ack_addr, and relaxed mode accepts it. */
    uint8_t reply[32];
    const uint8_t body[1] = { FP_CONF_WRONG_PWD };
    size_t n = fp_sensor_encode_packet(reply, sizeof(reply), 0xA1B2C3D4u, FP_PID_ACK, body, sizeof(body));
    CHECK(n > 0, "encoded foreign-addr ACK");

    raw_rx_t rx = { .buf = reply, .len = n, .off = 0 };
    fp_transport_t t = { .ctx = &rx, .write = raw_write_cb, .read = raw_read_cb, .flush = NULL };

    fp_sensor_clear_last_ack();
    fp_sensor_set_accept_any_ack_addr(false);
    fp_session_t fac = { .address = FP_FACTORY_ADDRESS, .password = { 0, 0, 0, 0 } };
    uint8_t code = 0xFF;
    fp_sensor_status_t st = fp_sensor_verify_password(&t, &fac, &code);
    CHECK(st == FP_SENSOR_BAD_ADDRESS, "strict check rejects mismatched ACK address");
    CHECK(fp_sensor_has_last_ack() && fp_sensor_last_ack_addr() == 0xA1B2C3D4u, "captures real sensor ChipAddr");
    CHECK(fp_sensor_last_ack_conf() == FP_CONF_WRONG_PWD, "captures confirmation code before address check");

    rx.off = 0;
    fp_sensor_set_accept_any_ack_addr(true);
    st = fp_sensor_verify_password(&t, &fac, &code);
    CHECK(st == FP_SENSOR_OK && code == FP_CONF_WRONG_PWD, "relaxed mode accepts ACK from foreign ChipAddr");
    fp_sensor_set_accept_any_ack_addr(false);
}

int main(void) {
    test_encoding();
    test_session();
    test_wire_faults();
    test_wrong_device_address();
    test_ack_addr_override();
    if (failures) {
        printf("%d FAILURE(S)\n", failures);
        return 1;
    }
    printf("ALL PASSED\n");
    return 0;
}
