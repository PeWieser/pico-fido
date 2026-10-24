/*
 * Host test for the R558-S password recovery ladder (src/fido/fp_r558_recover.c).
 *
 * The simulated module behaves like a locked R558-S: once a password is set it answers every
 * instruction except VfyPwd with 0x21. The test therefore also proves that the ladder is
 * non-destructive - only 0x13 ever leaves the host.
 *
 * Build and run: tests/fingerprint/run_r558_recover_test.sh
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fp_r558_recover.h"

static int failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { printf("FAIL: %s (line %d)\n", msg, __LINE__); failures++; } else { printf("ok:   %s\n", msg); } } while (0)

/* ---------------- simulated locked R558-S ---------------- */

typedef struct {
    uint8_t rx[2048];
    size_t rx_len, rx_pos;
    uint8_t password[4];
    int password_set;
    uint32_t address;
    int silent;
    unsigned writes;
    unsigned non_vfy_writes;   /* any instruction other than VfyPwd: must stay 0 */
} sim_t;

static void sim_push(sim_t *s, const uint8_t *data, size_t n) {
    if (s->rx_len + n > sizeof(s->rx)) { printf("sim overflow\n"); exit(2); }
    memcpy(s->rx + s->rx_len, data, n);
    s->rx_len += n;
}

static void sim_handle(sim_t *s, const uint8_t *cmd, size_t n) {
    s->writes++;
    if (n < 11 || cmd[0] != 0xEF || cmd[1] != 0x01 || cmd[6] != FP_PID_COMMAND) {
        s->non_vfy_writes++;
        return;
    }
    uint32_t addr = ((uint32_t)cmd[2] << 24) | ((uint32_t)cmd[3] << 16) | ((uint32_t)cmd[4] << 8) | cmd[5];
    uint16_t len = (uint16_t)((cmd[7] << 8) | cmd[8]);
    if (n != (size_t)(9 + len)) {
        return;
    }
    uint8_t ins = cmd[9];
    const uint8_t *p = cmd + 10;
    if (ins != FP_INS_VFY_PWD) {
        s->non_vfy_writes++;
    }
    if (s->silent) {
        return;
    }
    /* The module only listens at its own address. */
    if (addr != s->address) {
        return;
    }
    uint8_t ack[8];
    if (ins == FP_INS_VFY_PWD) {
        if (s->password_set && memcmp(s->password, p, 4) != 0) {
            ack[0] = FP_CONF_WRONG_PWD;
        }
        else {
            ack[0] = FP_CONF_OK;   /* also the "no password set" case */
        }
    }
    else {
        ack[0] = 0x21;             /* everything is blocked while the password is unverified */
    }
    uint8_t pkt[32];
    size_t pl = fp_sensor_encode_packet(pkt, sizeof(pkt), addr, FP_PID_ACK, ack, 1);
    sim_push(s, pkt, pl);
}

static int sim_write(void *ctx, const uint8_t *data, size_t len) {
    sim_handle((sim_t *)ctx, data, len);
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

static void sim_init(sim_t *s, const uint8_t pwd[4], uint32_t addr) {
    memset(s, 0, sizeof(*s));
    s->address = addr;
    if (pwd != NULL) {
        memcpy(s->password, pwd, 4);
        s->password_set = 1;
    }
}

static fp_transport_t make_transport(sim_t *s) {
    fp_transport_t t = { .ctx = s, .write = sim_write, .read = sim_read, .flush = sim_flush };
    return t;
}

/* ---------------- tests ---------------- */

static void test_candidate_list(void) {
    fp_recover_candidate_t list[FP_RECOVER_MAX_CANDIDATES];
    const uint32_t addr = 0x29062D09u;
    const uint8_t pwd[4] = { 1, 2, 3, 4 };
    const uint8_t other[4] = { 5, 6, 7, 8 };

    size_t n = fp_recover_add_candidate(list, 0, FP_RECOVER_MAX_CANDIDATES, FP_RECOVER_SRC_STORED, addr, pwd);
    CHECK(n == 1, "first candidate is appended");
    n = fp_recover_add_candidate(list, n, FP_RECOVER_MAX_CANDIDATES, FP_RECOVER_SRC_DERIVED, addr, pwd);
    CHECK(n == 1, "an identical credential pair is not added twice");
    n = fp_recover_add_candidate(list, n, FP_RECOVER_MAX_CANDIDATES, FP_RECOVER_SRC_DERIVED, addr, other);
    CHECK(n == 2, "a different password at the same address is added");
    n = fp_recover_add_candidate(list, n, FP_RECOVER_MAX_CANDIDATES, FP_RECOVER_SRC_FACTORY, 0, pwd);
    CHECK(n == 2, "address 0 is rejected");

    const uint32_t addrs[2] = { addr, FP_FACTORY_ADDRESS };
    n = fp_recover_add_password_variants(list, 0, FP_RECOVER_MAX_CANDIDATES, FP_RECOVER_SRC_USER, pwd, addrs, 2);
    CHECK(n == 2, "password variants cover every address");

    n = fp_recover_add_candidate(list, FP_RECOVER_MAX_CANDIDATES, FP_RECOVER_MAX_CANDIDATES,
                                FP_RECOVER_SRC_STORED, addr, other);
    CHECK(n == FP_RECOVER_MAX_CANDIDATES, "the list never exceeds its capacity");

    CHECK(strcmp(fp_recover_source_name(FP_RECOVER_SRC_DERIVED), "derived") == 0, "source names are stable");
    CHECK(strcmp(fp_recover_source_name(FP_RECOVER_SRC_NONE), "none") == 0, "unknown source falls back to none");
}

static void test_finds_stored_at_first_position(void) {
    const uint8_t pwd[4] = { 0xDE, 0xAD, 0xBE, 0xEF };
    sim_t s;
    sim_init(&s, pwd, 0x29062D09u);
    fp_transport_t t = make_transport(&s);

    fp_recover_candidate_t list[FP_RECOVER_MAX_CANDIDATES];
    size_t n = fp_recover_add_candidate(list, 0, FP_RECOVER_MAX_CANDIDATES, FP_RECOVER_SRC_STORED,
                                        0x29062D09u, pwd);
    n = fp_recover_add_candidate(list, n, FP_RECOVER_MAX_CANDIDATES, FP_RECOVER_SRC_FACTORY,
                                 FP_FACTORY_ADDRESS, (const uint8_t[4]){ 0, 0, 0, 0 });
    fp_recover_report_t rep;
    CHECK(fp_recover_run(&t, list, n, &rep) == true, "recovery succeeds with the stored credentials");
    CHECK(rep.found && rep.source == FP_RECOVER_SRC_STORED, "report names the stored stage");
    CHECK(rep.attempts == 1, "only one VfyPwd was needed");
    CHECK(rep.address == 0x29062D09u && memcmp(rep.password, pwd, 4) == 0, "report carries the verified credentials");
    CHECK(s.non_vfy_writes == 0, "the ladder never sends anything but VfyPwd");
    CHECK(strstr(rep.summary, "src=stored") != NULL, "summary is machine readable");
}

static void test_finds_derived_after_wrong_stored(void) {
    const uint8_t derived[4] = { 0x11, 0x22, 0x33, 0x44 };
    sim_t s;
    sim_init(&s, derived, 0x5049434Fu);
    fp_transport_t t = make_transport(&s);

    fp_recover_candidate_t list[FP_RECOVER_MAX_CANDIDATES];
    size_t n = fp_recover_add_candidate(list, 0, FP_RECOVER_MAX_CANDIDATES, FP_RECOVER_SRC_STORED,
                                        0x5049434Fu, (const uint8_t[4]){ 9, 9, 9, 9 });
    n = fp_recover_add_candidate(list, n, FP_RECOVER_MAX_CANDIDATES, FP_RECOVER_SRC_DERIVED,
                                 0x5049434Fu, derived);
    fp_recover_report_t rep;
    CHECK(fp_recover_run(&t, list, n, &rep) == true, "the second stage recovers a stale configuration");
    CHECK(rep.source == FP_RECOVER_SRC_DERIVED, "report names the derived stage");
    CHECK(rep.attempts == 2, "two VfyPwd frames were sent");
}

static void test_finds_password_at_factory_address(void) {
    /* SetPwd landed, SetChipAddr did not: the password is right but it lives at 0xFFFFFFFF. */
    const uint8_t pwd[4] = { 0xAA, 0xBB, 0xCC, 0xDD };
    sim_t s;
    sim_init(&s, pwd, FP_FACTORY_ADDRESS);
    fp_transport_t t = make_transport(&s);

    fp_recover_candidate_t list[FP_RECOVER_MAX_CANDIDATES];
    size_t n = fp_recover_add_candidate(list, 0, FP_RECOVER_MAX_CANDIDATES, FP_RECOVER_SRC_STORED,
                                        0x29062D09u, pwd);
    const uint32_t addrs[2] = { 0x29062D09u, FP_FACTORY_ADDRESS };
    n = fp_recover_add_password_variants(list, n, FP_RECOVER_MAX_CANDIDATES, FP_RECOVER_SRC_DERIVED,
                                        pwd, addrs, 2);
    fp_recover_report_t rep;
    CHECK(fp_recover_run(&t, list, n, &rep) == true, "password is found at the factory address");
    CHECK(rep.address == FP_FACTORY_ADDRESS, "the answering address is reported");
}

static void test_unknown_password_is_reported(void) {
    sim_t s;
    sim_init(&s, (const uint8_t[4]){ 4, 3, 2, 1 }, 0x29062D09u);
    fp_transport_t t = make_transport(&s);

    fp_recover_candidate_t list[FP_RECOVER_MAX_CANDIDATES];
    size_t n = 0;
    for (uint8_t i = 0; i < 3; i++) {
        const uint8_t cand[4] = { 0, 0, 0, i };
        n = fp_recover_add_candidate(list, n, FP_RECOVER_MAX_CANDIDATES, FP_RECOVER_SRC_USER,
                                     0x29062D09u, cand);
    }
    fp_recover_report_t rep;
    CHECK(fp_recover_run(&t, list, n, &rep) == false, "an unknown password is reported as failure");
    CHECK(rep.sensor_present, "the sensor is alive");
    CHECK(rep.last_conf == FP_CONF_WRONG_PWD, "the module answered with 0x13");
    CHECK(rep.attempts == 3, "all candidates were tried");
    CHECK(strstr(rep.summary, "alive") != NULL, "summary distinguishes alive from silent");
}

static void test_silent_sensor(void) {
    sim_t s;
    sim_init(&s, NULL, FP_FACTORY_ADDRESS);
    s.silent = 1;
    fp_transport_t t = make_transport(&s);

    fp_recover_candidate_t list[FP_RECOVER_MAX_CANDIDATES];
    size_t n = fp_recover_add_candidate(list, 0, FP_RECOVER_MAX_CANDIDATES, FP_RECOVER_SRC_FACTORY,
                                        FP_FACTORY_ADDRESS, (const uint8_t[4]){ 0, 0, 0, 0 });
    fp_recover_report_t rep;
    CHECK(fp_recover_run(&t, list, n, &rep) == false, "a silent sensor cannot be recovered");
    CHECK(!rep.sensor_present, "no frame means the sensor is not present");
    CHECK(strstr(rep.summary, "silent") != NULL, "summary says silent");
}

static void test_bounds_and_empty(void) {
    sim_t s;
    sim_init(&s, (const uint8_t[4]){ 7, 7, 7, 7 }, 0x29062D09u);
    fp_transport_t t = make_transport(&s);
    fp_recover_report_t rep;

    CHECK(fp_recover_run(&t, NULL, 0, &rep) == false, "an empty candidate list fails cleanly");
    CHECK(strstr(rep.summary, "no candidates") != NULL, "empty list has its own summary");
    CHECK(fp_recover_run(NULL, NULL, 0, &rep) == false, "a NULL transport is rejected");

    fp_recover_candidate_t list[FP_RECOVER_MAX_CANDIDATES + 4u];
    size_t n = 0;
    for (size_t i = 0; i < FP_RECOVER_MAX_CANDIDATES + 4u; i++) {
        const uint8_t cand[4] = { 1, 2, 3, (uint8_t)i };
        list[n].source = FP_RECOVER_SRC_USER;
        list[n].address = 0x29062D09u;
        memcpy(list[n].password, cand, 4);
        n++;
    }
    CHECK(fp_recover_run(&t, list, n, &rep) == false, "an oversized list does not match");
    CHECK(rep.attempts == FP_RECOVER_MAX_CANDIDATES, "the ladder is hard bounded");
}

static void put_conf(uint8_t *dst, uint8_t flags, const uint8_t pwd[4], uint32_t addr, uint16_t cap) {
    memset(dst, 0, 46);
    dst[0] = 0x01; dst[1] = flags; dst[2] = 0; dst[3] = 0;
    memcpy(dst + 4, pwd, 4);
    dst[8] = (uint8_t)(addr >> 24); dst[9] = (uint8_t)(addr >> 16);
    dst[10] = (uint8_t)(addr >> 8); dst[11] = (uint8_t)addr;
    dst[12] = (uint8_t)(cap >> 8); dst[13] = (uint8_t)cap;
}

static void put_backup(uint8_t *dst, const uint8_t pwd[4], uint32_t addr, uint16_t cap) {
    memset(dst, 0, 43);
    dst[0] = 0x01;
    memcpy(dst + 1, pwd, 4);
    dst[5] = (uint8_t)(addr >> 24); dst[6] = (uint8_t)(addr >> 16);
    dst[7] = (uint8_t)(addr >> 8); dst[8] = (uint8_t)addr;
    dst[9] = (uint8_t)(cap >> 8); dst[10] = (uint8_t)cap;
}

static void test_scan_image_finds_remnants(void) {
    /* Synthetic "part0": erased flash (0xFF), junk, one EF_FP_CONF remnant, one backup remnant,
       one look-alike with invalid flags and one with capacity 0. Only the two real ones count. */
    static uint8_t img[8192];
    memset(img, 0xFF, sizeof(img));
    const uint8_t pwd_a[4] = { 0xDE, 0xAD, 0xBE, 0xEF };
    const uint8_t pwd_b[4] = { 0x01, 0x23, 0x45, 0x67 };
    const uint8_t pwd_x[4] = { 0x11, 0x22, 0x33, 0x44 };
    put_conf(img + 1000, 0x40, pwd_x, 0x29062D09u, 100);      /* invalid flag bit: reject */
    put_conf(img + 2000, 0x01, pwd_x, 0x29062D09u, 0);        /* capacity 0: reject */
    put_conf(img + 3000, 0x01, pwd_a, 0x29062D09u, 100);      /* valid conf remnant */
    put_backup(img + 5000, pwd_b, 0x0BADF00Du, 100);          /* valid backup remnant */
    put_conf(img + 7000, 0x05, pwd_a, 0x29062D09u, 100);      /* duplicate pair: dedup */

    fp_recover_candidate_t list[FP_RECOVER_MAX_CANDIDATES];
    size_t n = fp_recover_scan_image(img, sizeof(img), list, 0, FP_RECOVER_MAX_CANDIDATES);
    CHECK(n == 2, "flash scan: exactly the two valid remnants are found");
    if (n >= 1) {
        CHECK(list[0].source == FP_RECOVER_SRC_FLASH && list[0].address == 0x29062D09u &&
              memcmp(list[0].password, pwd_a, 4) == 0, "flash scan: conf remnant first, in image order");
    }
    if (n >= 2) {
        CHECK(list[1].source == FP_RECOVER_SRC_FLASH && list[1].address == 0x0BADF00Du &&
              memcmp(list[1].password, pwd_b, 4) == 0, "flash scan: backup remnant second");
    }
    CHECK(strcmp(fp_recover_source_name(FP_RECOVER_SRC_FLASH), "flash") == 0,
          "flash scan: source name is \"flash\"");

    /* The scanned candidate must actually unlock a module locked with the remnant password. */
    sim_t sim;
    sim_init(&sim, pwd_a, 0x29062D09u);
    fp_transport_t t = make_transport(&sim);
    fp_recover_report_t rep;
    CHECK(fp_recover_run(&t, list, n, &rep) && rep.source == FP_RECOVER_SRC_FLASH,
          "flash scan: remnant candidate verifies against the locked module");
    CHECK(sim.non_vfy_writes == 0, "flash scan: still only VfyPwd on the wire");

    /* Bounds: tiny/empty images and a full list are safe. */
    CHECK(fp_recover_scan_image(img, 10, list, 0, FP_RECOVER_MAX_CANDIDATES) == 0,
          "flash scan: image shorter than one record yields nothing");
    CHECK(fp_recover_scan_image(NULL, sizeof(img), list, 3, FP_RECOVER_MAX_CANDIDATES) == 3,
          "flash scan: NULL image is a no-op");
}

int main(void) {
    test_candidate_list();
    test_scan_image_finds_remnants();
    test_finds_stored_at_first_position();
    test_finds_derived_after_wrong_stored();
    test_finds_password_at_factory_address();
    test_unknown_password_is_reported();
    test_silent_sensor();
    test_bounds_and_empty();
    if (failures != 0) {
        printf("\n%d check(s) failed\n", failures);
        return 1;
    }
    printf("\nall recovery ladder checks passed\n");
    return 0;
}
