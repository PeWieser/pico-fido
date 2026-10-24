/*
 * r558_mac_search - offline search: was an R558-S chip address derived from an ESP32 eFuse MAC?
 *
 * Pico FIDO (ESP32-S3, build >= 47) derives the R558-S module password and chip address as
 *     digest   = SHA-256("pico-fido-r558-efuse-bind-v1" || eFuse-MAC[6])
 *     password = digest[0..3],  address = digest[4..7] (big-endian)
 * (see esp_dev_efuse_session() in src/fido/fp_r558.c).
 *
 * If a locked sensor was paired that way - on ANY ESP32 board, not just the one at hand - then the
 * pairing board's MAC is one of the ~5e9 addresses in Espressif's IEEE OUI blocks and can be found
 * offline by searching for the observed chip address at digest[4..7]. Every hit yields exactly one
 * password candidate (digest[0..3]) to try with VfyPwd (e.g. via tools/r558_uart_recover.py or the
 * web recovery page). A hit is only a CANDIDATE until the module answers VfyPwd with 0x00 - with
 * ~5e9 MACs and a 32-bit address, roughly one purely accidental hit is expected in a full search.
 *
 * If the sensor was paired with build < 47, password AND address came from the ESP32 hardware RNG
 * (see docs/fingerprint/R558_RETTUNG_ANLEITUNG.md). This search then cannot find the password; use
 * the ESP32 flash forensics (tools/r558_flash_forensics.py) instead.
 *
 * Build:  gcc -O3 -march=native -pthread -o r558_mac_search tools/r558_mac_search.c
 * Usage:  ./r558_mac_search 29062D09 [--threads N] [--oui-start I] [--oui-count N]
 * Output: one line per hit:  HIT mac=XX:XX:XX:XX:XX:XX password=XXXXXXXX address=XXXXXXXX
 *
 * The OUI table below lists the IEEE MA-L blocks assigned to Espressif (snapshot from the nmap
 * mac-prefixes database, 2026-10). Popular high-volume ESP32 OUIs are searched first.
 */
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

static const uint32_t ESPRESSIF_OUIS[] = {
    0x18FE34u, 0x240AC4u, 0x30AEA4u, 0xA4CF12u, 0x7C9EBDu, 0x246F28u,
    0xEC94CBu, 0x3C71BFu, 0x84F3EBu, 0x5CCF7Fu, 0x2CF432u, 0x94B97Eu,
    0xE868E7u, 0x08B61Fu, 0xE05A1Bu, 0x48E729u, 0xC45BBEu, 0xD8A01Du,
    0x64B708u, 0x34B472u, 0x004B12u, 0x007007u, 0x048308u, 0x04B247u,
    0x083A8Du, 0x083AF2u, 0x089272u, 0x08A6F7u, 0x08D1F9u, 0x08F9E0u,
    0x0C4EA0u, 0x0C8B95u, 0x0CB815u, 0x0CDC7Eu, 0x10003Bu, 0x10061Cu,
    0x1020BAu, 0x1051DBu, 0x10521Cu, 0x1091A8u, 0x1097BDu, 0x10B41Du,
    0x10BDA3u, 0x140808u, 0x142B2Fu, 0x14335Cu, 0x146393u, 0x14C19Fu,
    0x188B0Eu, 0x1C6920u, 0x1C8F57u, 0x1C9DC2u, 0x1CC3ABu, 0x1CDBD4u,
    0x2043A8u, 0x206EF1u, 0x209BA9u, 0x20E7C8u, 0x244CABu, 0x24587Cu,
    0x2462ABu, 0x24A160u, 0x24B2DEu, 0x24D7EBu, 0x24DCC3u, 0x24EC4Au,
    0x2805A5u, 0x28372Fu, 0x28562Fu, 0x288485u, 0x2C3AE8u, 0x2CBCBBu,
    0x3030F9u, 0x3076F5u, 0x308398u, 0x30C6F7u, 0x30C922u, 0x30EDA0u,
    0x345F45u, 0x348518u, 0x34865Du, 0x349454u, 0x34987Au, 0x34AB95u,
    0x34B7DAu, 0x34CDB0u, 0x38182Bu, 0x3844BEu, 0x3C0F02u, 0x3C6105u,
    0x3C8427u, 0x3C8A1Fu, 0x3CDC75u, 0x3CE90Eu, 0x4022D8u, 0x404CCAu,
    0x409151u, 0x40F520u, 0x441793u, 0x441BF6u, 0x441D64u, 0x4827E2u,
    0x4831B7u, 0x483FDAu, 0x485519u, 0x489D31u, 0x48CA43u, 0x48F6EEu,
    0x4C11AEu, 0x4C7525u, 0x4CC382u, 0x4CEBD6u, 0x500291u, 0x50787Du,
    0x543204u, 0x5443B2u, 0x545AA6u, 0x588C81u, 0x58BF25u, 0x58CF79u,
    0x58E6C5u, 0x5C013Bu, 0x600194u, 0x6055F9u, 0x64E833u, 0x680947u,
    0x6825DDu, 0x686725u, 0x68B6B3u, 0x68C63Au, 0x68FE71u, 0x6CB456u,
    0x6CC840u, 0x70039Fu, 0x70041Du, 0x704BCAu, 0x70AF09u, 0x70B8F6u,
    0x744DBDu, 0x781C3Cu, 0x782184u, 0x78421Cu, 0x78E36Du, 0x78EE4Cu,
    0x7C2C67u, 0x7C7398u, 0x7C87CEu, 0x7CDFA1u, 0x80646Fu, 0x806599u,
    0x807D3Au, 0x80B54Eu, 0x80F1B2u, 0x80F3DAu, 0x840D8Eu, 0x841FE8u,
    0x84CCA8u, 0x84F703u, 0x84FCE6u, 0x8813BFu, 0x8856A6u, 0x885721u,
    0x88F155u, 0x8C4B14u, 0x8C4F00u, 0x8C8C29u, 0x8C94DFu, 0x8CAAB5u,
    0x8CBFEAu, 0x8CCE4Eu, 0x8CFD49u, 0x901506u, 0x90380Cu, 0x907069u,
    0x9097D5u, 0x90E5B1u, 0x943CC6u, 0x9451DCu, 0x9454C5u, 0x94A990u,
    0x94B555u, 0x94E686u, 0x983DAEu, 0x9888E0u, 0x98A316u, 0x98CDACu,
    0x98F4ABu, 0x9C139Eu, 0x9C9C1Fu, 0x9C9E6Eu, 0xA020A6u, 0xA0764Eu,
    0xA085E3u, 0xA0A3B3u, 0xA0B765u, 0xA0DD6Cu, 0xA0F262u, 0xA47B9Du,
    0xA4CB8Fu, 0xA4E57Cu, 0xA4F00Fu, 0xA8032Au, 0xA842E3u, 0xA84674u,
    0xA848FAu, 0xAC0BFBu, 0xAC1518u, 0xAC276Eu, 0xAC67B2u, 0xACA704u,
    0xACD074u, 0xACEBE6u, 0xB08184u, 0xB0A604u, 0xB0A732u, 0xB0B21Cu,
    0xB0CBD8u, 0xB43A45u, 0xB48A0Au, 0xB4BFE9u, 0xB4E62Du, 0xB8D61Au,
    0xB8F009u, 0xB8F862u, 0xBCDDC2u, 0xBCFF4Du, 0xC049EFu, 0xC04E30u,
    0xC05D89u, 0xC0CDD6u, 0xC44F33u, 0xC4D8D5u, 0xC4DD57u, 0xC4DEE2u,
    0xC82B96u, 0xC82E18u, 0xC8C9A3u, 0xC8F09Eu, 0xCC50E3u, 0xCC7B5Cu,
    0xCC8DA2u, 0xCCBA97u, 0xCCDBA7u, 0xD0CF13u, 0xD0EF76u, 0xD48AFCu,
    0xD48C49u, 0xD4D4DAu, 0xD4E9F4u, 0xD4F98Du, 0xD8132Au, 0xD83BDAu,
    0xD885ACu, 0xD8BC38u, 0xD8BFC0u, 0xD8F15Bu, 0xDC0675u, 0xDC1ED5u,
    0xDC4F22u, 0xDC5475u, 0xDCB4D9u, 0xDCDA0Cu, 0xE072A1u, 0xE08CFEu,
    0xE09806u, 0xE0E2E6u, 0xE465B8u, 0xE4B063u, 0xE4B323u, 0xE80690u,
    0xE831CDu, 0xE83DC1u, 0xE86BEAu, 0xE89F6Du, 0xE8DB84u, 0xE8F60Au,
    0xEC6260u, 0xEC64C9u, 0xECC9FFu, 0xECDA3Bu, 0xECE334u, 0xECFABCu,
    0xF008D1u, 0xF0161Du, 0xF024F9u, 0xF09E9Eu, 0xF0F5BDu, 0xF412FAu,
    0xF42DC9u, 0xF4650Bu, 0xF4CFA2u, 0xF85B1Bu, 0xF8B3B7u, 0xFC012Cu,
    0xFCB467u, 0xFCE8C0u, 0xFCF5C4u,
};
#define NUM_OUIS (sizeof(ESPRESSIF_OUIS) / sizeof(ESPRESSIF_OUIS[0]))

/* ---------------- SHA-256 (single 64-byte block, input pre-padded by caller template) -------- */
static const uint32_t K256[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};
#define ROR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))
#define SHR(x,n) ((x) >> (n))

static void sha256_block(const uint32_t w_in[16], uint32_t out8[8]) {
    uint32_t w[64];
    memcpy(w, w_in, 16 * sizeof(uint32_t));
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROR(w[i-15],7) ^ ROR(w[i-15],18) ^ SHR(w[i-15],3);
        uint32_t s1 = ROR(w[i-2],17) ^ ROR(w[i-2],19) ^ SHR(w[i-2],10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a=0x6a09e667u,b=0xbb67ae85u,c=0x3c6ef372u,d=0xa54ff53au;
    uint32_t e=0x510e527fu,f=0x9b05688cu,g=0x1f83d9abu,h=0x5be0cd19u;
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = ROR(e,6) ^ ROR(e,11) ^ ROR(e,25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + K256[i] + w[i];
        uint32_t S0 = ROR(a,2) ^ ROR(a,13) ^ ROR(a,22);
        uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + mj;
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    out8[0]=a+0x6a09e667u; out8[1]=b+0xbb67ae85u; out8[2]=c+0x3c6ef372u; out8[3]=d+0xa54ff53au;
    out8[4]=e+0x510e527fu; out8[5]=f+0x9b05688cu; out8[6]=g+0x1f83d9abu; out8[7]=h+0x5be0cd19u;
}

/* General SHA-256 for the self-test only (short inputs < 56 bytes). */
static void sha256_short(const uint8_t *in, size_t len, uint8_t out[32]) {
    uint8_t block[64]; memset(block, 0, sizeof(block));
    memcpy(block, in, len); block[len] = 0x80;
    uint64_t bits = (uint64_t)len * 8u;
    for (int i = 0; i < 8; i++) block[63-i] = (uint8_t)(bits >> (8*i));
    uint32_t w[16];
    for (int i = 0; i < 16; i++) w[i] = ((uint32_t)block[4*i]<<24)|((uint32_t)block[4*i+1]<<16)|((uint32_t)block[4*i+2]<<8)|block[4*i+3];
    uint32_t h[8]; sha256_block(w, h);
    for (int i = 0; i < 8; i++) { out[4*i]=(uint8_t)(h[i]>>24); out[4*i+1]=(uint8_t)(h[i]>>16); out[4*i+2]=(uint8_t)(h[i]>>8); out[4*i+3]=(uint8_t)h[i]; }
}

static int self_test(void) {
    static const uint8_t exp_abc[32] = {0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad};
    uint8_t out[32]; sha256_short((const uint8_t *)"abc", 3, out);
    if (memcmp(out, exp_abc, 32) != 0) { fprintf(stderr, "SELF-TEST FAILED (sha256 'abc')\n"); return -1; }
    /* Derivation test vector, cross-checkable with tools/r558_flash_forensics.py --mac 24:0A:C4:00:00:01 */
    uint8_t msg[34]; memcpy(msg, "pico-fido-r558-efuse-bind-v1", 28);
    msg[28]=0x24; msg[29]=0x0A; msg[30]=0xC4; msg[31]=0x00; msg[32]=0x00; msg[33]=0x01;
    sha256_short(msg, 34, out);
    fprintf(stderr, "self-test ok; derivation(24:0A:C4:00:00:01) password=%02X%02X%02X%02X address=%02X%02X%02X%02X\n",
            out[0],out[1],out[2],out[3], out[4],out[5],out[6],out[7]);
    return 0;
}

/* ---------------- search ---------------- */
static _Atomic size_t next_oui;
static _Atomic unsigned long long done_hashes;
static uint32_t target_addr;
static size_t oui_start, oui_end;

static void *worker(void *arg) {
    (void)arg;
    /* Block template: W0..W6 = domain (28 bytes), W7 = MAC[0..3], W8 = MAC[4..5]||0x80||0x00,
       W9..W14 = 0, W15 = 34*8 = 272. */
    uint32_t w[16];
    static const char domain[28] = "pico-fido-r558-efuse-bind-v1";
    for (int i = 0; i < 7; i++)
        w[i] = ((uint32_t)(uint8_t)domain[4*i]<<24)|((uint32_t)(uint8_t)domain[4*i+1]<<16)|((uint32_t)(uint8_t)domain[4*i+2]<<8)|(uint8_t)domain[4*i+3];
    for (int i = 9; i < 15; i++) w[i] = 0;
    w[15] = 272u;
    uint32_t h[8];
    for (;;) {
        size_t idx = atomic_fetch_add(&next_oui, 1);
        if (idx >= oui_end) return NULL;
        uint32_t oui = ESPRESSIF_OUIS[idx];
        uint32_t b0 = (oui >> 16) & 0xFF, b1 = (oui >> 8) & 0xFF, b2 = oui & 0xFF;
        for (uint32_t sfx = 0; sfx < 0x1000000u; sfx++) {
            uint32_t b3 = (sfx >> 16) & 0xFF, b4 = (sfx >> 8) & 0xFF, b5 = sfx & 0xFF;
            w[7] = (b0<<24)|(b1<<16)|(b2<<8)|b3;
            w[8] = (b4<<24)|(b5<<16)|0x8000u;
            sha256_block(w, h);
            /* address = digest[4..7] big-endian == second output word */
            if (h[1] == target_addr) {
                printf("HIT mac=%02X:%02X:%02X:%02X:%02X:%02X password=%08X address=%08X\n",
                       b0,b1,b2,b3,b4,b5, h[0], h[1]);
                fflush(stdout);
            }
        }
        atomic_fetch_add(&done_hashes, 0x1000000ull);
    }
}

int main(int argc, char **argv) {
    if (argc < 2 || strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        fprintf(stderr, "usage: %s <chip-address-hex> [--threads N] [--oui-start I] [--oui-count N]\n"
                        "       %s --self-test\n", argv[0], argv[0]);
        return 2;
    }
    if (strcmp(argv[1], "--self-test") == 0) return self_test();
    errno = 0;
    char *end = NULL;
    unsigned long target = strtoul(argv[1], &end, 16);
    if (errno != 0 || end == argv[1] || *end != '\0') {
        fprintf(stderr, "invalid chip address '%s' (expected hex, e. g. 29062D09)\n", argv[1]);
        return 2;
    }
    if (self_test() != 0) return 1;
    target_addr = (uint32_t)target;
    int threads = 2; oui_start = 0; size_t oui_count = NUM_OUIS;
    for (int i = 2; i + 1 < argc; i += 2) {
        if (strcmp(argv[i], "--threads") == 0) threads = atoi(argv[i+1]);
        else if (strcmp(argv[i], "--oui-start") == 0) oui_start = (size_t)atol(argv[i+1]);
        else if (strcmp(argv[i], "--oui-count") == 0) oui_count = (size_t)atol(argv[i+1]);
    }
    if (threads < 1) threads = 1;
    if (threads > 64) threads = 64;
    oui_end = oui_start + oui_count; if (oui_end > NUM_OUIS) oui_end = NUM_OUIS;
    atomic_init(&next_oui, oui_start); atomic_init(&done_hashes, 0);
    fprintf(stderr, "searching address=%08X in OUIs [%zu..%zu) of %zu with %d threads (%.2f G hashes max)\n",
            target_addr, oui_start, oui_end, NUM_OUIS, threads,
            (double)(oui_end - oui_start) * 16777216.0 / 1e9);
    struct timespec t0, t1; clock_gettime(CLOCK_MONOTONIC, &t0);
    pthread_t th[64];
    for (int i = 0; i < threads; i++) pthread_create(&th[i], NULL, worker, NULL);
    /* progress reporter */
    while (atomic_load(&next_oui) < oui_end) {
        struct timespec pause_time = { .tv_sec = 15, .tv_nsec = 0 };
        nanosleep(&pause_time, NULL);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        double el = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
        unsigned long long d = atomic_load(&done_hashes);
        fprintf(stderr, "progress: %.2f G hashes, %.1f s, %.2f Mhash/s, next OUI index %zu\n",
                d / 1e9, el, el > 0 ? d / el / 1e6 : 0.0, atomic_load(&next_oui));
        fflush(stderr);
    }
    for (int i = 0; i < threads; i++) pthread_join(th[i], NULL);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double el = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
    fprintf(stderr, "done: %.2f G hashes in %.1f s (%.2f Mhash/s)\n",
            atomic_load(&done_hashes) / 1e9, el, el > 0 ? (double)atomic_load(&done_hashes) / el / 1e6 : 0.0);
    return 0;
}
