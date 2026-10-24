#!/usr/bin/env python3
"""
r558_flash_forensics.py - find a lost GROW R558-S module password in flash dumps.

Two dump types are supported:

1. ESP32-S3 full flash dump of the Pico FIDO authenticator (default mode).
   Firmware builds < 47 paired the R558-S with a RANDOM password that only existed in the
   EF_FP_CONF record of the "part0" key-storage partition. The pico-keys-sdk flash layer keeps
   journal and redo copies of whole sectors, and re-flashing the app partition never touches
   part0, so a deleted/overwritten EF_FP_CONF often still has a readable plaintext remnant in
   the dump. This tool scans for the two plaintext layouts that contain the password:
     - EF_FP_CONF payload (46 bytes) and its picokeys file record (FID 0x1104 header),
     - the 43-byte backup blob (fp_backup()).
   Create the dump with (board in download mode, see docs/fingerprint/R558_RETTUNG_ANLEITUNG.md):
     esptool --chip esp32s3 --port <PORT> read_flash 0 0x400000 esp32_dump.bin

2. R558-S module SPI-flash dump (--sensor-flash).
   The module's parameter table (128 bytes, the region PS_ReadINFpage returns) stores the
   DeviceAddress at bytes 8..11, the PassWord at bytes 60..63 (0x3C) and the ParaTableFlag
   0x1234 at bytes 126..127 (AS60x SoC manual, parameter-table definition - the GROW module
   family shares this layout). If the module has an external SPI flash that was read out with
   a clip/programmer, this mode extracts the password directly. READ-ONLY: it never writes.

Additionally:
  --mac AA:BB:CC:DD:EE:FF   recompute the build>=47 eFuse derivation for an ESP32 MAC and
                            compare with an observed chip address (--address).

Output is a ranked candidate list. A candidate is only proven when the module answers
VfyPwd (0x13) with 0x00 - use tools/r558_uart_recover.py or the web recovery page (0x0B)
to test them. Handle the output like a password: it is one.

Examples:
  python3 tools/r558_flash_forensics.py esp32_dump.bin --address 29062D09 --json candidates.json
  python3 tools/r558_flash_forensics.py --mac 24:0A:C4:12:34:56 --address 29062D09
  python3 tools/r558_flash_forensics.py --sensor-flash r558_spi.bin --address 29062D09
  python3 tools/r558_flash_forensics.py --self-test
"""

import argparse
import hashlib
import json
import struct
import sys
import tempfile
from pathlib import Path

EF_FP_CONF_LEN = 46
BACKUP_LEN = 43
KNOWN_FLAGS = 0x01 | 0x02 | 0x04 | 0x08  # PAIRED | LOCKED | STAGED | ZA_BYPASS
DOMAIN = b"pico-fido-r558-efuse-bind-v1"


def be16(b: bytes) -> int:
    return struct.unpack(">H", b)[0]


def be32(b: bytes) -> int:
    return struct.unpack(">I", b)[0]


def pwd_plausible(p: bytes) -> bool:
    return p not in (b"\x00\x00\x00\x00", b"\xff\xff\xff\xff")


def add_candidate(out, seen, password: bytes, address: int, source: str, offset: int, confidence: int):
    key = (password, address)
    entry = {
        "password_hex": password.hex().upper(),
        "address_hex": f"{address:08X}",
        "source": source,
        "offset": offset,
        "confidence": confidence,
    }
    if key in seen:
        # Keep the highest-confidence sighting of the same pair.
        for e in out:
            if e["password_hex"] == entry["password_hex"] and e["address_hex"] == entry["address_hex"]:
                if confidence > e["confidence"]:
                    e.update(entry)
                break
        return
    seen.add(key)
    out.append(entry)


def scan_esp32_dump(data: bytes, wanted_addr: int | None):
    out, seen = [], set()

    # Highest confidence: picokeys file records. Layout on ESP32 (uintptr = 4 bytes):
    #   [next:4][prev:4][fid:2 LE = 04 11][len:2 LE = 2E 00][46-byte payload]
    # The same record bytes also appear inside journal/redo sector copies.
    rec_sig = b"\x04\x11\x2e\x00"
    start = 0
    while True:
        i = data.find(rec_sig, start)
        if i < 0:
            break
        start = i + 1
        p = data[i + 4 : i + 4 + EF_FP_CONF_LEN]
        if len(p) == EF_FP_CONF_LEN and p[0] == 0x01 and p[3] == 0:
            addr, cap = be32(p[8:12]), be16(p[12:14])
            if pwd_plausible(p[4:8]) and addr != 0 and 1 <= cap <= 512:
                add_candidate(out, seen, p[4:8], addr, "esp32:file-record(EF_FP_CONF)", i + 4, 100)

    # Signature scan identical to the firmware (fp_recover_scan_image): catches payloads whose
    # record header was cleared/overwritten and raw backup blobs.
    for off in range(0, len(data) - EF_FP_CONF_LEN + 1):
        if data[off] != 0x01:
            continue
        p = data[off : off + EF_FP_CONF_LEN]
        if p[3] == 0 and p[1] != 0 and (p[1] & ~KNOWN_FLAGS) == 0:
            addr, cap = be32(p[8:12]), be16(p[12:14])
            if pwd_plausible(p[4:8]) and addr != 0 and 1 <= cap <= 512:
                add_candidate(out, seen, p[4:8], addr, "esp32:conf-signature", off, 90)
                continue
        b = data[off : off + BACKUP_LEN]
        if len(b) == BACKUP_LEN:
            addr, cap = be32(b[5:9]), be16(b[9:11])
            if pwd_plausible(b[1:5]) and addr not in (0, 0xFFFFFFFF) and 1 <= cap <= 512:
                add_candidate(out, seen, b[1:5], addr, "esp32:backup-blob", off, 85)

    # Generic address-context scan (lowest confidence): every occurrence of the observed chip
    # address with something password-shaped in front of it (both layouts share "pwd just
    # before addr"). Useful for partially overwritten remnants.
    if wanted_addr is not None:
        needle = struct.pack(">I", wanted_addr)
        start = 0
        while True:
            i = data.find(needle, start)
            if i < 0:
                break
            start = i + 1
            if i >= 4 and pwd_plausible(data[i - 4 : i]):
                add_candidate(out, seen, data[i - 4 : i], wanted_addr,
                              "esp32:address-context", i - 4, 40)

    return out


def scan_sensor_dump(data: bytes, wanted_addr: int | None):
    """Parameter table (128 bytes): DeviceAddress +8, PassWord +60 (0x3C), ParaTableFlag +126."""
    out, seen = [], set()
    table_len = 128

    def consider(base: int, source: str, confidence: int):
        if base < 0 or base + table_len > len(data):
            return
        t = data[base : base + table_len]
        flag_variants = {t[126:128]: "BE/LE?"}
        if t[126:128] not in (b"\x12\x34", b"\x34\x12"):
            confidence -= 30  # flag not where the AS60x layout predicts: weaker evidence
            source += "(flag?)"
        for label, addr_bytes, pwd_bytes in (
            ("BE", t[8:12], t[60:64]),
            ("word-swapped", t[8:12][::-1], t[60:64][::-1]),
        ):
            addr = be32(addr_bytes)
            if addr == 0:
                continue
            if wanted_addr is not None and addr != wanted_addr:
                continue
            if pwd_plausible(pwd_bytes) or pwd_bytes == b"\x00\x00\x00\x00":
                add_candidate(out, seen, pwd_bytes, addr,
                              f"sensor:parameter-table[{label}]{source}", base, confidence)
        _ = flag_variants

    if wanted_addr is not None:
        for needle in (struct.pack(">I", wanted_addr), struct.pack("<I", wanted_addr)):
            start = 0
            while True:
                i = data.find(needle, start)
                if i < 0:
                    break
                start = i + 1
                consider(i - 8, "", 95)
    # Flag-anchored scan (also covers "address unknown").
    for needle in (b"\x12\x34", b"\x34\x12"):
        start = 0
        while True:
            i = data.find(needle, start)
            if i < 0:
                break
            start = i + 1
            consider(i - 126, "(flag-anchored)", 70)
    return out


def derive_from_mac(mac: bytes):
    digest = hashlib.sha256(DOMAIN + mac).digest()
    pwd = bytearray(digest[:4])
    if pwd == bytearray(4):
        pwd[0] = 0xA5
    addr = be32(digest[4:8])
    if addr in (0, 0xFFFFFFFF):
        addr = 0x5A3CC3A5
    return bytes(pwd), addr


def parse_mac(text: str) -> bytes:
    cleaned = text.replace(":", "").replace("-", "").replace(" ", "")
    mac = bytes.fromhex(cleaned)
    if len(mac) != 6:
        raise ValueError("MAC must have 6 bytes")
    return mac


def self_test() -> int:
    print("self-test: synthetic ESP32 dump ...")
    img = bytearray(b"\xff" * 16384)

    def put_conf(dst, flags, pwd, addr, cap):
        dst[0] = 1; dst[1] = flags; dst[2] = 0; dst[3] = 0
        dst[4:8] = pwd
        dst[8:12] = struct.pack(">I", addr)
        dst[12:14] = struct.pack(">H", cap)

    # file record at 0x1000 (payload at 0x100C)
    img[0x1000:0x1008] = b"\x00" * 8
    img[0x1008:0x100C] = b"\x04\x11\x2e\x00"
    rec = bytearray(46); put_conf(rec, 0x01, bytes.fromhex("DEADBEEF"), 0x29062D09, 100)
    img[0x100C:0x100C + 46] = rec
    # bare backup blob at 0x2000
    bb = bytearray(43); bb[0] = 1; bb[1:5] = bytes.fromhex("01234567")
    bb[5:9] = struct.pack(">I", 0x0BADF00D); bb[9:11] = struct.pack(">H", 100)
    img[0x2000:0x2000 + 43] = bb

    cands = scan_esp32_dump(bytes(img), 0x29062D09)
    got = {(c["password_hex"], c["address_hex"]) for c in cands}
    assert ("DEADBEEF", "29062D09") in got, got
    assert ("01234567", "0BADF00D") in got, got
    top = sorted(cands, key=lambda c: -c["confidence"])[0]
    assert top["password_hex"] == "DEADBEEF" and top["confidence"] == 100, top

    print("self-test: synthetic sensor SPI dump ...")
    simg = bytearray(b"\xff" * 8192)
    base = 0x1000
    simg[base + 8:base + 12] = struct.pack(">I", 0x29062D09)
    simg[base + 60:base + 64] = bytes.fromhex("CAFEBABE")
    simg[base + 126:base + 128] = b"\x12\x34"
    scands = scan_sensor_dump(bytes(simg), 0x29062D09)
    assert any(c["password_hex"] == "CAFEBABE" for c in scands), scands

    print("self-test: MAC derivation vector ...")
    pwd, addr = derive_from_mac(bytes.fromhex("240AC4000001"))
    assert pwd.hex().upper() == "2F57E5E3" and addr == 0x35AB7818, (pwd.hex(), hex(addr))
    print("self-test OK")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dump", nargs="?", help="ESP32 full flash dump (or sensor SPI dump with --sensor-flash)")
    ap.add_argument("--sensor-flash", action="store_true", help="treat the dump as an R558-S SPI-flash image")
    ap.add_argument("--address", help="observed R558-S chip address, hex (e.g. 29062D09)")
    ap.add_argument("--mac", help="ESP32 eFuse MAC (AA:BB:CC:DD:EE:FF) for the build>=47 derivation check")
    ap.add_argument("--json", help="write candidates as JSON to this file (importable by the web page / UART tool)")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()

    wanted = int(args.address, 16) if args.address else None
    candidates = []

    if args.mac:
        mac = parse_mac(args.mac)
        pwd, addr = derive_from_mac(mac)
        print(f"MAC {args.mac} -> derived address {addr:08X}, password {pwd.hex().upper()} "
              f"(SHA-256 domain derivation, build >= 47)")
        if wanted is not None:
            print("  MATCH: this MAC derives exactly the observed chip address. "
                  "The derived password is a strong candidate."
                  if addr == wanted else
                  f"  NO MATCH: observed address is {wanted:08X}. This board's derivation does NOT explain "
                  "the locked module (random pairing < build 47, or paired on another board).")
        candidates.append({
            "password_hex": pwd.hex().upper(), "address_hex": f"{addr:08X}",
            "source": "mac-derivation", "offset": -1,
            "confidence": 98 if (wanted is not None and addr == wanted) else 30,
        })

    if args.dump:
        data = Path(args.dump).read_bytes()
        print(f"dump: {args.dump} ({len(data)} bytes, sha256 {hashlib.sha256(data).hexdigest()[:16]}...)")
        if args.sensor_flash:
            found = scan_sensor_dump(data, wanted)
        else:
            found = scan_esp32_dump(data, wanted)
            if len(data) >= 0x300000:
                part0 = data[0x200000:0x300000]
                ff_ratio = part0.count(0xFF) / len(part0)
                print(f"  part0 region (0x200000..0x300000): {ff_ratio:.0%} erased (0xFF)")
                if ff_ratio > 0.999:
                    print("  WARNING: part0 is fully erased - the chip was erase_flash'ed after pairing. "
                          "Only remnants outside part0 (older partition layouts) could remain.")
        candidates.extend(found)
        if not found:
            print("  no remnants found in this dump.")
            if not args.sensor_flash:
                print("  Possible reasons: flash encryption active (dump is ciphertext), chip fully "
                      "erased after pairing, or the journal/redo sectors were recycled by later writes. "
                      "Try the firmware-internal scan (web recovery 0x0B, source \"flash\") which reads "
                      "the decrypted view, or the sensor-side options in the Anleitung.")

    if not candidates and not args.dump and not args.mac:
        ap.print_help()
        return 2

    candidates.sort(key=lambda c: -c["confidence"])
    if candidates:
        print("\ncandidates (ranked; TEST each with VfyPwd - a printout alone proves nothing):")
        for c in candidates:
            off = f"@0x{c['offset']:06X}" if c["offset"] >= 0 else ""
            print(f"  [{c['confidence']:3d}] password={c['password_hex']} address={c['address_hex']} "
                  f"({c['source']} {off})")
        print("\n concatenated passwords for the web recovery page (user candidates field):")
        print("  " + "".join(c["password_hex"] for c in candidates))
        print("\nWARNING: treat this output like a password. Do not post it publicly.")

    if args.json:
        Path(args.json).write_text(json.dumps({"candidates": candidates}, indent=2) + "\n")
        print(f"wrote {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
