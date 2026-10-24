#!/usr/bin/env python3
"""
r558_uart_recover.py - talk to a password-locked GROW R558-S directly over a USB-TTL adapter.

This bypasses the ESP32 entirely and gives ground truth about the module itself.
Wiring (module SH1.0-6P, 3.3 V TTL - see docs/fingerprint/R558_RETTUNG_ANLEITUNG.md):
    Pin 1 VCC_3.3V  -> 3.3 V        Pin 4 UART_TX -> adapter RX
    Pin 3 VCC_MCU   -> 3.3 V        Pin 5 UART_RX -> adapter TX
    Pin 6 GND       -> GND          Pin 2 TOUCH_OUT: leave unconnected
Never connect 5 V TTL levels. Power the module only after wiring (manual section II).

What it does, in order (each step is announced; nothing writes to the module before step 4):
  1. HandShake (0x35) at the given chip address - proves wiring/address. Locked modules
     answer 0x21, unlocked ones 0x00.
  2. ReadINFpage (0x16) attempt BEFORE any VfyPwd. Some firmware revisions of this module
     family answer it even while password-locked; the 512-byte page contains the parameter
     table with the password at offset 0x3C. On strictly gated modules this returns 0x21
     and costs nothing (it is not a password guess).
  3. Tries password candidates with VfyPwd (0x13) only: built-ins, --mac derivation,
     candidates JSON from r558_flash_forensics.py, --password values. After --max-tries
     failed attempts it PAUSES and asks for a 10 s power cycle, because these modules may
     mute their UART after too many wrong passwords in one power session.
  4. Only with an explicit --normalize flag AND a typed confirmation: SetPwd(0x00000000)
     and SetChipAddr(0xFFFFFFFF), returning the module to the universal factory state that
     any host can pair again. Templates are NOT deleted by this (use Empty via the normal
     pairing flow afterwards if desired).

Requires pyserial:  pip install pyserial
Examples:
  python3 tools/r558_uart_recover.py /dev/ttyUSB0 --address 29062D09 --candidates candidates.json
  python3 tools/r558_uart_recover.py COM7 --address 29062D09 --mac 24:0A:C4:12:34:56
  python3 tools/r558_uart_recover.py /dev/ttyUSB0 --address 29062D09 --candidates c.json --normalize factory
  python3 tools/r558_uart_recover.py --self-test
"""

import argparse
import hashlib
import json
import struct
import sys
import time
from pathlib import Path

HEADER = b"\xef\x01"
PID_CMD, PID_DATA, PID_ACK, PID_END = 0x01, 0x02, 0x07, 0x08
INS = {"VfyPwd": 0x13, "SetPwd": 0x12, "SetChipAddr": 0x15, "ReadSysPara": 0x0F,
       "ReadINFpage": 0x16, "HandShake": 0x35}
DOMAIN = b"pico-fido-r558-efuse-bind-v1"
CONF_NAMES = {0x00: "OK", 0x01: "packet error", 0x13: "wrong password (VfyPwd)",
              0x21: "password verification required (locked)", 0x18: "flash error"}


def build_frame(addr: int, ins: int, params: bytes = b"") -> bytes:
    payload = bytes([ins]) + params
    length = len(payload) + 2
    csum = (PID_CMD + (length >> 8) + (length & 0xFF) + sum(payload)) & 0xFFFF
    return HEADER + struct.pack(">I", addr) + bytes([PID_CMD]) + struct.pack(">H", length) + payload + struct.pack(">H", csum)


def parse_frame(buf: bytes):
    """Return (addr, pid, payload) for the first valid frame in buf, else None."""
    i = buf.find(HEADER)
    if i < 0 or len(buf) - i < 9:
        return None
    addr = struct.unpack(">I", buf[i + 2 : i + 6])[0]
    pid = buf[i + 6]
    length = struct.unpack(">H", buf[i + 7 : i + 9])[0]
    total = 9 + length
    if len(buf) - i < total or length < 3:
        return None
    payload = buf[i + 9 : i + 9 + length - 2]
    csum = struct.unpack(">H", buf[i + 9 + length - 2 : i + total])[0]
    calc = (pid + (length >> 8) + (length & 0xFF) + sum(payload)) & 0xFFFF
    if calc != csum:
        return None
    return addr, pid, payload, i + total


class Module:
    def __init__(self, ser, address: int):
        self.ser = ser
        self.addr = address
        self._buf = bytearray()  # persistent: ACK + data packets may arrive in one read

    def _next_frame(self, deadline: float):
        """Return (addr, pid, payload) of the next valid frame, or None at the deadline."""
        while True:
            parsed = parse_frame(bytes(self._buf))
            if parsed:
                addr, pid, payload, consumed = parsed
                del self._buf[:consumed]
                return addr, pid, payload
            # A complete-looking but checksum-invalid frame must not wedge the parser.
            i = self._buf.find(HEADER)
            if i >= 0 and len(self._buf) - i >= 9:
                length = struct.unpack(">H", self._buf[i + 7 : i + 9])[0]
                if 3 <= length <= 300 and len(self._buf) - i >= 9 + length:
                    del self._buf[: i + 2]
                    continue
            if time.time() >= deadline:
                return None
            chunk = self.ser.read(256)
            if chunk:
                self._buf += chunk

    def _flush(self):
        self._buf.clear()
        self.ser.reset_input_buffer()

    def cmd(self, ins: int, params: bytes = b"", timeout: float = 1.0):
        self._flush()
        self.ser.write(build_frame(self.addr, ins, params))
        parsed = self._next_frame(time.time() + timeout)
        if not parsed:
            return None, None, b""
        addr, pid, payload = parsed
        if pid not in (PID_ACK, 0x05) or not payload:
            return addr, None, b""
        return addr, payload[0], payload

    def handshake(self):
        return self.cmd(INS["HandShake"])

    def vfy_pwd(self, pwd: bytes):
        return self.cmd(INS["VfyPwd"], pwd)

    def read_inf_page(self, timeout: float = 2.0):
        """Return (code, 512-byte page or b''). Costs no password attempt."""
        self._flush()
        self.ser.write(build_frame(self.addr, INS["ReadINFpage"]))
        parsed = self._next_frame(time.time() + timeout)
        if not parsed:
            return None, b""
        _, pid, payload = parsed
        if pid != PID_ACK or not payload or payload[0] != 0x00:
            return (payload[0] if payload else None), b""
        data = bytearray()
        deadline = time.time() + timeout + 3
        while len(data) < 512:
            p2 = self._next_frame(deadline)
            if not p2:
                break
            _, dpid, dpayload = p2
            if dpid in (PID_DATA, PID_END):
                data += dpayload
            if dpid == PID_END:
                break
        return 0x00, bytes(data[:512])

    def read_sys_para(self):
        addr, code, payload = self.cmd(INS["ReadSysPara"])
        if code != 0x00 or len(payload) < 17:
            return code, None
        return code, {
            "status": struct.unpack(">H", payload[1:3])[0],
            "system_id": struct.unpack(">H", payload[3:5])[0],
            "capacity": struct.unpack(">H", payload[5:7])[0],
            "security_level": struct.unpack(">H", payload[7:9])[0],
            "address": struct.unpack(">I", payload[9:13])[0],
        }

    def set_pwd(self, pwd: bytes):
        return self.cmd(INS["SetPwd"], pwd)

    def set_chip_addr(self, new_addr: int):
        return self.cmd(INS["SetChipAddr"], struct.pack(">I", new_addr))


def derive_from_mac(mac: bytes):
    digest = hashlib.sha256(DOMAIN + mac).digest()
    pwd = bytearray(digest[:4])
    if pwd == bytearray(4):
        pwd[0] = 0xA5
    addr = struct.unpack(">I", digest[4:8])[0]
    if addr in (0, 0xFFFFFFFF):
        addr = 0x5A3CC3A5
    return bytes(pwd), addr


def load_candidates(args, address: int):
    cands = []  # (password_bytes, address, label)

    def add(pwd: bytes, addr: int, label: str):
        if len(pwd) == 4 and (pwd, addr) not in [(p, a) for p, a, _ in cands]:
            cands.append((pwd, addr, label))

    if args.candidates:
        doc = json.loads(Path(args.candidates).read_text())
        for c in doc.get("candidates", []):
            add(bytes.fromhex(c["password_hex"]), int(c["address_hex"], 16),
                f"candidates-file[{c.get('source','?')}]")
    if args.mac:
        mac = bytes.fromhex(args.mac.replace(":", "").replace("-", ""))
        pwd, daddr = derive_from_mac(mac)
        add(pwd, daddr, "mac-derivation")
        add(pwd, address, "mac-derivation@observed-addr")
    for p in args.password or []:
        add(bytes.fromhex(p), address, "--password")
    add(b"R558", 0x5049434F, "dev-shared")
    add(b"R558", address, "dev-shared@observed-addr")
    add(b"\x00\x00\x00\x00", address, "zero@observed-addr")
    add(b"\x00\x00\x00\x00", 0xFFFFFFFF, "factory")
    add(b"\xff\xff\xff\xff", address, "0xFFFFFFFF-pwd")
    return cands


def ask_power_cycle(auto_yes: bool) -> bool:
    print("\n>>> Power-cycle break: unplug the module's 3.3 V for at least 10 seconds, "
          "reconnect it, then press Enter to continue (or Ctrl-C to stop).")
    if auto_yes:
        print(">>> (--yes given: waiting 12 s - power-cycle the module NOW if you can)")
        time.sleep(12)
        return True
    try:
        input()
    except (EOFError, KeyboardInterrupt):
        return False
    time.sleep(0.3)  # module sends 0x55 after ~50 ms boot
    return True


def run(args, ser) -> int:
    address = int(args.address, 16)
    mod = Module(ser, address)
    time.sleep(0.2)
    ser.reset_input_buffer()

    print(f"[1] HandShake at address {address:08X} ...")
    addr, code, _ = mod.handshake()
    if code is None:
        print("    NO ANSWER. Check: 3.3 V on pins 1 AND 3, GND, TX<->RX crossed, "
              "57600 baud, and that the chip address is correct (a module only answers "
              "at its own address). If the address is unknown, it cannot be discovered by "
              "scanning - take it from the ESP32 status/telemetry (last ACK address).")
        return 2
    print(f"    module answered from {addr:08X}: code 0x{code:02X} ({CONF_NAMES.get(code, '?')})")
    if addr != address:
        print(f"    note: ACK address {addr:08X} differs from --address; continuing with {addr:08X}")
        mod.addr = addr
        address = addr

    candidates = load_candidates(args, address)

    print("[2] ReadINFpage (0x16) leak attempt (not a password guess) ...")
    icode, page = mod.read_inf_page()
    if icode == 0x00 and len(page) >= 128:
        dev_addr = struct.unpack(">I", page[8:12])[0]
        pwd_be = page[60:64]
        flag = page[126:128]
        print(f"    INF page RECEIVED ({len(page)} bytes): DeviceAddress@+8 = {dev_addr:08X}, "
              f"ParaTableFlag@+126 = {flag.hex().upper()}, PassWord@+0x3C = {pwd_be.hex().upper()}")
        print("    parameter table[0:128]:")
        for i in range(0, 128, 16):
            print(f"      {i:04X}: {page[i:i+16].hex(' ').upper()}")
        candidates.insert(0, (pwd_be, address, "INFpage@0x3C"))
        candidates.insert(1, (pwd_be[::-1], address, "INFpage@0x3C(word-swapped)"))
    else:
        print(f"    gated/failed (code {icode if icode is None else f'0x{icode:02X}'}): "
              "this revision enforces the password for ReadINFpage too. Continuing.")

    print(f"[3] Trying {len(candidates)} VfyPwd candidate(s), pause every {args.max_tries} ...")
    tries = 0
    found = None
    for pwd, caddr, label in candidates:
        if tries >= args.max_tries:
            if not ask_power_cycle(args.yes):
                print("aborted by user.")
                return 3
            tries = 0
            _, hcode, _ = mod.handshake()
            print(f"    after power cycle: HandShake code "
                  f"{'timeout' if hcode is None else f'0x{hcode:02X}'}")
        old = mod.addr
        mod.addr = caddr
        _, vcode, _ = mod.vfy_pwd(pwd)
        mod.addr = old
        tries += 1
        print(f"    try {label}: addr={caddr:08X} pwd={pwd.hex().upper()} -> "
              f"{'timeout' if vcode is None else f'0x{vcode:02X}'}")
        if vcode == 0x00:
            found = (pwd, caddr, label)
            break
        time.sleep(args.delay_ms / 1000.0)

    if not found:
        print("\nNo candidate verified. The module stays exactly as locked as before "
              "(VfyPwd changes nothing). Next options: docs/fingerprint/R558_RETTUNG_ANLEITUNG.md "
              "(ESP32 flash forensics, MAC search, sensor SPI-flash readout).")
        return 4

    pwd, caddr, label = found
    mod.addr = caddr
    print(f"\n*** UNLOCKED via {label}: password={pwd.hex().upper()} @ address={caddr:08X} ***")
    print("    Write these two values down NOW (they are the module's whole identity).")
    scode, para = mod.read_sys_para()
    if para:
        print(f"    ReadSysPara: capacity={para['capacity']}, security={para['security_level']}, "
              f"address={para['address']:08X}, status=0x{para['status']:04X}")

    if args.normalize == "factory":
        print("\n[4] --normalize factory: SetPwd(00000000) + SetChipAddr(FFFFFFFF).")
        print("    Templates are kept. Afterwards ANY host can talk to the module - pair it "
              "again in Pico FIDO immediately (pairing clears templates and sets fresh "
              "deterministic credentials).")
        if not args.yes:
            typed = input("    Type NORMALIZE to proceed: ").strip()
            if typed != "NORMALIZE":
                print("    skipped (module remains at the recovered password/address above).")
                return 0
        _, c1, _ = mod.set_pwd(b"\x00\x00\x00\x00")
        print(f"    SetPwd -> {c1 if c1 is None else f'0x{c1:02X}'}")
        _, c2, _ = mod.set_chip_addr(0xFFFFFFFF)
        print(f"    SetChipAddr -> {c2 if c2 is None else f'0x{c2:02X}'}")
        print("    Power-cycle the module (10 s), then verify:")
        input("    Press Enter after the power cycle ...")
        mod.addr = 0xFFFFFFFF
        _, vc, _ = mod.vfy_pwd(b"\x00\x00\x00\x00")
        _, hc, _ = mod.handshake()
        print(f"    verify @FFFFFFFF: VfyPwd(0) -> {vc if vc is None else f'0x{vc:02X}'}, "
              f"HandShake -> {hc if hc is None else f'0x{hc:02X}'}")
        if vc == 0x00:
            print("    Module is in factory state and usable again. Next: pair in Pico FIDO, "
                  "enroll a finger, create a sensor backup (web page).")
            return 0
        print("    Verification did not confirm the factory state; the recovered "
              "password/address above remain your way in - do not lose them.")
        return 5
    print("\nThe module is usable with the credentials above. In Pico FIDO, run the web "
          "recovery (0x0B) with this password as a user candidate, or use --normalize factory "
          "here and pair from scratch.")
    return 0


# ---------------------------------------------------------------- self-test
class FakeModule:
    """In-memory locked R558-S: answers HandShake/INF/VfyPwd/SetPwd/SetChipAddr/ReadSysPara."""

    def __init__(self, pwd: bytes, addr: int, inf_open: bool):
        self.pwd, self.addr, self.inf_open = pwd, addr, inf_open
        self.verified = False
        self.rx = bytearray()

    # pyserial-ish API
    def reset_input_buffer(self):
        self.rx.clear()

    def write(self, data: bytes):
        parsed = parse_frame(data)
        if not parsed:
            return len(data)
        addr, pid, payload, _ = parsed
        if addr != self.addr or not payload:
            return len(data)  # wrong address: module stays silent
        ins, params = payload[0], payload[1:]

        def ack(code: int, extra: bytes = b"", ack_pid: int = PID_ACK):
            body = bytes([code]) + extra
            length = len(body) + 2
            csum = (ack_pid + (length >> 8) + (length & 0xFF) + sum(body)) & 0xFFFF
            self.rx += HEADER + struct.pack(">I", self.addr) + bytes([ack_pid]) + \
                struct.pack(">H", length) + body + struct.pack(">H", csum)

        def data_pkts(blob: bytes, chunk: int = 128):
            off = 0
            while off < len(blob):
                part = blob[off:off + chunk]
                off += len(part)
                dpid = PID_END if off >= len(blob) else PID_DATA
                length = len(part) + 2
                csum = (dpid + (length >> 8) + (length & 0xFF) + sum(part)) & 0xFFFF
                self.rx += HEADER + struct.pack(">I", self.addr) + bytes([dpid]) + \
                    struct.pack(">H", length) + part + struct.pack(">H", csum)

        if ins == INS["HandShake"]:
            ack(0x00 if (self.verified or self.pwd == b"\0\0\0\0") else 0x21)
        elif ins == INS["ReadINFpage"]:
            if self.inf_open or self.verified:
                page = bytearray(512)
                page[8:12] = struct.pack(">I", self.addr)
                page[60:64] = self.pwd
                page[126:128] = b"\x12\x34"
                ack(0x00)
                data_pkts(bytes(page))
            else:
                ack(0x21)
        elif ins == INS["VfyPwd"]:
            if params[:4] == self.pwd:
                self.verified = True
                ack(0x00)
            else:
                ack(0x13)
        elif not self.verified:
            ack(0x21)
        elif ins == INS["ReadSysPara"]:
            extra = struct.pack(">HHHHIHH", 4, 0, 100, 3, self.addr, 2, 6)
            ack(0x00, extra)
        elif ins == INS["SetPwd"]:
            self.pwd = params[:4]
            ack(0x00)
        elif ins == INS["SetChipAddr"]:
            self.addr = struct.unpack(">I", params[:4])[0]
            self.verified = False
            ack(0x00)
        else:
            ack(0x01)
        return len(data)

    def read(self, n: int):
        if not self.rx:
            time.sleep(0.01)
            return b""
        out = bytes(self.rx[:n])
        del self.rx[:n]
        return out


def self_test() -> int:
    class A:  # minimal args
        address = "29062D09"; candidates = None; mac = None; password = ["DEADBEEF"]
        max_tries = 12; delay_ms = 0; yes = True; normalize = "none"

    print("self-test 1: gated INF, password candidate unlocks ...")
    fake = FakeModule(bytes.fromhex("DEADBEEF"), 0x29062D09, inf_open=False)
    assert run(A(), fake) == 0

    print("\nself-test 2: open INF leaks the password ...")
    fake2 = FakeModule(bytes.fromhex("12345678"), 0x29062D09, inf_open=True)
    assert run(A(), fake2) == 0

    print("\nself-test 3: wrong candidates stay locked ...")
    fake3 = FakeModule(bytes.fromhex("99AABBCC"), 0x29062D09, inf_open=False)
    assert run(A(), fake3) == 4

    print("\nself-test 4: wrong address -> silence is reported ...")
    fake4 = FakeModule(bytes.fromhex("DEADBEEF"), 0x11111111, inf_open=False)
    assert run(A(), fake4) == 2
    print("\nself-test OK")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("port", nargs="?", help="serial port, e.g. /dev/ttyUSB0 or COM7")
    ap.add_argument("--address", required=False, help="module chip address, hex (e.g. 29062D09)")
    ap.add_argument("--baud", type=int, default=57600)
    ap.add_argument("--candidates", help="candidates JSON from r558_flash_forensics.py")
    ap.add_argument("--mac", help="ESP32 MAC for the build>=47 derivation candidate")
    ap.add_argument("--password", action="append", help="extra 4-byte password candidate, hex (repeatable)")
    ap.add_argument("--max-tries", type=int, default=12, help="VfyPwd attempts before a power-cycle pause (default 12)")
    ap.add_argument("--delay-ms", type=int, default=120)
    ap.add_argument("--normalize", choices=["none", "factory"], default="none",
                    help="after unlocking: reset module password/address to factory values")
    ap.add_argument("--yes", action="store_true", help="skip typed confirmations (scripted use)")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()
    if not args.port or not args.address:
        ap.print_help()
        return 2
    try:
        import serial
    except ImportError:
        print("pyserial fehlt:  pip install pyserial", file=sys.stderr)
        return 2
    with serial.Serial(args.port, args.baud, timeout=0.2,
                       bytesize=serial.EIGHTBITS, parity=serial.PARITY_NONE,
                       stopbits=serial.STOPBITS_TWO) as ser:
        return run(args, ser)


if __name__ == "__main__":
    sys.exit(main())
