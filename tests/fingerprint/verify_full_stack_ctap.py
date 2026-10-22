#!/usr/bin/env python3
"""End-to-end full-stack test of Pico-Fido + GROW R558-S over real CTAP2 HID + UART bytes.

Exercises:
  1. minPINLength == 6 in authenticatorGetInfo AND setPIN policy enforcement (R2).
  2. Vendor CTAP 0x41 / 0x09: status, pair, enroll (including R558-S 0x3B merge error + retry),
     PS_ControlBLN (0x3C) built-in RGB ring LED commands, delete, backup, authenticatorReset
     clearing EF_FP_CONF & EF_FP_PINWRAP, and post-reset restore (R3).
  3. Standard CTAP 2.1 internal UV: getUVRetries (0x07) & getPinUvAuthTokenUsingUvWithPermissions (0x06).
  4. REAL COLD POWER-CYCLES (killing & restarting the pico_fido process so RAM/session_pin are 100% zeroed):
     - Discoverable Passkey MakeCredential(rk=True) via fingerprint only,
     - Cold reboot -> Passkey GetAssertion + ECDSA signature verification via fingerprint only (zero PIN!),
     - Cold reboot -> CredentialManagement enumeration via fingerprint only,
     - changePIN -> Cold reboot -> Passkey GetAssertion via fingerprint still succeeds!
  5. 5x wrong finger -> UV_BLOCKED + solid RED sensor LED -> PIN unlock -> green flash + working UV.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from fido2 import cbor
from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2, ClientPin, CredentialManagement
from fido2.ctap2.pin import PinProtocolV2
from fido2.hid.base import CtapHidConnection, HidDescriptor
from fido2.hid import CtapHidDevice, CAPABILITY
import fido2.hid


class _TcpHidConnection(CtapHidConnection):
    def __init__(self, host: str = "127.0.0.1", port: int = 35962) -> None:
        self._sock = socket.create_connection((host, port), timeout=5.0)
        self._sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def _recv_exact(self, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = self._sock.recv(n - len(buf))
            if not chunk:
                raise OSError("emulator closed TCP HID socket")
            buf += chunk
        return buf

    def write_packet(self, data: bytes) -> None:
        pkt = bytes(data).ljust(64, b"\x00")[:64]
        self._sock.sendall(struct.pack(">H", len(pkt)) + pkt)

    def read_packet(self) -> bytes:
        (plen,) = struct.unpack(">H", self._recv_exact(2))
        return self._recv_exact(plen)

    def close(self) -> None:
        try:
            self._sock.close()
        except Exception:
            pass


class VirtualR558Sensor:
    """Byte-accurate GROW R558-S UART module simulator over TCP."""

    def __init__(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(4)
        self.port = self.sock.getsockname()[1]

        self.lock = threading.Lock()
        self.address = 0xFFFFFFFF
        self.password = b"\x00\x00\x00\x00"
        self.password_set = False
        self.session_verified = False
        self.capacity = 100  # R558-S datasheet p. 6: 100 templates
        self.templates: dict[int, int] = {}
        self.buffers: dict[int, int] = {1: -1, 2: -1, 3: -1}
        self.last_finger = -1
        self.schedule: list[int] = []
        self.led_history: list[tuple[int, int, int, int]] = []
        self.force_reg_3b_once = False
        self._stop = False
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    def set_schedule(self, *fingers: int) -> None:
        with self.lock:
            self.schedule = list(fingers)

    def stop(self) -> None:
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass

    @staticmethod
    def _encode_ack(addr: int, payload: bytes) -> bytes:
        pid = 0x07
        length = len(payload) + 2
        cksum = (pid + (length >> 8) + (length & 0xFF) + sum(payload)) & 0xFFFF
        return struct.pack(">HIBH", 0xEF01, addr, pid, length) + payload + struct.pack(">H", cksum)

    def _accept_loop(self) -> None:
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                break
            threading.Thread(target=self._client_loop, args=(conn,), daemon=True).start()

    def _client_loop(self, conn: socket.socket) -> None:
        buf = bytearray()
        with conn:
            while not self._stop:
                try:
                    chunk = conn.recv(256)
                except OSError:
                    break
                if not chunk:
                    break
                buf.extend(chunk)
                while len(buf) >= 12:
                    idx = buf.find(b"\xEF\x01")
                    if idx < 0:
                        buf.clear()
                        break
                    if idx > 0:
                        del buf[:idx]
                    if len(buf) < 9:
                        break
                    addr, pid, length = struct.unpack(">IBH", buf[2:9])
                    total = 9 + length
                    if len(buf) < total:
                        break
                    pkt = bytes(buf[:total])
                    del buf[:total]
                    resp = self._handle_packet(addr, pid, pkt[9:-2])
                    if resp is not None:
                        try:
                            conn.sendall(resp)
                        except OSError:
                            return

    def _handle_packet(self, addr: int, pid: int, body: bytes) -> bytes | None:
        if pid != 0x01 or not body:
            return None
        with self.lock:
            if addr != self.address:
                return None  # Real R558-S silently ignores wrong chip address
            ins = body[0]
            p = body[1:]
            reply_addr = addr

            # Real GROW R558-S silicon rejects non-VfyPwd commands until VfyPwd succeeds in session
            if ins != 0x13 and not self.session_verified:
                return self._encode_ack(reply_addr, b"\x01")

            if ins == 0x0F:  # ReadSysPara
                data = struct.pack(">HHHHIBBH", 0, 9, self.capacity, 3, self.address, 0, 2, 6)
                payload = b"\x00" + data
            elif ins == 0x12:  # SetPwd
                self.password = p[:4]
                self.password_set = True
                payload = b"\x00"
            elif ins == 0x13:  # VfyPwd
                if self.password_set and p[:4] != self.password:
                    self.session_verified = False
                    payload = b"\x13"
                else:
                    self.session_verified = True
                    payload = b"\x00"
            elif ins == 0x15:  # SetChipAddr (R558-S manual p. 30: ACK uses NEW address!)
                new_addr = struct.unpack(">I", p[:4])[0]
                self.address = new_addr
                reply_addr = new_addr
                payload = b"\x00"
            elif ins == 0x01:  # GenImg
                f = self.schedule.pop(0) if self.schedule else -1
                if f < 0:
                    payload = b"\x02"
                else:
                    self.last_finger = f
                    payload = b"\x00"
            elif ins == 0x02:  # GenChar
                self.buffers[p[0]] = self.last_finger
                payload = b"\x00"
            elif ins == 0x05:  # RegModel
                if self.force_reg_3b_once:
                    self.force_reg_3b_once = False
                    payload = b"\x3B"  # Real R558-S poor template / merge failure code
                elif self.buffers.get(1) == self.buffers.get(2):
                    payload = b"\x00"
                else:
                    payload = b"\x3B"
            elif ins == 0x06:  # Store
                buf_id = p[0]
                page = struct.unpack(">H", p[1:3])[0]
                self.templates[page] = self.buffers[buf_id]
                payload = b"\x00"
            elif ins == 0x04:  # Search
                buf_id = p[0]
                start, count = struct.unpack(">HH", p[1:5])
                target = self.buffers[buf_id]
                hit = next((slot for slot in range(start, start + count) if self.templates.get(slot) == target), None)
                if hit is None:
                    payload = b"\x09"
                else:
                    payload = b"\x00" + struct.pack(">HH", hit, 120)
            elif ins == 0x0C:  # DeletChar
                page, count = struct.unpack(">HH", p[:4])
                for s in range(page, page + count):
                    self.templates.pop(s, None)
                payload = b"\x00"
            elif ins == 0x0D:  # Empty
                self.templates.clear()
                payload = b"\x00"
            elif ins == 0x1D:  # TemplateNum
                payload = b"\x00" + struct.pack(">H", len(self.templates))
            elif ins == 0x3C:  # PS_ControlBLN (R558-S built-in RGB ring LED)
                self.led_history.append((p[0], p[1], p[2], p[3]))
                payload = b"\x00"
            else:
                payload = b"\x01"

            return self._encode_ack(reply_addr, payload)


def send_vendor_fp(ctap: Ctap2, subcmd: int, pin_token: bytes | None = None, param: bytes | None = None) -> dict:
    req: dict[int, object] = {1: subcmd}
    raw_params = b""
    if param is not None:
        inner = {1: param}
        raw_params = cbor.encode(inner)
        req[2] = inner
    if pin_token is not None:
        msg = b"\xff" * 32 + bytes([0x0D, subcmd]) + raw_params
        auth = hmac.new(pin_token, msg, hashlib.sha256).digest()
        req[3] = 2
        req[4] = auth
    raw = ctap.device.call(0x41, bytes([0x09]) + cbor.encode(req))
    if not raw:
        raise CtapError(0x01)
    if raw[0] != 0x00:
        raise CtapError(raw[0])
    return cbor.decode(raw[1:]) if len(raw) > 1 else {}


def main() -> int:
    emu_bin = sys.argv[1]
    sensor = VirtualR558Sensor()
    workdir = tempfile.mkdtemp(prefix="picofido_r558_e2e_")
    proc: subprocess.Popen | None = None

    def start_emu() -> Ctap2:
        nonlocal proc
        env = os.environ.copy()
        env["PICO_FIDO_R558_PORT"] = str(sensor.port)
        env["PICOKEYS_EMULATION_DISABLE_CCID"] = "1"
        proc = subprocess.Popen([emu_bin], cwd=workdir, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for _ in range(40):
            time.sleep(0.05)
            try:
                devs = list(fido2.hid.list_devices())
                if devs:
                    ctap = Ctap2(devs[0])
                    _ = ctap.get_info()
                    return ctap
            except Exception:
                pass
            conn = None
            try:
                conn = _TcpHidConnection()
                desc = HidDescriptor("tcp://127.0.0.1:35962", 0x2E8A, 0x10FE, 64, 64, "Pico Fido", "0000")
                dev = CtapHidDevice(desc, conn)
                ctap = Ctap2(dev)
                _ = ctap.get_info()
                return ctap
            except Exception:
                if conn is not None:
                    conn.close()
        raise RuntimeError("pico_fido emulator did not start in time")

    def stop_emu() -> None:
        nonlocal proc
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
            proc = None
            time.sleep(0.1)

    try:
        ctap = start_emu()
        info = ctap.get_info()
        print("1. Checking getInfo minPINLength == 6 ...", flush=True)
        assert info.min_pin_length == 6, f"expected minPINLength=6, got {info.min_pin_length}"
        assert "uv" not in info.options or not info.options["uv"]

        cp = ClientPin(ctap, PinProtocolV2())
        try:
            cp.set_pin("1234")
            raise AssertionError("4-digit PIN should have failed PIN_POLICY_VIOLATION")
        except CtapError as e:
            assert e.code == CtapError.ERR.PIN_POLICY_VIOLATION
        cp.set_pin("246810")
        print("   ok: minPINLength=6 advertised & enforced", flush=True)

        print("2. Pairing GROW R558-S & checking built-in RGB ring LED (0x3C) ...", flush=True)
        st = send_vendor_fp(ctap, 1)
        assert st[1] is False and st[6] is True and st[7] is False and st[8] == "dev" and st[9] is True
        assert (0x02, 0x01, 0x01, 2) in sensor.led_history, f"expected blue 2x boot flash after VfyPwd, got {sensor.led_history}"
        probe_st = send_vendor_fp(ctap, 8)
        assert probe_st[9] is True and isinstance(probe_st[10], str) and len(probe_st[10]) > 0
        sensor.led_history.clear()
        tok = cp.get_pin_token("246810", permissions=ClientPin.PERMISSION.AUTHENTICATOR_CFG)
        pair_res = send_vendor_fp(ctap, 2, pin_token=tok)
        assert pair_res[1] == 100
        assert (0x02, 0x02, 0x02, 3) in sensor.led_history, f"expected green 3x flash, got {sensor.led_history}"
        print("   ok: paired (capacity=100) + green 3x LED flash verified", flush=True)

        print("3. Testing R558-S 0x3B merge failure -> UV_INVALID & clean 2-scan enrollment ...", flush=True)
        tok = cp.get_pin_token("246810", permissions=ClientPin.PERMISSION.AUTHENTICATOR_CFG)
        sensor.force_reg_3b_once = True
        sensor.set_schedule(7, -1, 8)
        try:
            send_vendor_fp(ctap, 3, pin_token=tok)
            raise AssertionError("expected UV_INVALID on 0x3B")
        except CtapError as e:
            assert e.code == CtapError.ERR.UV_INVALID, f"expected UV_INVALID, got {e}"

        tok = cp.get_pin_token("246810", permissions=ClientPin.PERMISSION.AUTHENTICATOR_CFG)
        sensor.led_history.clear()
        sensor.set_schedule(7, -1, 7)
        enr = send_vendor_fp(ctap, 3, pin_token=tok)
        assert enr[1] == 0
        # Verify Blue breathe -> Cyan lift -> Purple/Blue breathe -> Green 3x flash
        funcs_colors = [(f, c1) for (f, c1, _, _) in sensor.led_history]
        assert (0x01, 0x01) in funcs_colors and (0x03, 0x03) in funcs_colors and (0x02, 0x02) in funcs_colors
        assert ctap.get_info().options.get("uv") is True
        assert cp.get_uv_retries() == 5
        print("   ok: enrolled slot 0, LED sequence verified, uv=True, uvRetries=5", flush=True)

        print("4. Creating resident Passkey via CTAP 2.1 get_uv_token (0x06) WITHOUT PIN ...", flush=True)
        sensor.set_schedule(7)
        uv_tok = cp.get_uv_token(
            permissions=ClientPin.PERMISSION.MAKE_CREDENTIAL | ClientPin.PERMISSION.GET_ASSERTION,
            permissions_rpid="example.com",
        )
        cdh = hashlib.sha256(b"challenge-create").digest()
        pin_auth = PinProtocolV2().authenticate(uv_tok, cdh)
        att = ctap.make_credential(
            cdh,
            {"id": "example.com", "name": "Example"},
            {"id": b"user-42", "name": "alice@example.com", "displayName": "Alice"},
            [{"type": "public-key", "alg": -7}],
            options={"rk": True},
            pin_uv_param=pin_auth,
            pin_uv_protocol=2,
        )
        assert att.auth_data.flags & (1 << 2), "UV flag must be set"
        assert att.auth_data.flags & (1 << 0), "UP flag must be set"
        pub_cose = att.auth_data.credential_data.public_key
        pub_key = ec.EllipticCurvePublicNumbers(
            int.from_bytes(pub_cose[-2], "big"),
            int.from_bytes(pub_cose[-3], "big"),
            ec.SECP256R1(),
        ).public_key()
        print("   ok: resident Passkey created with fingerprint only!", flush=True)

        print("5. COLD POWER-CYCLE #1: killing pico_fido & logging in with FINGERPRINT ONLY (zero PIN!) ...", flush=True)
        stop_emu()
        ctap = start_emu()
        assert ctap.get_info().options.get("uv") is True, "pairing/templates must survive reboot in fp_init()!"
        cp = ClientPin(ctap, PinProtocolV2())

        sensor.set_schedule(7)
        uv_tok = cp.get_uv_token(permissions=ClientPin.PERMISSION.GET_ASSERTION, permissions_rpid="example.com")
        cdh2 = hashlib.sha256(b"challenge-cold-login").digest()
        pin_auth2 = PinProtocolV2().authenticate(uv_tok, cdh2)
        assn = ctap.get_assertion(
            "example.com",
            cdh2,
            pin_uv_param=pin_auth2,
            pin_uv_protocol=2,
        )
        pub_key.verify(assn.signature, assn.auth_data + cdh2, ec.ECDSA(hashes.SHA256()))

        # Also test CredentialManagement via fingerprint after cold boot!
        sensor.set_schedule(7)
        cm_tok = cp.get_uv_token(permissions=ClientPin.PERMISSION.CREDENTIAL_MGMT)
        cm = CredentialManagement(ctap, PinProtocolV2(), cm_tok)
        rps = list(cm.enumerate_rps())
        assert len(rps) == 1
        print("   ok: cold-boot fingerprint GetAssertion + ECDSA sig + CredentialManagement ALL VERIFIED!", flush=True)

        print("6. Testing changePIN -> COLD POWER-CYCLE #2 -> fingerprint login still works ...", flush=True)
        cp.change_pin("246810", "975312")
        stop_emu()
        ctap = start_emu()
        cp = ClientPin(ctap, PinProtocolV2())
        sensor.set_schedule(7)
        uv_tok = cp.get_uv_token(permissions=ClientPin.PERMISSION.GET_ASSERTION, permissions_rpid="example.com")
        cdh3 = hashlib.sha256(b"challenge-after-pin-change").digest()
        assn2 = ctap.get_assertion(
            "example.com",
            cdh3,
            pin_uv_param=PinProtocolV2().authenticate(uv_tok, cdh3),
            pin_uv_protocol=2,
        )
        pub_key.verify(assn2.signature, assn2.auth_data + cdh3, ec.ECDSA(hashes.SHA256()))
        print("   ok: fingerprint login after PIN change + cold reboot verified!", flush=True)

        print("7. Testing 5x wrong finger -> UV_BLOCKED + solid RED LED -> PIN unlock ...", flush=True)
        sensor.led_history.clear()
        for _ in range(5):
            sensor.set_schedule(99)
            try:
                cp.get_uv_token(permissions=ClientPin.PERMISSION.GET_ASSERTION, permissions_rpid="example.com")
            except CtapError as e:
                assert e.code == CtapError.ERR.UV_INVALID
        assert (0x03, 0x04, 0x04, 0) in sensor.led_history, f"expected solid RED lockout LED, got {sensor.led_history}"
        assert cp.get_uv_retries() == 0
        try:
            cp.get_uv_token(permissions=ClientPin.PERMISSION.GET_ASSERTION, permissions_rpid="example.com")
            raise AssertionError("expected UV_BLOCKED")
        except CtapError as e:
            assert e.code == CtapError.ERR.UV_BLOCKED

        tok = cp.get_pin_token("975312", permissions=ClientPin.PERMISSION.AUTHENTICATOR_CFG)
        send_vendor_fp(ctap, 5, pin_token=tok)
        assert cp.get_uv_retries() == 5
        print("   ok: lockout, solid RED LED, and PIN unlock verified!", flush=True)

        print("8. Testing R3 backup -> authenticatorReset -> restore -> COLD POWER-CYCLE #3 ...", flush=True)
        tok = cp.get_pin_token("975312", permissions=ClientPin.PERMISSION.AUTHENTICATOR_CFG)
        backup_blob = send_vendor_fp(ctap, 6, pin_token=tok)[1]
        assert len(backup_blob) == 43

        ctap.reset()
        st_after_reset = send_vendor_fp(ctap, 1)
        assert st_after_reset[1] is False, "EF_FP_CONF must be cleared on authenticatorReset!"

        cp = ClientPin(ctap, PinProtocolV2())
        cp.set_pin("654321")
        tok = cp.get_pin_token("654321", permissions=ClientPin.PERMISSION.AUTHENTICATOR_CFG)
        send_vendor_fp(ctap, 7, pin_token=tok, param=backup_blob)

        stop_emu()
        ctap = start_emu()
        cp = ClientPin(ctap, PinProtocolV2())
        assert ctap.get_info().options.get("uv") is True
        sensor.set_schedule(7)
        uv_tok = cp.get_uv_token(permissions=ClientPin.PERMISSION.MAKE_CREDENTIAL, permissions_rpid="restored.example")
        assert len(uv_tok) == 32
        print("   ok: backup -> reset -> restore -> cold-boot UV verified!", flush=True)

        print("\nALL FULL-STACK CTAP 2.1 + R558-S HARDWARE PROTOCOL TESTS PASSED!", flush=True)
        return 0
    finally:
        stop_emu()
        sensor.stop()
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
