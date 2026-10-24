/*
 * Pico FIDO - R558-S Rettungsseite (recovery page).
 *
 * Pure logic (CBOR mini-codec, CTAPHID framing helpers, flash-dump scanners, MAC derivation)
 * lives at the top and is exported for tests/website/test_logic.mjs. The DOM/WebHID wiring at
 * the bottom only runs in a browser. Everything happens locally: flash dumps and MACs are
 * processed in this tab and never uploaded.
 *
 * Protocol (firmware side: src/fido/cbor_vendor.c, CTAP_VENDOR_FP = 0x09):
 *   CTAPHID command 0xC1 (CTAP_VENDOR_CBOR), payload = 0x09 || CBOR map
 *     { 1: subcommand, 2: { 1: bytes } optional params }
 *   Subcommands used here (no PIN token): 0x01 status, 0x08 probe, 0x0B recover.
 *   Response payload = CTAP status byte || CBOR status map (keys 1..15).
 *
 * IMPORTANT (browser reality): Chrome/Edge block WebHID access to the FIDO usage page
 * 0xF1D0. Start the browser with --disable-hid-blocklist or the device will not even show
 * up in the picker (see the instructions on the page).
 */
"use strict";

/* ------------------------------------------------------------------ utils */
function hexToBytes(hex) {
  const clean = String(hex || "").replace(/[^0-9a-fA-F]/g, "");
  if (clean.length % 2 !== 0) throw new Error("Hex-Eingabe hat ungerade Länge.");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(2 * i, 2), 16);
  return out;
}
function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
}
function be16(b, off) { return ((b[off] << 8) | b[off + 1]) >>> 0; }
function be32(b, off) {
  return (((b[off] << 24) | (b[off + 1] << 16) | (b[off + 2] << 8) | b[off + 3]) >>> 0);
}

/* ------------------------------------------------------------- CBOR codec */
/* Minimal deterministic CBOR: uint, negative int, bytes, text, bool, array, map.
 * Encoding takes maps as arrays of [key, value] pairs to preserve key order.
 * Decoding returns Map for maps, Uint8Array for byte strings. */
function cborHead(major, value, out) {
  const mt = major << 5;
  if (value < 24) out.push(mt | value);
  else if (value < 256) out.push(mt | 24, value);
  else if (value < 65536) out.push(mt | 25, (value >> 8) & 0xff, value & 0xff);
  else if (value < 4294967296) {
    out.push(mt | 26, (value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff);
  } else throw new Error("CBOR-Zahl zu groß.");
}
function cborEncodeInto(value, out) {
  if (value === false) { out.push(0xf4); return; }
  if (value === true) { out.push(0xf5); return; }
  if (typeof value === "number" && Number.isInteger(value)) {
    if (value >= 0) cborHead(0, value, out); else cborHead(1, -1 - value, out);
    return;
  }
  if (value instanceof Uint8Array) {
    cborHead(2, value.length, out);
    for (const b of value) out.push(b);
    return;
  }
  if (typeof value === "string") {
    const enc = new TextEncoder().encode(value);
    cborHead(3, enc.length, out);
    for (const b of enc) out.push(b);
    return;
  }
  if (Array.isArray(value) && value.__cborMap) {
    cborHead(5, value.length, out);
    for (const [k, v] of value) { cborEncodeInto(k, out); cborEncodeInto(v, out); }
    return;
  }
  if (Array.isArray(value)) {
    cborHead(4, value.length, out);
    for (const v of value) cborEncodeInto(v, out);
    return;
  }
  throw new Error("CBOR: nicht unterstützter Typ.");
}
function cborMap(pairs) { const a = pairs.slice(); a.__cborMap = true; return a; }
function cborEncode(value) { const out = []; cborEncodeInto(value, out); return new Uint8Array(out); }

function cborDecode(bytes) {
  let pos = 0;
  function readHead() {
    const ib = bytes[pos++];
    const major = ib >> 5;
    let ai = ib & 0x1f;
    let val;
    if (ai < 24) val = ai;
    else if (ai === 24) val = bytes[pos++];
    else if (ai === 25) { val = be16(bytes, pos); pos += 2; }
    else if (ai === 26) { val = be32(bytes, pos); pos += 4; }
    else if (ai === 27) {
      val = be32(bytes, pos) * 4294967296 + be32(bytes, pos + 4); pos += 8;
    } else throw new Error("CBOR: unbestimmte Länge wird nicht unterstützt.");
    return [major, val];
  }
  function readValue() {
    const [major, val] = readHead();
    switch (major) {
      case 0: return val;
      case 1: return -1 - val;
      case 2: { const v = bytes.slice(pos, pos + val); pos += val; return v; }
      case 3: { const v = new TextDecoder().decode(bytes.slice(pos, pos + val)); pos += val; return v; }
      case 4: { const a = []; for (let i = 0; i < val; i++) a.push(readValue()); return a; }
      case 5: {
        const m = new Map();
        for (let i = 0; i < val; i++) { const k = readValue(); const v = readValue(); m.set(k, v); }
        return m;
      }
      case 7: {
        if (val === 20) return false;
        if (val === 21) return true;
        if (val === 22) return null;
        throw new Error("CBOR: float/simple nicht unterstützt.");
      }
      default: throw new Error("CBOR: ungültiger Major-Typ.");
    }
  }
  const result = readValue();
  return result;
}

/* CTAP_VENDOR_FP request: [0x09] || CBOR {1: sub, 2: {1: params}?} */
function buildFpRequest(subcommand, paramsBytes) {
  const pairs = [[1, subcommand]];
  if (paramsBytes && paramsBytes.length) pairs.push([2, cborMap([[1, paramsBytes]])]);
  const body = cborEncode(cborMap(pairs));
  const out = new Uint8Array(1 + body.length);
  out[0] = 0x09;
  out.set(body, 1);
  return out;
}

/* ---------------------------------------------------- CTAPHID frame build */
const HID_PACKET_SIZE = 64;
function buildHidFrames(cid, cmd, payload) {
  const frames = [];
  const first = new Uint8Array(HID_PACKET_SIZE);
  const dv = new DataView(first.buffer);
  dv.setUint32(0, cid, false);
  first[4] = cmd;
  dv.setUint16(5, payload.length, false);
  const firstChunk = Math.min(57, payload.length);
  first.set(payload.subarray(0, firstChunk), 7);
  frames.push(first);
  let off = firstChunk;
  let seq = 0;
  while (off < payload.length) {
    const f = new Uint8Array(HID_PACKET_SIZE);
    const d2 = new DataView(f.buffer);
    d2.setUint32(0, cid, false);
    f[4] = seq++;
    const chunk = Math.min(59, payload.length - off);
    f.set(payload.subarray(off, off + chunk), 5);
    frames.push(f);
    off += chunk;
  }
  return frames;
}

/* Incremental CTAPHID receiver: feed 64-byte reports, get complete messages. */
class HidReceiver {
  constructor() { this.reset(); }
  reset() { this.cid = null; this.cmd = null; this.len = 0; this.data = []; this.seq = 0; }
  feed(report) {
    const dv = new DataView(report.buffer, report.byteOffset, report.byteLength);
    const cid = dv.getUint32(0, false);
    const b4 = report[4];
    if (b4 & 0x80) {
      const cmd = b4;
      if (cmd === 0xbb) return { keepalive: true };        // CTAPHID_KEEPALIVE
      if (cmd === 0xbf) return { error: report[7] };       // CTAPHID_ERROR
      this.cid = cid; this.cmd = cmd;
      this.len = dv.getUint16(5, false);
      this.data = Array.from(report.subarray(7, Math.min(report.length, 7 + this.len)));
      this.seq = 0;
    } else {
      if (cid !== this.cid || b4 !== (this.seq & 0x7f)) return {};
      const need = this.len - this.data.length;
      this.data.push(...report.subarray(5, 5 + Math.min(59, need)));
      this.seq++;
    }
    if (this.data.length >= this.len) {
      const msg = { cid: this.cid, cmd: this.cmd, payload: new Uint8Array(this.data.slice(0, this.len)) };
      this.reset();
      return { message: msg };
    }
    return {};
  }
}

/* ------------------------------------------------------- MAC derivation */
const EFUSE_DOMAIN = new TextEncoder().encode("pico-fido-r558-efuse-bind-v1");
async function deriveFromMac(macBytes) {
  const msg = new Uint8Array(EFUSE_DOMAIN.length + 6);
  msg.set(EFUSE_DOMAIN, 0);
  msg.set(macBytes, EFUSE_DOMAIN.length);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", msg));
  return derivationFromDigest(digest);
}
function derivationFromDigest(digest) {
  const pwd = digest.slice(0, 4);
  if (pwd.every((b) => b === 0)) pwd[0] = 0xa5;
  let addr = be32(digest, 4);
  if (addr === 0 || addr === 0xffffffff) addr = 0x5a3cc3a5;
  return { password: pwd, address: addr };
}

/* --------------------------------------------------- flash dump scanners */
const KNOWN_FLAGS = 0x01 | 0x02 | 0x04 | 0x08;
function pwdPlausible(p) {
  return !(p.every((b) => b === 0) || p.every((b) => b === 0xff));
}
function scanEsp32Dump(data, wantedAddr) {
  const out = [];
  const seen = new Set();
  function add(pwd, addr, source, offset, confidence) {
    const key = bytesToHex(pwd) + "@" + addr.toString(16);
    const entry = {
      password_hex: bytesToHex(pwd),
      address_hex: addr.toString(16).toUpperCase().padStart(8, "0"),
      source, offset, confidence,
    };
    if (seen.has(key)) {
      const old = out.find((e) => e.password_hex === entry.password_hex && e.address_hex === entry.address_hex);
      if (old && confidence > old.confidence) Object.assign(old, entry);
      return;
    }
    seen.add(key);
    out.push(entry);
  }
  // picokeys file records: [next:4][prev:4][fid 04 11][len 2E 00][46B payload]
  const sig = [0x04, 0x11, 0x2e, 0x00];
  for (let i = 0; i + 4 + 46 <= data.length; i++) {
    if (data[i] === sig[0] && data[i + 1] === sig[1] && data[i + 2] === sig[2] && data[i + 3] === sig[3]) {
      const p = i + 4;
      if (data[p] === 1 && data[p + 3] === 0) {
        const addr = be32(data, p + 8);
        const cap = be16(data, p + 12);
        const pwd = data.slice(p + 4, p + 8);
        if (pwdPlausible(pwd) && addr !== 0 && cap >= 1 && cap <= 512) {
          add(pwd, addr, "esp32:file-record(EF_FP_CONF)", p, 100);
        }
      }
    }
  }
  // Signature scan (same rules as firmware fp_recover_scan_image).
  for (let off = 0; off + 46 <= data.length; off++) {
    if (data[off] !== 1) continue;
    const flags = data[off + 1];
    if (data[off + 3] === 0 && flags !== 0 && (flags & ~KNOWN_FLAGS) === 0) {
      const addr = be32(data, off + 8);
      const cap = be16(data, off + 12);
      const pwd = data.slice(off + 4, off + 8);
      if (pwdPlausible(pwd) && addr !== 0 && cap >= 1 && cap <= 512) {
        add(pwd, addr, "esp32:conf-signature", off, 90);
        continue;
      }
    }
    if (off + 43 <= data.length) {
      const addr = be32(data, off + 5);
      const cap = be16(data, off + 9);
      const pwd = data.slice(off + 1, off + 5);
      if (pwdPlausible(pwd) && addr !== 0 && addr !== 0xffffffff && cap >= 1 && cap <= 512) {
        add(pwd, addr, "esp32:backup-blob", off, 85);
      }
    }
  }
  if (wantedAddr) {
    const needle = new Uint8Array(4);
    new DataView(needle.buffer).setUint32(0, wantedAddr, false);
    for (let i = 4; i + 4 <= data.length; i++) {
      if (data[i] === needle[0] && data[i + 1] === needle[1] && data[i + 2] === needle[2] && data[i + 3] === needle[3]) {
        const pwd = data.slice(i - 4, i);
        if (pwdPlausible(pwd)) add(pwd, wantedAddr, "esp32:address-context", i - 4, 40);
      }
    }
  }
  out.sort((a, b) => b.confidence - a.confidence);
  return out;
}

function scanSensorDump(data, wantedAddr) {
  const out = [];
  const seen = new Set();
  function consider(base, source, confidence) {
    if (base < 0 || base + 128 > data.length) return;
    const flag = data.slice(base + 126, base + 128);
    let conf = confidence;
    let src = source;
    if (!((flag[0] === 0x12 && flag[1] === 0x34) || (flag[0] === 0x34 && flag[1] === 0x12))) {
      conf -= 30; src += "(flag?)";
    }
    const addrBE = be32(data, base + 8);
    const addrSwap = be32(data.slice(base + 8, base + 12).reverse(), 0);
    for (const [label, addr, pwd] of [
      ["BE", addrBE, data.slice(base + 60, base + 64)],
      ["word-swapped", addrSwap, data.slice(base + 60, base + 64).reverse()],
    ]) {
      if (addr === 0) continue;
      if (wantedAddr && addr !== wantedAddr) continue;
      const key = bytesToHex(pwd) + "@" + addr.toString(16);
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({
        password_hex: bytesToHex(pwd),
        address_hex: addr.toString(16).toUpperCase().padStart(8, "0"),
        source: `sensor:parameter-table[${label}]${src}`,
        offset: base, confidence: conf,
      });
    }
  }
  if (wantedAddr) {
    const be = new Uint8Array(4);
    new DataView(be.buffer).setUint32(0, wantedAddr, false);
    const le = be.slice().reverse();
    for (const needle of [be, le]) {
      for (let i = 8; i + 4 <= data.length; i++) {
        if (data[i] === needle[0] && data[i + 1] === needle[1] && data[i + 2] === needle[2] && data[i + 3] === needle[3]) {
          consider(i - 8, "", 95);
        }
      }
    }
  }
  for (let i = 126; i + 2 <= data.length; i++) {
    if ((data[i] === 0x12 && data[i + 1] === 0x34) || (data[i] === 0x34 && data[i + 1] === 0x12)) {
      consider(i - 126, "(flag-anchored)", 70);
    }
  }
  out.sort((a, b) => b.confidence - a.confidence);
  return out;
}

/* --------------------------------------------------------------- exports */
const PURE_EXPORTS = {
  hexToBytes, bytesToHex, cborEncode, cborDecode, cborMap, buildFpRequest,
  buildHidFrames, HidReceiver, derivationFromDigest, scanEsp32Dump, scanSensorDump,
};
if (typeof module !== "undefined" && module.exports) {
  module.exports = PURE_EXPORTS;
}

/* ============================================================ browser UI */
if (typeof document !== "undefined") {
  const $ = (id) => document.getElementById(id);
  let device = null;
  let channelId = null;
  let receiver = new HidReceiver();
  let messageWaiters = [];
  let foundCandidates = [];

  function log(line, cls) {
    const el = $("log");
    const div = document.createElement("div");
    if (cls) div.className = cls;
    div.textContent = line;
    el.appendChild(div);
    el.scrollTop = el.scrollHeight;
  }

  function onReport(event) {
    const report = new Uint8Array(event.data.buffer, event.data.byteOffset, event.data.byteLength);
    const res = receiver.feed(report.slice());
    if (res.message) {
      const waiters = messageWaiters;
      messageWaiters = [];
      for (const w of waiters) w.resolve(res.message);
    } else if (res.error !== undefined) {
      const waiters = messageWaiters;
      messageWaiters = [];
      for (const w of waiters) w.reject(new Error("CTAPHID-Fehler 0x" + res.error.toString(16)));
    }
  }

  function waitMessage(timeoutMs) {
    return new Promise((resolve, reject) => {
      const entry = {
        resolve: (m) => { clearTimeout(timer); resolve(m); },
        reject: (e) => { clearTimeout(timer); reject(e); },
      };
      const timer = setTimeout(() => {
        messageWaiters = messageWaiters.filter((w) => w !== entry);
        reject(new Error("Zeitüberschreitung: Das Gerät hat nicht geantwortet."));
      }, timeoutMs);
      messageWaiters.push(entry);
    });
  }

  async function hidSend(cid, cmd, payload) {
    for (const frame of buildHidFrames(cid, cmd, payload)) {
      await device.sendReport(0, frame);
    }
  }

  async function hidInit() {
    const nonce = crypto.getRandomValues(new Uint8Array(8));
    receiver.reset();
    await hidSend(0xffffffff, 0x86, nonce);
    const msg = await waitMessage(5000);
    if (msg.cmd !== 0x86 || msg.payload.length < 17) {
      throw new Error("Unerwartete INIT-Antwort.");
    }
    channelId = be32(msg.payload, 8);
    return channelId;
  }

  async function vendorFp(subcommand, paramsBytes, timeoutMs) {
    if (!device || channelId === null) throw new Error("Zuerst mit dem Gerät verbinden.");
    receiver.reset();
    await hidSend(channelId, 0xc1, buildFpRequest(subcommand, paramsBytes || null));
    const msg = await waitMessage(timeoutMs || 30000);
    if (msg.cmd !== 0xc1) throw new Error("Unerwarteter Antwortbefehl 0x" + msg.cmd.toString(16));
    if (msg.payload.length === 0) throw new Error("Leere Antwort vom Gerät.");
    const status = msg.payload[0];
    if (status !== 0) {
      throw new Error("CTAP-Status 0x" + status.toString(16).padStart(2, "0") +
        (status === 0x3e ? " (Firmware zu alt: Vendor-Befehl 0x09 fehlt – bitte neueste Firmware flashen)" : ""));
    }
    if (msg.payload.length < 2) return new Map();
    return cborDecode(msg.payload.slice(1));
  }

  function renderStatus(m) {
    const rows = [
      ["Gekoppelt (paired)", m.get(1)],
      ["Gesperrt (locked)", m.get(2)],
      ["Kapazität", m.get(3)],
      ["Belegte Slots", Array.isArray(m.get(4)) ? m.get(4).join(", ") || "(keine)" : m.get(4)],
      ["Fehlversuche", m.get(5)],
      ["Fingerprint unterstützt", m.get(6)],
      ["Flash verschlüsselt", m.get(7)],
      ["Build-Typ", m.get(8)],
      ["Sensor erkannt", m.get(9)],
      ["Telemetrie / Pins", m.get(10)],
      ["Letzter Schritt (Opcode)", m.get(11) !== undefined ? "0x" + Number(m.get(11)).toString(16) : "–"],
      ["Letzter Conf-Code", m.get(12) !== undefined ? "0x" + Number(m.get(12)).toString(16) : "–"],
      ["Recover gefunden", m.get(14)],
      ["Recover-Quelle", m.get(15)],
    ];
    const t = $("statusTable");
    t.innerHTML = "";
    for (const [k, v] of rows) {
      const tr = document.createElement("tr");
      const th = document.createElement("th"); th.textContent = k;
      const td = document.createElement("td"); td.textContent = v === undefined ? "–" : String(v);
      tr.append(th, td);
      t.appendChild(tr);
    }
  }

  async function doStatus() {
    const m = await vendorFp(0x01, null, 15000);
    renderStatus(m);
    return m;
  }

  $("connectBtn").addEventListener("click", async () => {
    try {
      if (!navigator.hid) {
        throw new Error("WebHID ist in diesem Browser nicht verfügbar (Chromium-Browser + HTTPS/localhost nötig).");
      }
      log("Geräteauswahl öffnen … (falls kein Gerät erscheint: Browser mit --disable-hid-blocklist starten)");
      const devices = await navigator.hid.requestDevice({
        filters: [{ usagePage: 0xf1d0, usage: 0x01 }],
      });
      if (!devices.length) throw new Error("Kein Gerät ausgewählt.");
      device = devices[0];
      device.addEventListener("inputreport", onReport);
      if (!device.opened) await device.open();
      const cid = await hidInit();
      log(`Verbunden: ${device.productName || "FIDO-Gerät"}, Kanal 0x${cid.toString(16)}`, "ok");
      const m = await doStatus();
      if (m.get(6) === false) {
        log("Firmware ohne Fingerprint-Unterstützung (supported=false). Bitte ESP32-S3-Firmware mit R558-Unterstützung flashen.", "err");
      }
    } catch (e) {
      log("Verbinden fehlgeschlagen: " + e.message, "err");
    }
  });

  $("statusBtn").addEventListener("click", async () => {
    try { await doStatus(); log("Status aktualisiert.", "ok"); }
    catch (e) { log("Status fehlgeschlagen: " + e.message, "err"); }
  });

  $("probeBtn").addEventListener("click", async () => {
    try {
      log("Probe (0x08): UART-Pin-Scan läuft …");
      const m = await vendorFp(0x08, null, 30000);
      renderStatus(m);
      log("Probe fertig. Telemetrie: " + (m.get(10) || "–"), "ok");
    } catch (e) { log("Probe fehlgeschlagen: " + e.message, "err"); }
  });

  $("recoverBtn").addEventListener("click", async () => {
    try {
      let candidateBytes = null;
      const raw = $("candidateHex").value.trim();
      if (raw) {
        candidateBytes = hexToBytes(raw);
        if (candidateBytes.length === 0 || candidateBytes.length % 4 !== 0) {
          throw new Error("Kandidaten müssen aus 4-Byte-Blöcken bestehen (Hex-Länge ein Vielfaches von 8).");
        }
        log(`Recover (0x0B) mit ${candidateBytes.length / 4} Besitzer-Kandidat(en) plus Geräte-Leiter …`);
      } else {
        log("Recover (0x0B): Geräte-Leiter stored → derived → flash → shared → factory …");
      }
      log("Tipp: Für ein sauberes VfyPwd-Budget das Gerät vorher 10 s vom USB trennen und Recover als erste Aktion ausführen.");
      const m = await vendorFp(0x0b, candidateBytes, 60000);
      renderStatus(m);
      const found = m.get(14);
      const src = m.get(15) || "none";
      if (found) {
        log(`SENSOR WIEDERHERGESTELLT (Quelle: ${src}). Jetzt im nächsten Schritt „pair“ ausführen (Haupt-Webapp), Finger anlernen und ein Backup erstellen!`, "ok");
      } else {
        const tele = String(m.get(10) || "");
        log(`Recover ohne Treffer (Quelle: ${src}). Telemetrie: ${tele || "–"}`, "err");
        if (tele.includes("silent")) {
          log("Deutung: Modul antwortet gar nicht – Verkabelung/Versorgung/UART-Pins prüfen, nicht das Passwort.", "err");
        } else {
          log("Deutung: Modul lebt, Passwort unbekannt – weiter mit Schritt 3 (MAC prüfen) und 4 (Flash-Dump-Analyse) oder den PC-Tools.", "err");
        }
      }
    } catch (e) { log("Recover fehlgeschlagen: " + e.message, "err"); }
  });

  $("macBtn").addEventListener("click", async () => {
    try {
      const mac = hexToBytes($("macInput").value);
      if (mac.length !== 6) throw new Error("MAC muss 6 Bytes haben (z. B. 24:0A:C4:12:34:56).");
      const { password, address } = await deriveFromMac(mac);
      const addrHex = address.toString(16).toUpperCase().padStart(8, "0");
      const wanted = $("observedAddr").value.replace(/[^0-9a-fA-F]/g, "").toUpperCase();
      let line = `Ableitung: Adresse ${addrHex}`;
      if (wanted) {
        line += address.toString(16).toUpperCase().padStart(8, "0") === wanted.padStart(8, "0")
          ? " ⇒ TREFFER zur beobachteten Chip-Adresse! Das abgeleitete Passwort wurde in das Kandidatenfeld übernommen."
          : ` ⇒ kein Treffer (beobachtet: ${wanted}). Diese Board-Ableitung erklärt die Sperre nicht.`;
      }
      $("macResult").textContent = line;
      if (wanted && address.toString(16).toUpperCase().padStart(8, "0") === wanted.padStart(8, "0")) {
        $("candidateHex").value = bytesToHex(password);
      }
      log(line, "ok");
    } catch (e) { $("macResult").textContent = "Fehler: " + e.message; }
  });

  function renderCandidates(list) {
    foundCandidates = list;
    const t = $("candidateTable");
    t.innerHTML = "";
    for (const c of list) {
      const tr = document.createElement("tr");
      for (const text of [String(c.confidence), c.password_hex, c.address_hex, c.source, "0x" + c.offset.toString(16)]) {
        const td = document.createElement("td"); td.textContent = text; tr.appendChild(td);
      }
      t.appendChild(tr);
    }
    $("dumpActions").hidden = list.length === 0;
  }

  $("dumpFile").addEventListener("change", async (ev) => {
    try {
      const file = ev.target.files[0];
      if (!file) return;
      const data = new Uint8Array(await file.arrayBuffer());
      const wantedText = $("observedAddr").value.replace(/[^0-9a-fA-F]/g, "");
      const wanted = wantedText ? parseInt(wantedText, 16) : null;
      const mode = $("dumpMode").value;
      const list = mode === "sensor" ? scanSensorDump(data, wanted) : scanEsp32Dump(data, wanted);
      renderCandidates(list);
      log(`Dump analysiert (${file.name}, ${data.length} Bytes, Modus ${mode}, alles lokal): ${list.length} Kandidat(en).`,
          list.length ? "ok" : "err");
      if (mode === "esp32" && data.length >= 0x300000) {
        const part0 = data.subarray(0x200000, 0x300000);
        let ff = 0;
        for (const b of part0) if (b === 0xff) ff++;
        log(`part0-Region zu ${(100 * ff / part0.length).toFixed(1)} % gelöscht (0xFF).`);
        if (ff / part0.length > 0.999) {
          log("Warnung: part0 komplett gelöscht – der Chip wurde nach dem Pairing per erase_flash gelöscht.", "err");
        }
      }
    } catch (e) { log("Dump-Analyse fehlgeschlagen: " + e.message, "err"); }
  });

  $("useCandidatesBtn").addEventListener("click", () => {
    $("candidateHex").value = foundCandidates.map((c) => c.password_hex).join("");
    log(`${foundCandidates.length} Kandidat(en) in Schritt 2 übernommen. Jetzt „Sensor wiederherstellen“ klicken.`, "ok");
    document.getElementById("step-recover").scrollIntoView({ behavior: "smooth" });
  });

  $("downloadJsonBtn").addEventListener("click", () => {
    const blob = new Blob([JSON.stringify({ candidates: foundCandidates }, null, 2)],
      { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "r558-candidates.json";
    a.click();
    URL.revokeObjectURL(a.href);
  });

  // Firmware release list (public GitHub API; plain links, no in-page flashing here).
  (async () => {
    const box = $("releases");
    try {
      const resp = await fetch("https://api.github.com/repos/PeWieser/pico-fido/releases?per_page=10");
      if (!resp.ok) throw new Error("HTTP " + resp.status);
      const rels = await resp.json();
      const fw = rels.filter((r) => /^fw-/.test(r.tag_name || ""));
      if (!fw.length) { box.textContent = "Keine fw-Releases gefunden."; return; }
      box.innerHTML = "";
      for (const r of fw.slice(0, 5)) {
        const div = document.createElement("div");
        const title = document.createElement("strong");
        title.textContent = r.name || r.tag_name;
        div.appendChild(title);
        for (const a of r.assets || []) {
          if (!/\.(bin|txt)$/.test(a.name)) continue;
          const link = document.createElement("a");
          link.href = a.browser_download_url;
          link.textContent = a.name;
          link.rel = "noopener";
          const li = document.createElement("div");
          li.appendChild(link);
          div.appendChild(li);
        }
        box.appendChild(div);
      }
    } catch (e) {
      box.textContent = "Releases konnten nicht geladen werden (" + e.message +
        "). Direkt: https://github.com/PeWieser/pico-fido/releases";
    }
  })();

  log("Bereit. Schritt 1: Gerät verbinden. Alles auf dieser Seite läuft lokal im Browser – Dumps und MACs werden nicht hochgeladen.");
}
