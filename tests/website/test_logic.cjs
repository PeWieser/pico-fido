// Offline tests for the recovery website's pure logic (website/app.js).
// Run: node tests/website/test_logic.cjs
const L = require("../../website/app.js");

let checks = 0, failures = 0;
function ok(cond, msg) {
  checks++;
  if (!cond) { failures++; console.error("FAIL: " + msg); }
}
function eqHex(bytes, hex, msg) {
  ok(L.bytesToHex(bytes).toLowerCase() === hex.toLowerCase(),
     msg + ` (got ${L.bytesToHex(bytes)}, want ${hex})`);
}

// --- CBOR: firmware request vectors (subcommand requests from cbor_vendor.c) ---
eqHex(L.buildFpRequest(0x01, null), "09a10101", "status request");
eqHex(L.buildFpRequest(0x0b, null), "09a1010b", "recover without candidates");
eqHex(L.buildFpRequest(0x0b, L.hexToBytes("11223344")),
      "09a2010b02a1014411223344", "recover with one candidate (params key 2 is a map {1: bytes})");

// --- CBOR: decode a typical status response map ---
// {1:true, 2:false, 3:200, 6:true, 15:"flash"}
const statusBytes = L.hexToBytes("a501f502f40318c806f50f65666c617368");
const m = L.cborDecode(statusBytes);
ok(m.get(1) === true, "paired true");
ok(m.get(2) === false, "locked false");
ok(m.get(3) === 200, "capacity 200");
ok(m.get(15) === "flash", "recover source flash");

// --- CTAPHID framing: short message = single 64-byte frame ---
const frames = L.buildHidFrames(0x11223344, 0xc1, L.buildFpRequest(0x01, null));
ok(frames.length === 1, "single frame for short payload");
ok(frames[0][4] === 0xc1 && frames[0][5] === 0 && frames[0][6] === 4, "init frame header");
const rx = new L.HidReceiver();
const res = rx.feed(frames[0]);
ok(res.message && res.message.cmd === 0xc1 && res.message.payload.length === 4,
   "receiver reassembles short message");

// --- CTAPHID: long telemetry message spans continuation frames ---
const bigPayload = new Uint8Array(200).map((_, i) => i & 0xff);
const bigFrames = L.buildHidFrames(0x11223344, 0xc1, bigPayload);
ok(bigFrames.length > 1, "continuation frames created");
const rx2 = new L.HidReceiver();
let msg = null;
for (const f of bigFrames) { const r = rx2.feed(f); if (r.message) msg = r.message; }
ok(msg && msg.payload.length === 200 && msg.payload[199] === 199,
   "receiver reassembles multi-frame message");
// KEEPALIVE frame is consumed silently
const ka = new Uint8Array(64); ka[4] = 0xbb; ka[6] = 1; ka[7] = 1;
ok(rx2.feed(ka).keepalive === true, "keepalive handled");

// --- MAC derivation (known vector, matches firmware/Python/C references) ---
const { createHash } = require("crypto");
const domain = Buffer.from("pico-fido-r558-efuse-bind-v1");
const digest = createHash("sha256")
  .update(domain).update(Buffer.from([0x24, 0x0a, 0xc4, 0x00, 0x00, 0x01])).digest();
const d = L.derivationFromDigest(new Uint8Array(digest));
eqHex(d.password, "2F57E5E3", "derived password for test MAC");
ok(d.address === 0x35ab7818, "derived address for test MAC");

// --- ESP32 dump scan: file-record + stale conf + backup blob ---
function confPayload(pwdHex, addrHex, flags = 0x03) {
  const p = new Uint8Array(46).fill(0xff);
  p[0] = 1; p[1] = flags; p[2] = 0; p[3] = 0;
  p.set(L.hexToBytes(pwdHex), 4);
  p.set(L.hexToBytes(addrHex), 8);
  p[12] = 0; p[13] = 200;
  return p;
}
{
  const dump = new Uint8Array(0x8000).fill(0xff);
  dump.set(L.hexToBytes("04112E00"), 0x100);               // live file record
  dump.set(confPayload("A1B2C3D4", "29062D09"), 0x104);
  const blob = new Uint8Array(43).fill(0xff);              // backup blob
  blob[0] = 1; blob.set(L.hexToBytes("C001D00D"), 1);
  blob.set(L.hexToBytes("11111111"), 5); blob[9] = 0; blob[10] = 100;
  dump.set(blob, 0x400);
  const list = L.scanEsp32Dump(dump, 0x29062d09);
  ok(list.length >= 2, "ESP32 scan finds candidates");
  ok(list[0].password_hex === "A1B2C3D4" && list[0].confidence === 100,
     "file-record candidate ranked first");
  ok(list.some((c) => c.password_hex === "C001D00D" && c.source.includes("backup")),
     "backup blob candidate found");
  ok(L.scanEsp32Dump(new Uint8Array(0x1000).fill(0xff), null).length === 0,
     "erased dump yields nothing");
}

// --- sensor SPI dump scan: parameter table @ address+0, password @ +60, flag @ +126 ---
{
  const dump = new Uint8Array(0x2000).fill(0xff);
  const base = 0x400;
  dump.set(L.hexToBytes("29062D09"), base + 8);
  dump.set(L.hexToBytes("5EEDF00D"), base + 60);
  dump[base + 126] = 0x12; dump[base + 127] = 0x34;
  const list = L.scanSensorDump(dump, 0x29062d09);
  ok(list.some((c) => c.password_hex === "5EEDF00D" && c.address_hex === "29062D09"),
     "sensor parameter-table password found");
}

console.log(`${checks - failures}/${checks} checks passed`);
process.exit(failures ? 1 : 0);
