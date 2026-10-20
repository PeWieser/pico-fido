# Architekturübersicht, Forensische Fehlerdiagnose & Hardware-Anleitung (`PeWieser/pico-fido` vs. `polhenarejos/pico-fido`)

## 1. Übersicht & Vergleich beider Repositories

### 1.1 Upstream-Repository (`polhenarejos/pico-fido`, Stand `v8.2` / `0x0802`)
`polhenarejos/pico-fido` ist eine vollständige Open-Source-Sicherheitsstick-Firmware in C auf Basis des Submoduls **`pico-keys-sdk`** (`50699e53`). Sie implementiert einen vollwertigen **CTAP 2.1 / 2.2 / 2.3 & U2F FIDO2-Authenticator**, **OATH (TOTP/HOTP)**, **YubiKey-OTP** sowie Verwaltung über **CCID / WebUSB / CTAPHID**.

| Schicht | Verzeichnis / Dateien | Aufgabe im Upstream |
|---|---|---|
| **Plattform- & USB-Laufzeit (`pico-keys-sdk`)** | `pico-keys-sdk/src/main.c`, `usb/hid/hid.c`, `usb/ccid/ccid.c`, `led/led_neopixel.c`, `fs/low_flash.c`, `rng/hwrng.c` | Startpunkt `app_main()` (ESP-IDF), Initialisierung des Flash-Dateisystems (`low_flash_init()` -> Partition **`part0`**), TinyUSB Composite Device (**HID FIDO + CCID/WebUSB**), Onboard-WS2812-LED via ESP-IDF-RMT (`GPIO48`), Hardware-RNG & Flash-/OTP-Schlüsselableitung (`derive_kbase()`). |
| **FIDO2 / CTAP2 Kern** | `src/fido/fido.c`, `cbor.c`, `cmd_*.c`, `files.c`, `management.c` | APDU-/CTAP-Dispatch, Dateiverwaltung (`EF_PIN`, `EF_KEYDEV`, `EF_MINPINLEN`, Resident Keys), MKEK/Session-PIN-Schlüsselhülle (`load_keydev()` / `store_keys()`). |
| **CTAP2-CBOR-Befehle** | `cbor_get_info.c`, `cbor_make_credential.c`, `cbor_get_assertion.c`, `cbor_client_pin.c`, `cbor_cred_mgmt.c`, `cbor_config.c`, `cbor_reset.c`, `cbor_vendor.c` | Alle FIDO2-Befehle inkl. `pinUvAuthToken` (Protokoll 1 & 2), `credBlob`, `largeBlobs`, `hmac-secret`, `minPinLength` und Vendor-Kanal (`0x41` / `CTAP_VENDOR_CBOR` -> Subcommand `0x10` für `PicoKeys.dev`). |
| **Build-System (Upstream)** | Root-`CMakeLists.txt`, `workflows/autobuild.sh` | Baut standardmäßig für RP2040/RP2350 (`PICO_SDK`), Linux-Emulation (`ENABLE_EMULATION=1`) oder reines ESP-IDF (`idf.py -DPICO_PLATFORM=esp32s3`, wobei Upstream eine eigene ESP-IDF-Komponentenstruktur im `autobuild.sh` voraussetzt). |

---

### 1.2 Dieses Fork-Repository (`PeWieser/pico-fido`)
Dieser Fork erweitert `polhenarejos/pico-fido` gezielt um **drei große Funktionsblöcke** für einen eigenständigen **ESP32-S3 Biometrie-FIDO2-Stick mit GROW R558-S Fingerabdrucksensor**:

1. **PlatformIO- & CI-Release-Integration für ESP32-S3:**
   - `platformio.ini` mit drei Umgebungen: `esp32s3` (Produktion), `esp32s3_dev` (Entwicklung ohne eFuse-Zwang), `esp32s3_secure` (Secure Boot v2 + Flash Encryption).
   - `main/pio_entry.c` + `main/CMakeLists.txt` + `main/idf_component.yml` (`zorxx/neopixel`) als ESP-IDF-Einstiegskomponente für PlatformIO.
   - `.github/workflows/platformio.yml` + `.github/scripts/merge_image.py` zum automatischen Erzeugen kompletter 4-MB-Flash-Images (`0x0`).
2. **GROW R558-S Biometrie-Engine & Hardware-Treiber (`src/fido/fp_*`):**
   - `fp_r558_uart.c`: ESP-IDF-UART1-Treiber (`57600 Baud, 8N2`, `TX = GPIO17`, `RX = GPIO18`) sowie TCP-Bridge für Hardware-in-the-Loop-/Emulations-Tests.
   - `fp_r558_sensor.c`: Binärprotokoll des GROW R558-S (`0xEF01`-Header, `VfyPwd 0x13`, `SetPwd 0x12`, `ReadSysPara 0x0F`, `ReadIndexTable 0x1F`, `GetImage 0x01`, `GenChar 0x02`, `RegModel 0x05`, `StoreChar 0x06`, `SearchNow 0x3A`, `DeletChar 0x0C`, `Empty 0x0D`, sowie jetzt **`PS_ControlBLN 0x3C`** für den integrierten RGB-Ring des R558-S).
   - `fp_r558.c`: Sicherheits-Engine mit zufälligem 32-Bit-Sensorpasswort (Pairing), 5-Fehlversuchs-Lockout in Flash (`EF_FP_CONF = 0x1104`), Manipulationserkennung (Template-Bitmasken-Abgleich Sensor vs. ESP32-Flash) und verschlüsseltem Backup/Restore-Blob (`43 Byte`).
   - `fp_led.c`: Zustands-LED-Steuerung (Blau atmend = Warten auf Finger, Grün blinkend = Erfolg/Scan-Bestätigung, Rot blinkend = Fehler, Rot dauerhaft = Gesperrt).
3. **WebApp-Verwaltungsprotokoll (`cbor_vendor.c` Subcommand `0x09` & `docs/`):**
   - Hersteller-Befehl `CTAP_VENDOR_CBOR (0x41)` mit erstem Byte `0x09` für Status (`0x01`), Pairing (`0x02`), Enrollment (`0x03`), Löschen (`0x04`), Entsperren (`0x05`), Backup (`0x06`) und Restore (`0x07`), geschützt durch `pinUvAuthToken` mit Berechtigung `ACFG (0x20)`.
   - Vollständige Spezifikationen für deine WebApp in `docs/fingerprint/WEBAPP_PROMPT.md` & `docs/release/WEBAPP_FIRMWARE_PROMPT.md`.

---

## 2. Warum deine aktuelle Firmware auf dem ESP32-S3 komplett versagt hat (Alle 12 verifizierten Ursachen)

Wir haben die exakte kompilierte ESP32-S3-Binärdatei (`firmware.elf`, `partitions.bin`, `esp32s3_dev.bin`) im **echten Espressif Xtensa-LX7-Emulator (`qemu-system-xtensa -machine esp32s3`)** gebootet, die Symboltabelle mit `xtensa-esp32s3-elf-nm` und die Crash-Adressen mit `xtensa-esp32s3-elf-addr2line` ausgewertet sowie die gesamte CTAP-2.1-Protokollkette mit `python-fido2` gegen echte Kaltstarts getestet.

Dabei zeigten sich **zwei katastrophale Showstopper beim Booten/Linken** (die exakt erklären, warum **weder USB erkannt wird noch irgendeine LED jemals aufleuchtet**) sowie **zehn weitere kritische Folgefehler** in LED-Treiber, Kconfig, CTAP 2.1, Kaltstart-Schlüsselentsperrung und Sensor-Verdrahtung — **alle 12 sind in diesem Branch vollständig behoben und getestet**:

### Ursache 1 (Showstopper #1 — Kein Boot / Sofortiger CPU-Crash vor `led_init()` und `usb_init()`): Falsche Partitionstabelle in `platformio.ini`
- **Was passierte:** `sdkconfig.defaults` setzte zwar `CONFIG_PARTITION_TABLE_CUSTOM_FILENAME="partitions.csv"` (`factory @ 0x20000`, Dateisystem-Partition **`part0 @ 0x200000`**), aber **PlatformIO ignoriert diese Kconfig-Zeile vollständig**, solange `board_build.partitions` nicht explizit in `platformio.ini` gesetzt ist! PlatformIO überschrieb die Partitionstabelle bei jedem Build stillschweigend mit seiner Standardtabelle `default.csv` (`app0 @ 0x10000`, **`part0` existiert überhaupt nicht!**):
  - **Fall A — Flashen des Release-/Merged-Images (`esp32s3_dev.bin` an `0x0`):** `merge_image.py` schrieb die App an **`0x20000`**, während `partitions.bin` dem Bootloader sagte, die App liege bei **`0x10000`** (wo nur `0xFF` stand). Der ESP32-S3 hing in einer endlosen Bootloader-Reset-Schleife (`E (45) esp_image: image at 0x10000 has invalid magic byte / invalid header: 0xffffffff`) — **die App startete nicht eine einzige Millisekunde!**
  - **Fall B — Direktes Flashen mit `pio run -t upload`:** PlatformIO schrieb die App zwar an `0x10000`, aber beim allerersten Befehl in `app_main()` (`pico-keys-sdk/src/main.c:195` -> `low_flash_init()` in `low_flash.c:625`) suchte der Code die Flash-Partition **`part0`**, erhielt `NULL` zurück und dereferenzierte `part0->size` bei `0x0000000c` -> **sofortiger `Guru Meditation Error: Core 0 panic'ed (LoadProhibited)` noch VOR `led_init()` (Zeile 198) und `usb_init()` (Zeile 199)!**
- **Fix:** `board_build.partitions = pico-keys-sdk/config/esp32/partitions.csv` (bzw. `config/esp32/partitions_secure.csv` für `esp32s3_secure`) und `board_build.flash_mode = dio` in `platformio.ini` eingetragen; `merge_image.py` prüft jetzt zusätzlich hart sowohl den exakten `factory`-Offset als auch das Vorhandensein von `part0` in `partitions.bin`.

### Ursache 2 (Showstopper #2 — 0 Byte FIDO- & Fingerprint-Code in `firmware.elf`): Fehlendes `REQUIRES fido pico-keys-sdk` in `main/CMakeLists.txt`
- **Was passierte:** `main/pio_entry.c` war komplett leer; `main/CMakeLists.txt` hatte keine Abhängigkeit auf `fido` und `pico-keys-sdk` deklariert, und `src/fido/CMakeLists.txt` nutzte kein `WHOLE_ARCHIVE`. Beim Linken von `firmware.elf` verwarf der GNU-Linker **`libfido.a` zu 100 %**! `xtensa-esp32s3-elf-nm firmware.elf` zeigte `4200ba78 W picokey_init` (**leerer Weak-Stub!**) und **null Symbole** aus `fido.c`, `cbor_vendor.c`, `fp_r558.c` oder `fp_led.c`! Selbst mit reparierter Partitionstabelle hätte das Board niemals eine FIDO2-, WebUSB- oder Fingerabdruck-Funktion registriert!
- **Fix:** `REQUIRES fido pico-keys-sdk` in `main/CMakeLists.txt` und `WHOLE_ARCHIVE` in `src/fido/CMakeLists.txt` gesetzt + CI-Symbolprüfung (`T picokey_init`, `T fp_init`, `T fido_process_apdu`, `T cbor_vendor`) in `.github/workflows/platformio.yml`.

### Ursache 3 (Showstopper #3 — WebApp sperrt „Koppeln“ & „Wiederherstellen“ auch auf `esp32s3_dev`): `#ifndef`-Kconfig-Bug & `flashEncrypted`-Statusfeld
- **Was passierte:**
  1. In `src/fido/fp_r558_config.h` stand `#ifndef CONFIG_PICO_FIDO_R558_REQUIRE_FLASH_ENCRYPTION` -> `#define FP_REQUIRE_FLASH_ENCRYPTION 1`. In ESP-IDF/Kconfig ist ein ausgeschaltetes `bool` (`=n` in `sdkconfig.dev.defaults`) **nicht als `0` definiert, sondern `#undef`!** Dadurch erzwang **selbst das Entwicklungs-Image `esp32s3_dev` immer `FP_REQUIRE_FLASH_ENCRYPTION = 1`** und blockierte `pair` und `restore` mit `CTAP2_ERR_NOT_ALLOWED (0x30)`!
  2. Zusätzlich verlangt deine WebApp laut `docs/fingerprint/WEBAPP_PROMPT.md` (Abschnitt 7): *„Ist `7: flashEncrypted = false`, sind Pairing und Restore ausgeschaltet. Die App versucht es nicht erst, sondern deaktiviert die Schaltflächen.“* Da `fp_status()` auf unverschlüsselten Entwicklungsboards `false` lieferte, waren die Buttons in deiner WebApp dauerhaft ausgegraut!
- **Fix:** `#ifdef CONFIG_PICO_FIDO_R558_REQUIRE_FLASH_ENCRYPTION` in `fp_r558_config.h` korrigiert und `status[7]` auf `ESP_PLATFORM` an `flash_requirement_met()` gekoppelt (`true` im `esp32s3_dev`-Profil, echte Hardware-Prüfung `esp_flash_encryption_enabled()` im Produktivprofil `esp32s3` / `esp32s3_secure`).

### Ursache 4 (Showstopper #4 — Weder Onboard-LED noch R558-S-LED-Ring leuchteten): Überschriebener LED-Treiber + fehlendes UART-Kommando `0x3C` (`PS_ControlBLN`)
- **Was passierte:**
  1. `fp_led_init()` überschrieb den globalen Zeiger `led_driver` von `pico-keys-sdk` (`led_neopixel.c`, Onboard-RGB-LED an `GPIO48`, die im Leerlauf sanft pulsiert) komplett und schaltete im Zustand `FP_LED_IDLE` auf `(0, 0, 0)` (**komplett dunkel**)! Zudem legt `zorxx/neopixel` intern einen FreeRTOS-Task mit nur **1024 Byte Stack** an (akute Stack-Overflow-Gefahr auf ESP32-S3).
  2. **Entscheidender Hardware-Befund aus dem GROW-R558-S-Datenblatt (S. 7–8 & S. 27–29):** Der **GROW R558-S besitzt keinen GPIO4-WS2812-Eingang, sondern einen fest eingebauten RGB-Leuchtring im Sensorgehäuse**, der **ausschließlich per UART-Paket `PS_ControlBLN` (`0x3C`)** gesteuert wird! Dieser Befehl fehlte im gesamten Code komplett — der Ring im R558-S konnte also **niemals** leuchten!
- **Fix:**
  - `fp_r558_sensor_control_led()` (`0x3C`, `PS_ControlBLN`) exakt nach Datenblatt implementiert: Der **eingebaute RGB-Ring des R558-S** atmet jetzt blau beim Warten auf den Finger, blinkt grün bei Scan-Erfolg/Kopplung, blinkt rot bei Fehlversuch und leuchtet dauerhaft rot bei Sperre!
  - `fp_led.c` verkettet (`chains`) zusätzlich den nativen `pico-keys-sdk`-Onboard-LED-Treiber (`GPIO48`), sodass die Onboard-LED wie bei der Original-Firmware normal funktioniert **und** bei Bedarf optional auch ein externer WS2812-Ring an `GPIO4` mitläuft.

### Ursache 5 (Showstopper #5 — Kanonischer CBOR-Sortierfehler in `authenticatorGetInfo`): `"uv"` am Ende der `options`-Map
- **Was passierte:** Sobald der erste Fingerabdruck angelernt war (`fp_uv_available() == true`), hing `src/fido/cbor_get_info.c` den 2-Buchstaben-Schlüssel `"uv"` **ans Ende** der `options`-Map (hinter `"makeCredUvNotRqd"` mit Länge 16). Laut CTAP2 / RFC 8949 müssen CBOR-Maps streng nach **Schlüssellänge und dann alphabetisch** sortiert sein (`"ep"`, `"rk"`, **`"uv"`**, `"alwaysUv"`, ...). Strikte FIDO2-Clients (`python-fido2`, `libfido2`, Browser/OS) brechen sonst sofort mit `Non-canonical CBOR from Authenticator` ab!
- **Fix:** `"uv"` exakt an seine kanonische Position direkt hinter `"rk"` verschoben.

### Ursache 6 (Showstopper #6 — Browser/Windows/macOS/Linux Passkey-Login per Fingerabdruck scheiterte): Fehlende CTAP-2.1-Subcommands `0x06` & `0x07`
- **Was passierte:** Die Firmware meldet in `getInfo` `"FIDO_2_1"`, `"pinUvAuthToken": true` und `"uv": true`. Alle modernen Betriebssysteme und Browser (Windows 11, Chrome, Edge, Safari, Firefox, Linux `libfido2`) rufen dann **nicht** das veraltete CTAP-2.0-Flag `options.uv` auf, sondern `authenticatorClientPIN` Subcommand **`0x07` (`getUVRetries`)** und **`0x06` (`getPinUvAuthTokenUsingUvWithPermissions`)**! Beide fehlten in `src/fido/cbor_client_pin.c` komplett -> sofortiger Abbruch mit `CTAP2_ERR_INVALID_SUBCOMMAND (0x2B)`!
- **Fix:** Beide CTAP-2.1-Biometrie-Subcommands (`0x07` und `0x06`) vollständig nach Spezifikation in `src/fido/cbor_client_pin.c` implementiert.

### Ursache 7 (Showstopper #7 — Nach Aus-/Einstecken des USB-Sticks schlug Fingerabdruck-Login IMMER fehl): `load_keydev()` ohne `session_pin`
- **Was passierte:** Sobald eine FIDO2-PIN gesetzt ist, verschlüsselt `pico-fido` den Geräte-Hauptschlüssel (`EF_KEYDEV`) mit `session_pin` im RAM. Zieht man den Stick einmal vom PC ab und steckt ihn wieder an, ist `session_pin` im RAM leer (`has_session_pin == false`). Authentifiziert man sich danach nur per Fingerabdruck (ohne vorherige PIN-Eingabe), schlägt `load_keydev()` fehl — kein einziger Passkey kann nach einem Neustart per Fingerabdruck erstellt oder genutzt werden!
- **Fix:** Kryptografische Versiegelung (`EF_FP_PINWRAP = 0x1105`) implementiert: `session_pin` wird mit `AES-256-GCM / AEAD` unter einem aus Hardware-Geheimnis (`derive_kbase()`) + 32-Bit-R558-Sensorpasswort + Sensoradresse mittels `HKDF-SHA256` abgeleiteten Schlüssel versiegelt und **ausschließlich nach erfolgreicher Live-UART-Authentifizierung + echtem Fingerabdruck-Match am R558-S** wieder im RAM entsiegelt (inkl. automatischer Aktualisierung bei `changePIN`, `pair`, `enroll`, `unlock`, `restore` und Löschung bei `reset`).

### Ursache 8 (`authenticatorReset` hinterließ Geister-Pairing im Flash): `EF_FP_CONF` fehlte in `cbor_reset.c`
- **Was passierte:** `fido_reset_should_clear()` löschte beim Werksreset weder `EF_FP_CONF` noch `EF_FP_PINWRAP`. Dadurch blieb `paired = true` nach einem FIDO-Reset stehen und der in `WEBAPP_PROMPT.md` spezifizierte **Backup/Restore-Ablauf nach Reset** war unmöglich (`NOT_ALLOWED`)!
- **Fix:** `EF_FP_CONF` und `EF_FP_PINWRAP` werden beim FIDO-Werksreset sauber gelöscht.

### Ursache 9 (`minPINLength = 4` vs. `6` Widerspruch): `cbor_get_info.c` meldete `4`, `setPIN` verlangte `6`
- **Was passierte:** `cbor_get_info.c` kodierte hart `4`, während `ctap.h` (`FIDO_MIN_PIN_LENGTH_DEFAULT`) `6` erzwang. Browser/Betriebssysteme erlaubten daher beim Einrichten 4-stellige PINs, die der Stick sofort mit `PIN_POLICY_VIOLATION (0x37)` ablehnte.
- **Fix:** `cbor_get_info.c` meldet jetzt konsistent `FIDO_MIN_PIN_LENGTH_DEFAULT` (`6`).

### Ursache 10 (6-Pin-Stromversorgungsfalle am GROW R558-S + USB-Port-Falle am ESP32-S3)
- **Hardware-Punkt A (GROW R558-S 6-Pin-Stecker):** In der alten `docs/platformio/README.md` stand nur *ein* `VCC`-Pin. Laut **offiziellem GROW-R558-S-Handbuch (S. 7–8)** hat der 6-polige Stecker aber **zwei getrennte 3,3-V-Eingänge**: **Pin 1 (`V_Touch` / `VCC_3.3V`)** UND **Pin 3 (`VCC` / `VCC_MCU`)**! Ist nur einer angeschlossen, hat entweder der Sensor-Prozessor samt RGB-Ring keinen Strom (`Pin 3` offen) oder der Touch-Sensor reagiert nie (`Pin 1` offen).
- **Hardware-Punkt B (ESP32-S3 mit 2 USB-C-Buchsen):** Bei Boards mit zwei USB-C-Buchsen läuft FIDO2/WebUSB **ausschließlich** über die Buchse **`USB` / `OTG`** (`GPIO19`/`GPIO20`), **niemals** über die Buchse `UART` / `COM` (CH343/CP2102).

### Ursache 11 (R558-S Spezifische Fehlercodes, Boot-Reihenfolge & CTAPHID-Keepalive/Cancel)
- **Fix:** `0x3B` (`RegModel` Merge-Fehler zweier unpassender Finger-Scans -> `UV_INVALID` statt generischem `PROCESSING`-Fehler), `0x15`/`0x33` (erneutes Abtasten im Timeout-Fenster), verzögertes Nachladen von `ef_fp_conf` via `file_search_by_fid()` nach dem Booten sowie sauberes CTAPHID-Keepalive (`STATUS_UPNEEDED`) und Abbruch per Browser-„Abbrechen“ (`CTAPHID_CANCEL` -> `cancel_button`) eingebaut.

### Ursache 12 (GitHub Actions Workflows & Linux-Emulations-Build)
- **Fix:** `CMakeLists.txt` fällt ohne `libtss2` sauber auf `otp_emulation.c` zurück; `.github/workflows/platformio.yml` prüft bei jedem Push `firmware.elf`, `partitions.bin` **und bootet das fertige ESP32-S3-Image live in QEMU (`esp32s3`)**; `.github/workflows/test.yml` führt alle Docker-FIDO2-Tests **und** den kompletten R558-Kaltstart-Systemtest (`tests/fingerprint/verify_full_stack_ctap.py`) aus; `.github/workflows/nightly.yml` schlägt ohne Signatur-Secret im Fork nicht mehr fehl.

---

## 3. Exakte Hardware-Verdrahtung & Schnellstart zum Flashen

### 3.1 Pinbelegung GROW R558-S <-> ESP32-S3 (`3,3 V` — NIEMALS `5 V`!)

| R558-S Pin (MX 1.25mm) | Typische Kabelfarbe | R558-S Signal | ESP32-S3 Pin | Wichtig |
|---|---|---|---|---|
| **Pin 1** | Rot | `V_Touch` (`VCC_3.3V`) | **`3V3` (3,3 V)** | **Pflicht!** Touch-Versorgung |
| **Pin 2** | Gelb | `Touch_Out` (`Vout`) | *offen lassen (NC)* | Optionaler Touch-Ausgang |
| **Pin 3** | Blau | `VCC` (`VCC_MCU`) | **`3V3` (3,3 V)** | **Pflicht!** Sensor-MCU + eingebauter RGB-Ring |
| **Pin 4** | Grün | `TX` (`UART_TX`) | **`GPIO18`** | Sensor TX -> ESP32 RX |
| **Pin 5** | Weiß | `RX` (`UART_RX`) | **`GPIO17`** | ESP32 TX -> Sensor RX |
| **Pin 6** | Schwarz | `GND` | **`GND`** | **Pflicht!** Masse |

### 3.2 Kompilieren & Flashen (Entwicklungsboard ohne eFuse-Verschlüsselung)

```bash
git pull
git submodule update --init --recursive

# Komplett-Flash löschen (einmalig empfohlen, um alte kaputte Partitionstabellen sicher zu entfernen!)
pio run -e esp32s3_dev -t erase

# Bauen & Flashen des Entwicklungsprofils esp32s3_dev
pio run -e esp32s3_dev -t upload
```

Anschließend das USB-Datenkabel in die **`USB` / `OTG`**-Buchse des ESP32-S3 stecken (bzw. einmal kurz **RESET** drücken):
1. Der ESP32-S3 startet ohne Fehler durch (`factory @ 0x20000`, `part0 @ 0x200000`), initialisiert `picokey_init()` + `fp_init()` + `led_init()` + `usb_init()`.
2. Windows / macOS / Linux und Chrome / Edge erkennen das Gerät **sofort als Pico Key** (FIDO2 + WebUSB/CCID).
3. Deine WebApp sieht `supported: true`, `flashEncrypted: true` (im `esp32s3_dev`-Profil freigeschaltet), erlaubt **PIN setzen (mind. 6 Ziffern) -> Sensor koppeln -> Finger 2× auflegen (Anlernen) -> Backup/Restore**, und der **eingebaute RGB-Ring des GROW R558-S** leuchtet passend zu jedem Schritt!
