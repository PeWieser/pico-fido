# R558 Fingerabdrucksensor an ESP32-S3 Super Mini – Plan und Umsetzung

Dieses Dokument beschreibt die Einbindung eines R558(-S)-Fingerabdrucksensors in Pico FIDO auf dem
ESP32-S3 Super Mini. Es ist der Stand der Umsetzung im Branch `arena/c392330f-pico-fido`.

**Wichtig vorab:** Die Firmware wurde nur auf dem Host getestet (Protokoll- und Engine-Tests mit einem
simulierten Modul). Ein ESP-IDF-Build und ein Test mit echter Hardware sind **noch nicht erfolgt**.
Siehe Abschnitt 9.

---

## 1. Anforderungen (aus der Aufgabe)

| # | Anforderung | Umsetzung |
|---|---|---|
| 1 | Sensor R558 an ESP32-S3 Super Mini | UART-Anbindung, `src/fido/fp_r558_*.c` |
| 2 | Angreifer darf keinen anderen Sensor anstecken und Zugriff auf Keys erhalten | Sensor-Pairing mit PIN, geheimes Passwort und Adresse, Prüfung vor jeder Verifikation, Sperre bei Manipulation (Abschnitt 4) |
| 3 | Anlernen von Fingerabdrücken ausschließlich über die Webapp | Vendor-Befehl `CTAP_VENDOR_FP` (0x09) mit PIN-Token (ACFG), ohne Taster. Keine Geräte-seitige Anlernfunktion (Abschnitt 5) |
| 4 | Prompt für eine andere KI zur Integration des Anlern-UI | `docs/fingerprint/WEBAPP_PROMPT.md` |
| 5 | LED: Ruhe aus | Ring aus, wenn kein FIDO-Vorgang läuft |
| 6 | LED: Passkey-Abfrage vom PC blau | `fp_led_op_begin()` in `cbor.c` (MakeCredential, GetAssertion) |
| 7 | LED: Erfolg grün, Fehlschlag rot | `fp_led_op_end(ok)`, 1,5 s |
| 8 | LED: Passkey-Speicherung blau pulsierend | `fp_led_saving(true)` um die Passkey-Speicherung (nur Credentials, nicht Templates) |
| 8a | LED: Anlernen blau atmend (leicht → stark) | `fp_led_enrolling(true)` während `fp_enroll()`; kein Taster |
| 8b | Keine Taster-Pflicht | Pairing, Anlernen, Löschen und Entsperren brauchen nur das PIN-Token; der Sensor ist die einzige Benutzerinteraktion |

---

## 2. Hardware

### 2.1 Verkabelung (Standardwerte, in `fp_r558_config.h` überschreibbar)

| Signal | ESP32-S3 Super Mini | R558 |
|---|---|---|
| Versorgung | 3V3 | VCC (3,3 V; **nicht 5 V**, der Sensor ist nicht 5-V-fest) |
| Masse | GND | GND |
| UART TX (ESP → Sensor) | GPIO17 | RX des Sensors |
| UART RX (Sensor → ESP) | GPIO18 | TX des Sensors |
| LED-Ring Daten | GPIO4 | DIN des Rings |

- **Bitte die GPIO-Nummern gegen das Pinout deines Boards prüfen.** Die Standardwerte sind so gewählt,
  dass sie nicht mit USB (GPIO19/20), Boot (GPIO0) oder den Strapping-Pins kollidieren.
- Der LED-Ring läuft üblicherweise mit 5 V. Die Datenleitung vom ESP (3,3 V) reicht meist, sicherheitshalber
  einen Pegelwandler verwenden. Die Ring-Versorgung kommt von 5 V, nicht vom 3V3-Pin.
- Der Touch-Ausgang (`TOUCH`) des R558 wird **nicht** verwendet.
- Die Leitungen zum Sensor sollten kurz sein und nicht frei zugänglich, siehe Restrisiko R1.

### 2.2 Protokoll des Sensors

- UART 57600 Baud, 8 Datenbits, keine Parität, **2 Stoppbits** (8N2, Handbuch Abschnitt IV). Die Firmware nutzt
  8N2 in `fp_r558_uart.c`. Das Power-on-Byte `0x55` des Moduls wird vom Paket-Parser übersprungen (Header-Suche).
- Paketformat: `EF 01 | Adresse(4) | PID(1) | Länge(2) | Payload | Prüfsumme(2)`. Prüfsumme = Summe über PID, Länge und
  Payload (Modulo 65536).
- Bestätigt aus dem R558-S-Handbuch (V1.1): Standardpasswort `0x00000000`, Standardadresse `0xFFFFFFFF`,
  Passwort wird nach Änderung im Flash gespeichert und kann nicht ausgelesen werden, nach Einschalten muss zuerst
  `VfyPwd` gesendet werden, und die Adresse ist per `SetChipAddr` fest, nur ein Flash-Löschen setzt sie zurück.
- Gegen das R558-S-Handbuch (V1.1, Datei `r558-s-fingerprint-module-user-manual-v1-1-1-2-1_compress.pdf`)
  geprüft: Befehlscodes `GenImg 0x01`, `Img2Tz (Genchar) 0x02`, `Search 0x04`, `RegModel 0x05`, `Store 0x06`,
  `LoadChar 0x07`, `DeletChar 0x0C`, `Empty 0x0D`, `ReadSysPara 0x0F`, `SetPwd 0x12`, `VfyPwd 0x13`,
  `SetChipAddr 0x15`. Bestätigungscodes `0x00`, `0x02`, `0x03`, `0x06`–`0x0A`, `0x13`, `0x15`, `0x18` stimmen.
  Parameterlayouts (Search, DeletChar, SetPwd/VfyPwd, SetChipAddr) stimmen.
- Noch nicht am echten Modul getestet. Die Antwortlängen von `ReadSysPara` und die Antwortzeiten von `Search`
  sind nur aus dem Handbuch übernommen.

---

## 3. Architektur

```
Passkey-Anfrage (PC) ─► cbor.c ─► cbor_make_credential.c / cbor_get_assertion.c
                                      │  uv=true (ohne PIN-Token) ─► fp_uv_ctap_status()
                                      ▼
                              fp_r558.c (Engine)  ◄─── Konfiguration: EF_FP_CONF 0x1104 (verschlüsselt im Objektspeicher)
                                      │
                              fp_r558_sensor.c (Paketschicht, testbar auf dem Host)
                                      │
                              fp_r558_uart.c (ESP-IDF UART1, sonst Stub)

Webapp ─► CTAP-HID Vendor-CBOR (0x41) ─► cbor_vendor.c, Befehl CTAP_VENDOR_FP (0x09)
                                      │  Unterbefehle 0x01–0x05 (siehe WEBAPP_PROMPT.md)
                                      ▼
                              fp_r558.c

fp_init.c: picokey_init() (überschreibt den WEAK-Hook) ─► fp_led_init() (Ring-Treiber) + fp_init()
fp_led.c:  Ring-Treiber auf NeoPixel-Basis, überschreibt led_driver (nur ESP mit Feature)
```

| Datei | Zweck |
|---|---|
| `src/fido/fp_r558_sensor.[ch]` | Paketformat, Prüfsumme, Befehle des Moduls. Keine Abhängigkeit zur Firmware. |
| `src/fido/fp_r558_uart.[ch]` | UART-Transport (ESP-IDF). Auf anderen Plattformen ein Stub, der immer Fehler meldet. |
| `src/fido/fp_r558.[ch]` | Engine: Pairing, Verifikation, Enrollment, Löschen, Sperre, Konfiguration. |
| `src/fido/fp_r558_config.h` | GPIOs, Ring-Größe, Timeouts, Fehlgrenze. |
| `src/fido/fp_led.[ch]` | Ring-Zustandsmaschine und Treiber. |
| `src/fido/fp_init.c` | `picokey_init()`-Hook. |
| `src/fido/cbor_vendor.c` | Vendor-Befehl `CTAP_VENDOR_FP` (0x09) inkl. PIN-Authentifizierung. |
| `src/fido/cbor_make_credential.c`, `cbor_get_assertion.c`, `cbor_get_info.c` | UV-Pfad über den Fingerabdruck, Option `uv` in getInfo. |
| `src/fido/cbor.c` | LED-Klammer um MakeCredential und GetAssertion. |
| `src/fido/files.[ch]`, `ctap.h`, `fido.c` | Neue Datei `EF_FP_CONF` (0x1104), Konstante `CTAP_VENDOR_FP`. |
| `CMakeLists.txt`, `src/fido/CMakeLists.txt` | Option `ENABLE_R558_FINGERPRINT` (Standard: EIN auf ESP32, AUS sonst), Quellen, Komponente `driver`. |
| `tests/fingerprint/` | Host-Tests für Paketschicht und Engine (Abschnitt 8). |

### 3.1 Konfigurationsschalter

- Standard: **EIN** auf ESP32, **AUS** auf RP2040/RP2350 und in der Emulation.
- Ausschalten: `idf.py -D ENABLE_R558_FINGERPRINT=OFF build` bzw. `cmake -DENABLE_R558_FINGERPRINT=OFF ...`.
- Bei AUS verhält sich das Gerät wie vorher: keine `uv`-Option in getInfo, keine Fingerabdruck-UV, keine LED-Änderung.

---

## 4. Sicherheitsmodell

### 4.1 Vertrauensanker

1. **Die PIN ist die Wurzel des Vertrauens.** Pairing, Enrollment, Löschen und Entsperren verlangen ein PIN-Token
   mit der Berechtigung `authenticatorConfig` (ACFG). Ohne gesetzte PIN ist kein Pairing möglich.
2. **Pairing setzt ein zufälliges Passwort und eine zufällige Adresse** im Sensor (4 Byte je). Beides wird in
   `EF_FP_CONF` (0x1104) im Flash-Datenbereich gespeichert. **Der Schutz im Ruhezustand hängt an der
   ESP32-Flash-Verschlüsselung.** Der Objektspeicher des SDK verschlüsselt diese Datei nicht selbst; das habe ich
   im Quelltext nicht gefunden (siehe R1).
3. **Vor jeder Verifikation** wird das gespeicherte Passwort an der gespeicherten Adresse geprüft (`VfyPwd`).

### 4.2 Was passiert bei einem Sensortausch

| Angriff | Ergebnis |
|---|---|
| Fremder Sensor (Werkszustand) wird angesteckt, Verifikation wird verlangt | Der Sensor antwortet nicht auf die gespeicherte Adresse → `FP_ERR_SENSOR`, **kein** UV, **keine** Sperre, nichts wird verändert. |
| Fremder Sensor mit eigenem Passwort, das aber an der gespeicherten Adresse antwortet | `VfyPwd` schlägt fehl → `FP_ERR_SENSOR_AUTH`, **sofortige Sperre** der UV. |
| Fremder Sensor wird **neu gepairt** | Nur mit PIN-Token (kein Tastendruck). Es ist nur möglich, wenn der **bisherige** Sensor nicht mehr antwortet. Vor dem Pairing werden alle Templates des neuen Sensors gelöscht. |
| Sensor mit bereits gesetztem Passwort (anderer Besitzer) | `FP_ERR_NOT_FACTORY`, wird abgelehnt. |
| Sensor enthält Template, das diese Firmware nicht angelegt hat | Engine prüft den Slot gegen die eigene Belegungsliste. Unbekannter Slot → Sperre. |
| Fehlversuche (Finger passt nicht) | Nach `FP_MAX_FAILED_ATTEMPTS` (Standard 5) in Folge Sperre. Entsperren nur mit PIN-Token (`0x05`). Timeouts zählen nicht. |

Gegenüber dem Anforderungsziel bedeutet das: **Allein durch Anstecken eines anderen Sensors bekommt man keinen
UV-Zugriff.** Dafür braucht man die PIN.

### 4.3 Restrisiken (ehrlich)

- **R1 – Mitlesen auf der UART-Leitung.** Passwort und Adresse laufen im Klartext über die Leitung. Wer während
  des Betriebs die Leitung abhört, kann ein Passwort und eine Adresse auslesen und einen **Fake-Sensor** bauen,
  der jedes Finger-Match bestätigt. Gegenmaßnahmen: Sensor im Gehäuse, kurze Leitungen, keine frei zugänglichen
  Testpunkte. Langfristig empfohlen: **ESP32-Flash-Verschlüsselung und Secure Boot aktivieren**, damit die
  Konfiguration nicht aus dem Flash gelesen und die Firmware nicht verändert werden kann. Ohne Flash-Verschlüsselung
  liegen Passwort und Adresse im Klartext im Flash, und wer den Chip auslesen kann, kann einen Fake-Sensor bauen.
  Das Repo aktiviert beides derzeit nicht (siehe `config/esp32/sdkconfig.defaults` im SDK).
- **R2 – Der Sensor ist nicht authentisch.** Der R558 hat keine Kryptografie für Gerätezertifikate. Ob ein Modul
  „echt“ ist, lässt sich nicht prüfen. Die Sicherheit beruht allein auf dem geheimen Passwort und der Adresse (R1).
- **R3 – FIDO-Reset.** Ein Reset des Authenticators löscht `EF_FP_CONF`. Der Sensor behält aber das alte Passwort
  und die Adresse. Ein Wiederverwenden desselben Sensors erfordert dann ein Zurücksetzen des Sensors auf Werks-
  einstellung (Flash löschen, Befehl `RestSetting 0x3B` laut Datenblatt; ob er ohne Passwort funktioniert, ist noch zu prüfen). Ein neuer Sensor geht
  sofort.
- **R4 – Kein Tastendruck.** Pairing, Enrollment, Löschen und Entsperren verlangen nur das PIN-Token. Der
  Fingerabdrucksensor ist die einzige Interaktion am Gerät. Die Vendor-Befehle 0x02–0x05 prüfen bewusst
  keinen `up_btn`. Die Sicherheit beruht auf PIN plus Sensorbindung (Abschnitt 4.1).
- **R5 – Enrollment-Unterbrechung.** Ein abgebrochenes Enrollment hinterlässt keinen Eintrag (der Slot wird erst
  nach erfolgreichem `Store` belegt). Ein Template könnte aber im Sensor liegen, wenn der Stromausfall genau
  zwischen `Store` und dem Flash-Commit passiert. Dieses Template liegt dann in einem freien Slot und wird beim
  nächsten Pairing gelöscht oder beim nächsten Enrollment überschrieben.
- **R6 – Biometrie bleibt im Sensor.** Templates verlassen den Sensor nicht. Die Firmware kennt nur Slot-Nummern.

---

## 5. Enrollment über die Webapp

- Anlernen ist **nur** über die Webapp möglich, ohne Taster. Der Sensor ist die einzige Interaktion am Gerät.
- Die Firmware hat **keine** Anlernfunktion am Gerät. Alle Befehle des Unterbefehls-Satzes `CTAP_VENDOR_FP` sind
  PIN-geschützt (mit Ausnahme von `0x01 status`).
- Der Ablauf für das Anlernen (2 Scans, Finger abheben zwischen den Scans) steht in `fp_enroll()`.
- Die Anweisungen für den Benutzer zeigt die Webapp (Prompt: `WEBAPP_PROMPT.md`). Das Gerät zeigt den
  Fortschritt über den Ring an.
- Der Befehl blockiert bis zu etwa 60 Sekunden (jeweils 20 s Zeitlimit für jeden Fingerschritt).

---

## 6. LED-Verhalten

| Zustand | Ring |
|---|---|
| Ruhe | aus |
| Passkey-Anfrage (MakeCredential/GetAssertion läuft, auch während der Fingerprint-Abfrage) | blau, stetig |
| Enrollment läuft (Vendor-Befehl 0x03) | blau, atmend zwischen leichtem und starkem Blau (Periode 2,4 s) |
| Passkey (Credential) wird gespeichert | blau, pulsierend (Periode 1,2 s). Template-Speicherung pulsiert **nicht** |
| Erfolg | grün, 1,5 s, dann aus |
| Fehlschlag (kein Match, Timeout, Sperre, Fehler) | rot, 1,5 s, dann aus |
| Pairing / Löschen / Entsperren (Vendor-Befehl) | blau, stetig, dann grün oder rot über `fp_led_op_begin/end` |

Hinweis: Die bestehenden LED-Modi des SDK (Mounted, Suspended, Button, ...) werden **auf dem Ring ignoriert**. Der
Onboard-RGB-LED (GPIO48) wird nicht mehr angesteuert, sobald der Ring aktiv ist.

---

## 7. Schnittstelle für die Webapp (Kurzfassung)

Vollständige Beschreibung inkl. PIN-Protokoll: `docs/fingerprint/WEBAPP_PROMPT.md`.

- Transport: CTAP-HID, Befehl `CTAP_VENDOR_CBOR` = `0xC1` (`CTAPHID_VENDOR_FIRST + 1`), Nutzlast = `0x09` gefolgt von einer CBOR-Map.
- Unterbefehle (Schlüssel 1): `0x01 status` (ohne Auth), `0x02 pair`, `0x03 enroll`, `0x04 delete`, `0x05 unlock`.
- Auth: `pinUvAuthParam` über `32×0xFF || 0x0D || Unterbefehl || rohe CBOR-Bytes von Schlüssel 2` mit dem
  PIN-Token (Berechtigung ACFG = 0x20).

---

## 8. Tests und Prüfstand

| Test | Ergebnis |
|---|---|
| `tests/fingerprint/run_r558_sensor_test.sh` – Paketschicht gegen simuliertes Modul (Vektor aus Datenblatt, Junk-Bytes, Prüfsummenfehler, falsche Adresse, Timeout) | bestanden |
| `tests/fingerprint/run_r558_engine_test.sh` – Engine (Pairing, Enrollment, Verifikation, Sperre, Sensortausch, Manipulation, unbekanntes Template, unterbrochenes Pairing, Nicht-Werkszustand, Löschen) | bestanden (40 Prüfungen) |
| Emulations-Build (`cmake -DENABLE_EMULATION=1`), vorhandene C-Tests `fido_*_test` | bestanden |
| Emulations-Build, Gesamtbinary `pico_fido` | **nicht baubar** in dieser Umgebung (fehlende Bibliothek `tss2`, nur Linux-OTP). Vorbestehend, unabhängig von dieser Änderung. |
| `pytest`-Suite (`tests/`) | nicht ausgeführt, benötigt das Gesamtbinary |
| ESP-IDF-Build (`idf.py build`) | **nicht ausgeführt** (ESP-IDF in dieser Umgebung nicht verfügbar) |
| Hardware (R558 + Ring am ESP32-S3) | **nicht ausgeführt** |

Die Engine-Tests benötigen einen vorherigen Emulations-Build (für die Header der Dritt-Bibliotheken), siehe
Kopf von `run_r558_engine_test.sh`.

### 8.1 Offene Punkte vor dem Einsatz

1. ESP-IDF-Build durchlaufen lassen und die Warnungen prüfen (besonders `neopixel.h`-Aufrufe in `fp_led.c`
   und `uart_*`-Aufrufe in `fp_r558_uart.c`).
2. Am echten Modul prüfen: Antworten gegen das Handbuch (Abschnitt 2.2 ist bereits mit dem Datenblatt abgeglichen),
   Antwortzeiten von `Search` und Stoppbits (8N2 laut Datenblatt).
3. Prüfen, ob die Browser mit der geänderten `uv`-Option in getInfo und den MC/GA-Optionen `uv: true`
   zurechtkommen (Chrome, Firefox, Safari). Diese Änderung folgt der CTAP-2.1-Idee des integrierten UV und wurde
   nicht gegen Konformitätstests geprüft.
4. Erneut prüfen, dass `uv=true` in GetAssertion ohne Fingerabdruck weiterhin abgelehnt wird (wie vorher).

---

## 9. Offene Entscheidungen (Rückfragen an dich)

1. **LED-Ring:** Beantwortet. Standard übernommen: WS2812, 12 Pixel, Daten GPIO4.
2. **Verkabelung:** Beantwortet. Sensor UART TX GPIO17, RX GPIO18. Ring GPIO4.
3. **Blaupulsierung:** Beantwortet. Pulsieren nur beim **Speichern eines Passkeys**. Template-Speicherung nicht.
   Das Anlernen zeigt stattdessen blaues Atmen (Abschnitt 6).
4. **Tastendruck:** Beantwortet. Kein Tastendruck. PIN genügt. Der Sensor ist die einzige Interaktion.
5. **Fehlgrenze:** 5 Fehlversuche in Folge, danach Sperre bis PIN-Entsperren. Passt das?
6. **Secure Boot und Flash-Verschlüsselung** für den ESP32-S3: Beantwortet. Vorbereiten als Folgeschritt (siehe R1). Noch
   nicht umgesetzt. `sdkconfig.defaults` enthält derzeit weder Secure Boot noch Flash-Encryption.
7. **Enrollment-Transport:** Umgesetzt als CTAP-HID-Vendor-CBOR über WebHID. Alternativ wäre eine
   REST-Route über lwIP möglich, das ist aber nur mit USB-Netzwerk verfügbar und daher nicht empfohlen.
