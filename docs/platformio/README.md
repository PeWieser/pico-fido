# Pico FIDO mit PlatformIO bauen und flashen (ESP32-S3)

Diese Anleitung gilt für den ESP32-S3 (z. B. "Super Mini", 4 MB Flash, USB-C). Der Build läuft über
PlatformIO mit dem ESP-IDF-Framework und nutzt dieselbe CMake-Konfiguration wie `idf.py`.

## 1. Voraussetzungen

- Python 3 und VS Code mit der Erweiterung **PlatformIO IDE**, oder nur PlatformIO Core (`pip install platformio`).
- Git mit Submodulen.
- Ein USB-C-Kabel, das Daten überträgt (kein reines Ladekabel).

## 2. Repository vorbereiten

```bash
git clone https://github.com/PeWieser/pico-fido.git
cd pico-fido
git submodule update --init --recursive
```

Die Submodule sind nötig. Ohne `pico-keys-sdk` bricht der Build ab.

## 3. Bauen (Wichtig: Profil wählen!)

Für **normale Entwicklungsboards ohne gebrannte Flash-Verschlüsselungs-eFuses** (Standardfall!) **unbedingt** das Entwicklungsprofil `esp32s3_dev` verwenden:

```bash
pio run -e esp32s3_dev
```

| Umgebung (`-e ...`) | Partitionstabelle | `factory`-Offset | Schlüsselspeicher (`part0`) | Einsatz |
|---|---|---|---|---|
| `esp32s3_dev` | `pico-keys-sdk/config/esp32/partitions.csv` | `0x20000` | `0x200000` (2 MB, unverschlüsselt) | **Standard für Test-/Bench-Hardware ohne Flash-Encryption-eFuses** |
| `esp32s3` | `pico-keys-sdk/config/esp32/partitions.csv` | `0x20000` | `0x200000` (2 MB) | Produktivprofil (erfordert aktive Hardware-Flash-Verschlüsselung) |
| `esp32s3_secure` | `config/esp32/partitions_secure.csv` | `0x30000` | `0x200000` (`encrypted`-Flag) | Secure Boot v2 + Flash Encryption (brennt eFuses!) |

Die erste Ausführung lädt ESP-IDF, die Toolchain und die verwalteten Komponenten herunter. Das dauert einige Minuten.
Das Ergebnis liegt unter `.pio/build/esp32s3_dev/`.

Die Versionen sind in `platformio.ini` festgelegt:

| Eintrag | Wert | Grund |
|---|---|---|
| `platform` | `espressif32@6.12.0` | liefert ESP-IDF 5.5.x |
| `framework-espidf` | (von der Plattform) `~3.50500.0` | ESP-IDF 5.5.0 |
| `board` | `esp32-s3-devkitc-1` | generischer ESP32-S3 |
| `board_upload.flash_size` | `4MB` | passend zu `sdkconfig.defaults` und `partitions.csv` |
| `board_build.flash_mode` | `dio` | stabiler Boot auf QSPI- und Octal-ESP32-S3-Modulen |
| `board_build.partitions` | `pico-keys-sdk/config/esp32/partitions.csv` | `factory @ 0x20000` + `part0 @ 0x200000` |


## 4. Richtigen USB-Port nutzen & in den Bootloader wechseln

**Wichtiger Hinweis zu ESP32-S3-DevKits mit 2 USB-C-Buchsen:**
- Der FIDO2-/Pico-Key-USB-Stack (TinyUSB HID + CCID/WebUSB) läuft **ausschließlich** über den **nativen USB-OTG-Port** des ESP32-S3 (**`GPIO19` = `D-`, `GPIO20` = `D+`**, auf DevKits beschriftet mit **`USB`** bzw. **`OTG`**).
- Die zweite Buchse (**`UART`** / **`COM`**, angebunden an einen CH343 / CP2102 USB-Seriell-Chip) kann **niemals** als FIDO-Key am PC erscheinen!
- Bei einem **ESP32-S3 Super Mini** (nur 1 USB-C-Buchse) liegt diese direkt auf `GPIO19`/`GPIO20` — dort unbedingt ein **echtes USB-Datenkabel** (kein reines Ladekabel) verwenden.

Zum erstmaligen Flashen den Chip in den Download-Modus versetzen:

1. Taste **BOOT** (`GPIO0`) gedrückt halten.
2. Kurz **RESET** (`RST`) drücken (oder das USB-Kabel bei gedrückter BOOT-Taste einstecken).
3. **BOOT** loslassen.

## 5. Flashen

Mit PlatformIO (flasht automatisch Bootloader, Partitionstabelle `partitions.bin` und Firmware `0x20000`):

```bash
pio run -e esp32s3_dev -t upload
```

Oder mit dem fertigen Komplett-Image (`esp32s3_dev.bin`) ab Adresse **`0x0`**:

```bash
esptool.py --chip esp32s3 --baud 460800 write_flash --flash_mode dio --flash_size 4MB 0x0 pico-fido-esp32s3-dev-*.bin
```

Danach den Chip einmal per **RESET**-Taste (oder kurzes Aus-/Einstecken am **`USB`**-OTG-Port) neu starten. Das Gerät meldet sich sofort als **Pico Key** (`VID 0x20A0` / konfigurierte VID:PID, WebUSB + CTAPHID + CCID) und der LED-Status startet.

## 6. Serielle Ausgabe

Auf einem Board mit separater `UART`-Buchse (CH343/CP2102 an `UART0`, `GPIO43`/`GPIO44`, 115200 Baud) lässt sich der komplette ESP-IDF-Bootlog parallel zum aktiven USB-FIDO-Betrieb mitlesen:

```bash
pio device monitor -b 115200
```

Auf einem Ein-Buchsen-Board (Super Mini) übernimmt TinyUSB nach dem Booten `GPIO19`/`GPIO20` für FIDO2/CCID, sodass der interne USB-Serial/JTAG-Port nach `usb_init()` abgemeldet wird (das ist normal!).

## 7. Exakte 6-Pin-Verdrahtung des GROW R558-S Fingerabdrucksensors (Datenblatt V1.1.1, S. 7–8)

**WICHTIG — Häufigster Hardware-Fehler beim GROW R558-S:**
Der **GROW R558-S** besitzt einen **6-poligen MX-1,25-mm-Stecker** mit **zwei getrennten 3,3-V-Versorgungspins** (`Pin 1` für die kapazitive Touch-Erkennung **und** `Pin 3` für den Sensor-Prozessor samt integriertem RGB-Leuchtring). **Beide Pins (`Pin 1` UND `Pin 3`) müssen zwingend mit `3,3 V` verbunden werden!** Bleibt `Pin 3` offen, sind sowohl UART als auch der eingebaute RGB-Ring des R558-S komplett stromlos; bleibt `Pin 1` offen, erkennt der Sensor keinen Finger. **Niemals an `5 V` anschließen** (Maximalspannung laut Datenblatt S. 6: `3,6 V`!).

| R558-S Pin (MX 1.25mm) | Typische Kabelfarbe | R558-S Signalname (Handbuch S. 7) | Anschluss am ESP32-S3 | Funktion |
|---|---|---|---|---|
| **Pin 1** | Rot (oder Pin 1 Markierung) | **`V_Touch` / `VCC_3.3V`** | **`3V3` (3,3 V)** | Dauerhafte 3,3-V-Speisung des Touch-Detektors (**Pflicht!**) |
| **Pin 2** | Gelb | **`Touch_Out` (`Vout`)** | *offen lassen (NC)* | Touch-IRQ-Ausgang (High bei Berührung, optional) |
| **Pin 3** | Blau | **`VCC` / `VCC_MCU`** | **`3V3` (3,3 V)** | **Hauptstromversorgung Sensor-MCU & eingebauter RGB-Ring (Pflicht!)** |
| **Pin 4** | Grün | **`TX` (`UART_TX`)** | **`GPIO18`** (`FP_UART_RX_GPIO`) | Sensor sendet -> ESP32-S3 empfängt (3,3-V-Logik) |
| **Pin 5** | Weiß | **`RX` (`UART_RX`)** | **`GPIO17`** (`FP_UART_TX_GPIO`) | ESP32-S3 sendet -> Sensor empfängt (3,3-V-Logik) |
| **Pin 6** | Schwarz | **`GND`** | **`GND`** | Gemeinsame Masse (**Pflicht!**) |

**LED-Ansteuerung (dreifach unterstützt — out of the box ohne Zusatzbauteil):**
1. **Integrierter RGB-Ring im GROW R558-S:** Wird von der Firmware **direkt über UART (`PS_ControlBLN`, Befehl `0x3C`)** angesteuert (Blau atmend = Finger auflegen, Grün blinkend = Erfolg/Fortschritt, Rot blinkend = Fehler/Kein Treffer, Rot dauerhaft = 5x Fehlversuch / gesperrt). Es ist **kein externer LED-Ring nötig**!
2. **Onboard-RGB-LED des ESP32-S3-Boards (`GPIO48`, RMT-Treiber aus `pico-keys-sdk`):** Bleibt vollständig aktiv und zeigt den normalen Pico-Key-Status an.
3. **Optionaler externer WS2812-LED-Ring an `GPIO4`:** Wird parallel ebenfalls mitangesteuert, falls angeschlossen.

Die UART-Parameter sind **57600 Baud, 8N2** gemäß GROW R558-S Handbuch V1.1.1.

## 8. Sicherheit

- Secure Boot und Flash-Verschlüsselung sind noch nicht eingerichtet. Das ist ein Folgeschritt.
  Siehe `docs/fingerprint/R558_PLAN.md`, Abschnitt 4.
- Das Anlernen von Fingerabdrücken läuft ausschließlich über die Webapp, siehe `docs/fingerprint/WEBAPP_PROMPT.md`.

## Hinweis zum Stand dieses Branches

Der GitHub-Workflow `.github/workflows/platformio.yml` baut die Umgebungen `esp32s3` und `esp32s3_dev` bei jedem Push.
Das Ergebnis steht als Kommentar am Commit (Erfolg oder Fehlerzeilen) und in der Job-Zusammenfassung.
Der Build läuft dort erfolgreich durch. Ein Flash-Test auf echter Hardware steht noch aus.

Der Quellordner ist `main/` (`src_dir = main`). Dort liegt die Hauptkomponente für PlatformIO
(`main/pio_entry.c`). Der Firmware-Code liegt in `src/fido/`, `pico-keys-sdk/` und dem Submodul.
Die Root-`CMakeLists.txt` erkennt ESP-IDF über `IDF_PATH` und behält die von PlatformIO gesetzten
`EXTRA_COMPONENT_DIRS` bei. Das ist nötig, weil `picokeys_sdk_import.cmake` diese Variable überschreibt.

## 9. Secure Boot und Flash-Verschlüsselung (R1)

**Achtung: unumkehrbar.** Diese Schritte brennen eFuses am Chip. Danach lässt sich weder Flash-Verschlüsselung
noch Secure Boot abschalten. Teste das Profil zuerst auf einem Ersatzboard, nie auf dem Gerät mit deinen Schlüsseln.
Der Ablauf ist nicht am Gerät getestet.

1. **Signaturschlüssel erzeugen** (außerhalb des Repos, nie committen):
   ```bash
   espsecure.py generate_signing_key --version 2 --scheme rsa3072 secure_boot_signing_key.pem
   ```
   `espsecure.py` kommt mit ESP-IDF. Die Datei bewahrst du sicher auf. Verloren heißt: keine Updates mehr.
   `.gitignore` schließt `*.pem` und `secure_boot_signing_key*` aus.

2. **Bauen mit dem Secure-Profil:**
   ```bash
   pio run -e esp32s3_secure
   ```
   Das Profil `config/esp32/sdkconfig.secure.defaults` setzt Secure Boot v2, Flash-Verschlüsselung im
   Development-Modus und die Partitionstabelle `config/esp32/partitions_secure.csv`. In dieser Tabelle hat
   `part0` (Schlüsselspeicher) das Flag `encrypted`.

3. **Erster Start:** Das Gerät verschlüsselt den Flash und brennt die Secure-Boot-Eintragung beim ersten Start selbst.
   Dafür muss das erste Image unverschlüsselt und unsigniert vorliegen. Prüfe danach mit der seriellen Ausgabe, dass
   die Flash-Verschlüsselung aktiv ist. `flash_encrypted = true` in `status` zeigt das ebenfalls.

4. **Updates danach:** Ein normales `pio run -t upload` schreibt Klartext und macht das Gerät unbrauchbar, wenn die
   Verschlüsselung aktiv ist. Verwende für Updates das verschlüsselte Schreiben von `esptool` (Option `--encrypt`) und
   das signierte Image. Die genaue Befehlszeile ist in der ESP-IDF-Doku zu „Flash Encryption“ und „Secure Boot“ beschrieben.
   Dieser Teil ist nicht getestet.

5. **Pairing:** Mit aktiver Verschlüsselung erlaubt die Firmware Pairing und Restore (Option
   `PICO_FIDO_R558_REQUIRE_FLASH_ENCRYPTION`). Ohne aktive Verschlüsselung lehnt sie beides mit `NOT_ALLOWED` ab.
   Ein bereits gekoppelter Sensor bleibt gekoppelt. Wenn du vorher ohne Verschlüsselung gekoppelt hast, koppele nach
   dem Aktivieren neu.

**Release-Modus** (`CONFIG_SECURE_FLASH_ENCRYPTION_MODE_RELEASE`) schaltet das serielle Schreiben komplett ab.
Verwende ihn erst, wenn der Development-Modus stabil läuft und du ein Backup-Image hast.
