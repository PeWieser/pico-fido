# R558-S Rettung: Sensor mit verlorenem Zufallspasswort wieder nutzbar machen

**Zielgruppe:** Besitzer eines Pico-FIDO-Schlüssels (ESP32-S3 Super Mini + GROW R558-S),
dessen Sensor gekoppelt ist/war, aber seither nur noch `0x21` („Passwort falsch“) meldet
oder dunkel bleibt, weil die Zugangsdaten in `EF_FP_CONF` verloren gingen
(Chip-Adresse weiterhin sichtbar, z. B. `A=0x29062D09`).

## 0. Was bei dir passiert ist (kurz & ehrlich)

- Vor Build 47 hat das Pairing **Passwort und Chip-Adresse aus der Hardware-RNG gewürfelt**
  und beides *nur* in der Schlüsseldatei `EF_FP_CONF` abgelegt. Geht diese Datei verloren
  (Neupartitionierung, Werkzustand-Reset per Fusemarker, Löschen), steht das Modul auf einem
  unbekannten Zufallswert.
- Seit Build 47 wird stattdessen aus der eFuse-MAC des ESP32-S3 abgeleitet
  (`SHA-256("pico-fido-r558-efuse-bind-v1" ‖ MAC)`) – solche Passwörter sind reproduzierbar.
- **Für die Chip-Adresse `0x29062D09` wurde das inzwischen hart geprüft:** Eine Vollsuche über
  alle 297 Espressif-OUIs × 2²⁴ NICs (≈ 4,98 Milliarden SHA-256, `tools/r558_mac_search.c`)
  fand **gar keine** MAC, die diese Adresse erzeugt. Die Sperre stammt also belegbar aus dem
  alten Zufallspfad. Früher eingebettete Behauptungen („AVX-512 OUI-Match `0x7BF6B530`“)
  waren falsch und wurden aus der Firmware entfernt.
- Konsequenz: Ausrechnen geht nicht. Aber das Passwort wurde damals **im Klartext in den
  ESP32-Flash geschrieben** – und das Dateisystem (Journal/Redo/ältere Sektoren) bewahrt
  häufig physische Kopien, auch wenn die Datei logisch weg ist. Genau dafür gibt es jetzt
  die Flash-Stufe der Recovery-Leiter und die Forensik-Tools unten.

## 1. Vorbereitung (einmalig)

1. **Neueste Firmware** flashen (Releases `fw-8.0-build*`, Komplett-Image ab `0x0`).
   Wichtig: Für die Rettung **kein** `esptool erase_flash` ausführen – das würde genau die
   Flash-Reste zerstören, die das Passwort noch enthalten können!
2. **Browser für die Rettungsseite:** Chrome/Edge sperren WebHID auf der FIDO-Usage-Page
   `0xF1D0`. Browser mit deaktivierter Blockliste starten:
   - Windows: `"C:\Program Files\Google\Chrome\Application\chrome.exe" --disable-hid-blocklist`
   - macOS: `open -a "Google Chrome" --args --disable-hid-blocklist`
   - Linux: `google-chrome --disable-hid-blocklist`
3. Rettungsseite öffnen: `https://PeWieser.github.io/pico-fido/`
   (nach Aktivierung von GitHub Pages; lokal geht auch `website/` per `python3 -m http.server`).
4. Optional für Schritt 3/4: `esptool` am PC (`pip install esptool`) und den seriellen Port
   kennen (Windows `COMx`, macOS `/dev/cu.usbmodem*`, Linux `/dev/ttyACM*`).

## 2. Weg A (einfachster): Recovery über die Website

1. Gerät **10 s vom USB trennen**, wieder anstecken (frisches VfyPwd-Budget – das Modul kann
   seine UART nach zu vielen Fehlversuchen bis zum nächsten Stromzyklus stumm schalten).
2. Auf der Website **Schritt 1: Gerät verbinden**. Status lesen und die Telemetrie-Zeile
   notieren, insbesondere `A=0x…………` (beobachtete Chip-Adresse).
3. **Schritt 2: „Sensor wiederherstellen“** (Vendor-Befehl `0x0B`, keine PIN nötig).
   Die Firmware testet nur per `VfyPwd` (nichts wird gelöscht):
   gespeicherte Daten → eFuse-Ableitung → **Flash-Archäologie** (eigener `part0`-Flash wird
   nach `EF_FP_CONF`-Resten gescannt) → Dev-Zugangsdaten → deine Kandidaten → Werkzustand.
4. **Erfolg:** `Recover gefunden = true`; die Quelle sagt, woher das Passwort kam
   (`flash` = dein altes Zufallspasswort wurde im ESP32-Flash gefunden).
   Danach sofort **pairen**, Finger anlernen und ein **Sensor-Backup** (JSON) speichern.
5. **Kein Treffer**, Telemetrie enthält `silent`: Modul antwortet gar nicht → Verkabelung und
   3,3-V-Versorgung prüfen (Sensor ist **nicht** 5-V-fest), ggf. „Probe (Pin-Scan)“.
   Weiter mit Weg B–D.

## 3. Weg B (stärkster Hebel): ESP32-Flash-Dump auswerten

Voraussetzung: Der Schlüssel-Flash wurde seit dem Pairing **nicht** per `erase_flash`
komplett gelöscht. (Falls doch: `part0` wäre zu >99,9 % `0xFF` – dann direkt zu Weg E.)

1. Board in den **Download-Modus**: BOOT halten → RESET kurz drücken → BOOT loslassen.
2. Volldump (4 MB) ziehen, z. B.:
   `esptool --chip esp32s3 --port <PORT> read_flash 0 0x400000 esp32_dump.bin`
3. Auswerten – beides findet dieselbe Kandidatenliste (die Webseite arbeitet nur lokal):
   - **Im Browser:** Website Schritt 4, Dump-Typ „ESP32-S3 Flash-Dump“, Datei wählen.
   - **Am PC:** `python3 tools/r558_flash_forensics.py esp32_dump.bin --address 29062D09 --json kandidaten.json`
4. Kandidaten in Website-Schritt 2 übernehmen (Knopf „Kandidaten übernehmen“) oder am PC
   direkt testen (Weg D). Konfidenz 100 = intakter Dateirekord, 90 = Signaturtreffer.

## 4. Weg C: MAC-Ableitung ausschließen (5 Minuten)

Nur relevant, falls der Sensor je mit Build ≥ 47 (evtl. anderem Board) gekoppelt wurde:

1. MAC lesen: `esptool --port <PORT> read_mac` (Download-Modus).
2. Auf der Website Schritt 3 eingeben und gegen die beobachtete Chip-Adresse vergleichen.
3. Oder komplett offline am PC über alle Espressif-MACs suchen (findet garantiert jede
   MAC, die die Adresse ableitet – falls es eine gibt):
   ```bash
   gcc -O3 -march=native -pthread tools/r558_mac_search.c -o /tmp/r558_mac_search
   /tmp/r558_mac_search 29062D09 --threads 8   # Treffer ⇒ password=… als Kandidat nutzen
   ```
   Für `0x29062D09` endete diese Suche nachweislich leer (s. Abschnitt 0).

## 5. Weg D: Direkt am Sensor per USB-TTL (PC)

Wenn der ESP32-Pfad nicht weiterführt, geht es ohne Schlüssel-Firmware direkt ans Modul
(pyserial nötig: `pip install pyserial`):

```bash
python3 tools/r558_uart_recover.py /dev/ttyUSB0 --address 29062D09 \
    --candidates kandidaten.json --mac 24:0A:C4:12:34:56
```

- **Verkabelung (Achtung 3,3 V, SH1.0-6P):** USB-TTL mit 3V3-Logik →
  Pin 1 `VCC_3.3V` und Pin 3 `VCC_MCU` an 3,3 V, Pin 6 GND, Pin 4 `UART_TX` an Adapter-RX,
  Pin 5 `UART_RX` an Adapter-TX (57600 8N2), Pin 2 `TOUCH_OUT` offen lassen.
  Modul keinesfalls mit 5 V speisen; erst verkabeln, dann Spannung anlegen.
- Das Tool macht: HandShake (Lebenszeichen/Adressen-Rückmeldung) → **ReadINFpage-Test**
  (manche Firmware-Generationen geben die Parametertabelle inkl. Passwort auch vor `VfyPwd`
  heraus – bei gesperrten Modulen meist `0x21`, der Versuch kostet nichts) → Kandidaten per
  `VfyPwd` testen (mit Stromzyklus-Pausen) → optional `--normalize factory`, setzt erst nach
  erfolgreichem Entsperren und ausdrücklicher Bestätigung Passwort 0 / Adresse `0xFFFFFFFF`
  (Fingerabdruck-Templates bleiben erhalten; danach neu pairen).

## 6. Weg E: Wenn der ESP32-Flash leer ist (Experten)

Das Modul speichert seine Parameter (inkl. Passwort) nach dem Stand der verwandten
AS60x-Dokumentation in einem externen seriellen SPI-Flash; die MCU-Firmware selbst liegt im
Mask-ROM. Der R558-S kann im Detail abweichen – deshalb **erst nur lesen**:

1. Platine öffnen, SoC- und Flash-Chip identifizieren (Foto machen!). SPI-Flash per
   SOIC-8-Clip/Programmer (z. B. CH341A mit flashrom) im stromlosen Zustand dumpen.
2. Dump auswerten: Website Schritt 4 („Sensor-SPI-Flash-Dump“) oder
   `python3 tools/r558_flash_forensics.py sensor_dump.bin --sensor-flash --address 29062D09`
   (Parametertabelle: Adresse bei Offset +8, Passwort bei +60, Flag `0x1234` bei +126).
3. Gefundenes Passwort per Weg A/D verifizieren. **Kein Patchen ohne vorheriges Backup** des
   Original-Dumps; ein ungültiges Parameter-Flag würde das Modul auf Werkswerte zurücksetzen
   (Passwort 0, Adresse `0xFFFFFFFF`), aber das ist der allerletzte Schritt und kann bei
   falschem Tabellenlayout das Modul bricken.

## 7. Was nicht funktioniert (damit du keine Zeit verschwendest)

- **Ausrechnen aus der Chip-Adresse:** Vor Build 47 kamen beide Werte aus der Hardware-RNG
  des ESP32-S3; die Adresshälfte verrät die Passworthälfte nicht (geprüft, Audit im Repo).
- **Brute Force über UART:** 2³² Passwörter bei 57600 Baud und Timeout-Schaltung des Moduls
  sind lebenslang. Gezielte Kandidaten (Flash! MAC!) schlagen Raten um Größenordnungen.
- **`RestSetting`/Reset ohne Passwort:** Antwortet auf gesperrtem Modul mit `0x21`.
- **GROW-„Masterpasswort“:** Existiert laut Handbuch nicht; ein vergessenes Passwort ist per
  Befehl nicht auslesbar. Einzige Herstelleroption: Modul einschicken/tauschen.

## 8. Wenn alles fehlschlägt

- Das Modul ist dann ein Sensor mit unbekanntem Passwort – elektrisch intakt, aber ohne
  Weg E oder Herstellereingriff nicht wiederverwendbar. Ersatzmodule kosten wenig; das neue
  Pairing leitet seit Build 47 reproduzierbar aus der Board-MAC ab, zusätzlich **Backup-JSON
  speichern** (Pin-/Backup-Doku im Repo), dann kann dieser Zustand nicht mehr eintreten.
- Hilfreich für eine gezielte Rückmeldung (Issue im Repo): Telemetrie-Zeile aus Schritt 1,
  ob je `erase_flash` lief, ob ein Webapp-Backup (`pico-fido-r558-backup*.json`) existiert,
  ob derselbe ESP32 wie beim Pairing benutzt wird, Foto der Sensorplatine.

## 9. Sicherheit & Ehrlichkeit

- Alle Tools/Webseite arbeiten **offline/lokal**; Dumps enthalten Schlüssel und Zugangsdaten
  **im Klartext** (das Pico-FIDO-Dateisystem speichert ohne Flash-Verschlüsselung nicht
  geheim) – Dumps und Kandidaten-JSON wie Passwörter behandeln, nicht veröffentlichen.
- Die Recovery wird genau deshalb nur mit physischem Zugriff (HID am eigenen Rechner /
  Board-Flash / Modul-Clip) möglich; über WebAuthn gibt es keinen Fernzugriff darauf.
- Host-Tests aller neuen Teile sind grün (C-Ladder-Scanner, MAC-Suche, beide PC-Tools,
  Website-Logik). **Ein ESP-IDF-Komplettbuild und der Lauf an echter Hardware in dieser
  Arbeitsumgebung stehen weiterhin aus** – deine Rückmeldung (Telemetrie!) hilft beim
  Schließen dieser Lücke.
