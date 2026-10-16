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
git checkout arena/c392330f-pico-fido     # oder main, sobald der Branch gemergt ist
git submodule update --init --recursive
```

Die Submodule sind nötig. Ohne `pico-keys-sdk` bricht der Build ab.

## 3. Bauen

```bash
pio run
```

Die erste Ausführung lädt ESP-IDF, die Toolchain und die verwalteten Komponenten herunter. Das dauert einige Minuten.
Das Ergebnis liegt unter `.pio/build/esp32s3/`.

Die Versionen sind in `platformio.ini` festgelegt:

| Eintrag | Wert | Grund |
|---|---|---|
| `platform` | `espressif32@6.12.0` | liefert ESP-IDF 5.5.x |
| `framework-espidf` | `~3.50501.0` | ESP-IDF 5.5.1, wie in der CI |
| `board` | `esp32-s3-devkitc-1` | generischer ESP32-S3 |
| `board_upload.flash_size` | `4MB` | passend zu `sdkconfig.defaults` und `partitions.csv` |

Wenn PlatformIO das Paket `framework-espidf@~3.50501.0` nicht findet, entferne die Zeile `platform_packages`
in `platformio.ini`. PlatformIO nimmt dann die von der Plattform vorgesehene ESP-IDF-Version.

## 4. In den Bootloader wechseln

Das Super Mini nutzt den nativen USB-Anschluss des ESP32-S3. Dieser Anschluss ist später der FIDO-Token. Zum Flashen
muss der Chip in den Download-Modus:

1. Taste **BOOT** gedrückt halten.
2. Kurz **RESET** drücken (oder das USB-Kabel bei gedrückter BOOT-Taste einstecken).
3. BOOT loslassen.

## 5. Flashen

```bash
pio run -t upload
```

Ist der Port nicht richtig erkannt, setze in `platformio.ini` den Eintrag `upload_port`
(z. B. `/dev/ttyACM0` unter Linux, `COM5` unter Windows) oder nutze `pio device list`.

Danach den Chip mit RESET neu starten. Das Gerät meldet sich als FIDO-Token.

## 6. Serielle Ausgabe

```bash
pio device monitor
```

Die Ausgabe läuft über den USB-Serial/JTAG-Anschluss. Wenn der FIDO-USB-Modus aktiv ist, ist dieser Anschluss
möglicherweise nicht verfügbar. Dann bleibt die Konsole leer.

## 7. Verdrahtung des Fingerabdrucksensors

| Signal | ESP32-S3 | Hinweis |
|---|---|---|
| R558 TX | GPIO18 | ESP RX |
| R558 RX | GPIO17 | ESP TX |
| R558 VCC / GND | 3,3 V / GND | Sensor nur mit 3,3 V betreiben |
| LED-Ring Daten | GPIO4 | WS2812, 12 Pixel |

Die UART-Parameter sind 57600 Baud, 8N2, nach dem Datenblatt des R558-S (Handbuch V1.1).

## 8. Sicherheit

- Secure Boot und Flash-Verschlüsselung sind noch nicht eingerichtet. Das ist ein Folgeschritt.
  Siehe `docs/fingerprint/R558_PLAN.md`, Abschnitt 4.
- Das Anlernen von Fingerabdrücken läuft ausschließlich über die Webapp, siehe `docs/fingerprint/WEBAPP_PROMPT.md`.

## Hinweis zum Stand dieses Branches

Die `platformio.ini`, die Komponente unter `src/` und diese Anleitung wurden in einer Sandbox ohne Zugriff auf das
PlatformIO-Registry geschrieben. Dort konnte der Build nicht durchlaufen. Die Konfiguration wurde nur über
`pio project config` geprüft. Der erste echte `pio run` steht also noch aus. Bitte melde dich, wenn er fehlschlägt.
