# Prompt: Firmware-Downloads und Update-Hinweise in der Pico-FIDO-Webapp

Kopiere den folgenden Abschnitt in die KI, die die Webapp erweitert. Er beschreibt, wo die Firmware-Dateien liegen,
was jede Datei ist und wie die Webapp damit umgehen soll. Er setzt die bestehende Webapp (WebHID, Fingerabdruck-UI,
Einrichtungsassistent) voraus.

---

## Auftrag

Die Webapp für **Pico FIDO** (ESP32-S3) bekommt einen Bereich **„Firmware“**. Er zeigt die verfügbaren Releases,
erklärt die Unterschiede, lädt das gewählte Image herunter, prüft die Prüfsumme und spielt es auf das verbundene Gerät.
Das Aufspielen geschieht per WebSerial direkt aus der Webapp, mit ausdrücklicher Bestätigung des Nutzers. Es gelten
die Schutzregeln unten: Auf einem Gerät mit aktiver Flash-Verschlüsselung wird **nie** ein Klartext-Image geschrieben.

## Wo die Firmware liegt

- Repository: `PeWieser/pico-fido`, GitHub Releases.
- Releases entstehen automatisch bei jedem Push auf `main`, wenn der Build erfolgreich ist.
- Tag-Format: `fw-<Version>-build<Nummer>`, zum Beispiel `fw-8.0-build42`.
- Im Release liegen drei Dateien:

| Datei | Bedeutung |
|---|---|
| `pico-fido-esp32s3-<Version>-<Commit>.bin` | **Produktiv.** Für Geräte mit aktiver Flash-Verschlüsselung. |
| `pico-fido-esp32s3-dev-<Version>-<Commit>.bin` | **Entwicklung.** Ohne Flash-Verschlüsselung. Das Sensor-Passwort liegt im Klartext im Flash. |
| `SHA256SUMS.txt` | Prüfsummen beider Images. |

Beide `.bin`-Dateien sind **vollständige Images** (Bootloader, Partitionstabelle und App in einer Datei). Sie werden
ab Adresse **`0x0`** geschrieben. Es gibt keine einzelne App-Datei zum separaten Einspielen.

Die Versionsnummer steht im Tag und im Dateinamen. `<Commit>` sind die ersten 7 Zeichen des Commits, aus dem gebaut wurde.

## Welches Image wofür

- **Produktiv** ist die Standardwahl für ein Gerät, das benutzt wird. Die Firmware verlangt, dass die
  Flash-Verschlüsselung am Chip aktiv ist. Ohne sie lehnt sie Pairing und Restore des Fingerabdrucksensors ab
  (`NOT_ALLOWED`).
- **Entwicklung** ist nur für Testboards gedacht. Sie erlaubt Pairing ohne Flash-Verschlüsselung. Das Sensor-Passwort
  liegt dabei unverschlüsselt im Flash. Ein Gerät mit diesem Image ist nicht für den Produktivbetrieb geeignet.

## Ablauf in der Webapp

1. **Releases laden.** `GET https://api.github.com/repos/PeWieser/pico-fido/releases` (öffentlich, ohne Token).
   Nur Releases mit Tags im Format `fw-…` anzeigen. Die neueste Version oben. Bei Fehlern (Netz, Rate-Limit):
   verständliche Meldung und Link zur Releases-Seite.
2. **Image wählen.** Zwei Karten mit Name, Version, Commit und dem Satz aus der Tabelle „Welches Image wofür“.
   Standard ist „Produktiv“. Die Entwicklungsvariante hat einen deutlichen Warnhinweis und muss ausdrücklich gewählt werden.
3. **Gerät prüfen, bevor etwas heruntergeladen wird.** Ist ein Gerät verbunden, `status` lesen (`7: flashEncrypted`, `8: buildType` = `"prod"` | `"dev"`):
   - Aktuell aktiven Build-Typ (`8: buildType`, falls vorhanden) und Verschlüsselungsstatus (`7: flashEncrypted`) klar am verbundenen Gerät anzeigen.
   - `7: flashEncrypted = false` und „Produktiv“ gewählt: Hinweis „Auf diesem Gerät ist die Flash-Verschlüsselung nicht
     aktiv. Mit dem Produktiv-Image bleibt das Pairing gesperrt. Entweder die Verschlüsselung aktivieren
     (Einrichtungsassistent, Schritt 2a) oder das Entwicklungs-Image (`dev`) wählen.“
   - `7: flashEncrypted = true` und „Entwicklung“ gewählt: Warnung „Auf diesem Gerät ist die Flash-Verschlüsselung
     aktiv. Bitte das Produktiv-Image wählen; ein unverschlüsseltes Schreiben per WebSerial ist gesperrt.“
   - Kein Gerät verbunden (z. B. fabrikneuer ESP32-S3 im Bootloader-Modus): Die Auswahl ist erlaubt! Für ein noch
     unverschlüsseltes Board im Bootloader-Modus ohne bestehendes FIDO-Gerät darf WebSerial direkt an `0x0` flashen
     (mit ausdrücklicher Bestätigung, dass keine Hardware-Flash-Verschlüsselungs-eFuses gebrannt sind).
4. **Download und Prüfsumme (WICHTIG: GitHub-CORS beachten!).**
   - **CORS-Regel im Browser:** **Nicht** `fetch(asset.browser_download_url)` aufrufen (`https://github.com/.../releases/download/...` hat im Browser keinen CORS-Header und schlägt mit NetworkError fehl!), sondern die Asset-API-URL aus dem Release-JSON verwenden:
     `fetch(asset.url, { headers: { Accept: "application/octet-stream" } })` (`https://api.github.com/repos/PeWieser/pico-fido/releases/assets/<id>`).
   - Zusätzlich immer einen **lokalen Datei-Upload (`<input type="file" accept=".bin">`)** anbieten (mit Link zur GitHub-Releases-Seite), damit der Nutzer ein heruntergeladenes `.bin` auch offline oder bei API-Rate-Limit direkt einspielen kann.
   - `SHA256SUMS.txt` ebenfalls über `asset.url` mit `Accept: application/octet-stream` laden und den SHA-256-Wert mit WebCrypto (`crypto.subtle.digest("SHA-256", bytes)`) prüfen. Stimmt er nicht: Abbruch, Datei verwerfen, Meldung „Die Prüfsumme stimmt nicht. Die Datei nicht verwenden.“
5. **Aufspielen (WebSerial).** Nur möglich, wenn kein verbundenes FIDO-Gerät `7: flashEncrypted = true` meldet.
   - Der Nutzer bestätigt in einem Dialog: „Das Gerät wird mit der Firmware <Version> überschrieben. Der Vorgang
     löscht den Flash-Inhalt, auch gekoppelte Sensordaten. Vorher ein Backup erstellen.“ Ein Backup-Button steht
     im Dialog bereit.
   - **Wichtig beim WebHID-Handover:** Falls das Gerät aktuell per WebHID geöffnet ist, Verbindung sauber schließen
     (`device.close()`), bevor WebSerial öffnet, und klaren Hinweis zeigen, wie das Board in den ESP32-S3-ROM-Download-Modus
     gebracht wird (**BOOT gedrückt halten → kurz RESET drücken → BOOT loslassen**).
   - Die Übertragung läuft über WebSerial mit `esptool-js` (`ESPLoader`, Baudrate `460800`, `flashMode: "dio"`, `flashFreq: "80m"`, `flashSize: "4MB"`, `eraseAll: false` bzw. optionaler Checkbox „Kompletten Flash löschen (`eraseFlash`) — empfohlen beim Wechsel von alter/fremder Firmware“). Geschrieben wird das vollständige Image ab Adresse **`0x0`**.
   - Fortschrittsanzeige. Bei Abbruch oder Fehler: Meldung, dass das Gerät danach eventuell neu geflasht werden muss.
   - Nach dem Schreiben: Gerät neu verbinden, `status` lesen und `version` anzeigen.
   - Hinweis für den Bootloader-Modus: Ist das Gerät nicht im Flash-Modus, sagt die Webapp, wie der Nutzer ihn
     aktiviert (Boot-Taste halten und USB anstecken, bzw. den Hinweis aus `docs/platformio/README.md`, Abschnitt 4).
   - Ohne WebSerial-Unterstützung im Browser: Anleitung mit `esptool.py … write_flash 0x0 <Datei>` als Alternative,
     ebenfalls nur für Geräte ohne Flash-Verschlüsselung.

## Schutzregel: verschlüsselte Geräte

Das Klartext-Image darf **nur auf einen Chip ohne aktive Flash-Verschlüsselung** geschrieben werden. Ist die Verschlüsselung
aktiv, schreibt ein gewöhnliches `write_flash` Klartext. Der Chip startet dann nicht mehr, und das Gerät ist unbrauchbar.
Die Webapp muss das technisch erzwingen, nicht nur per Hinweis:

- Vor dem Schreiben wird `status` gelesen. Ist `flashEncrypted = true`, bricht die Webapp mit einer Meldung ab. Der
  Schreibknopf bleibt deaktiviert, und es wird kein Schreibbefehl gesendet.
- Ein Dialog, der nach dem Lesen von `status` offen bleibt, wird beim Zustandswechsel neu geprüft.
- Die Anleitung für verschlüsselte Geräte lautet sinngemäß:

  Bei aktiver Verschlüsselung nur verschlüsselt schreiben, mit `--encrypt` von `esptool` (ESP-IDF-Doku „Flash Encryption“).
  Das geht nur im **Entwicklungsmodus** der Verschlüsselung. Im Release-Modus ist das serielle Schreiben abgeschaltet.
  Dann gilt `docs/platformio/README.md`, Abschnitt 9. Die Webapp führt das nicht selbst aus und zeigt nur den Verweis.

Das Lesen von `status` ist der Schutz, den die Webapp bietet. Sie passt Schreibknopf und Anleitung an den gelesenen Zustand an.

## Was die Webapp beachten muss

- `status` liefert jetzt **sowohl** `7: flashEncrypted` (`bool`, echter Hardware-eFuse-Status) **als auch** `8: buildType` (`"prod"` oder `"dev"`):
  - `buildType === "dev"` erlaubt Pairing & Restore auch bei `flashEncrypted === false` (für Testboards), während `flashEncrypted === false` gleichzeitig signalisiert, dass WebSerial-Updates weiterhin gefahrlos unverschlüsselt möglich sind.
  - `flashEncrypted === true` sperrt WebSerial-Klartext-Updates strikt technisch.
- Sie signiert nichts und prüft keine Secure-Boot-Signatur. Secure Boot gehört zur Produktiv-Einrichtung mit eigenem
  Schlüssel und ist nicht Teil der Releases.
- Sie kann Geräte mit aktiver Flash-Verschlüsselung nicht per WebSerial aktualisieren. Das bleibt der Weg über die Doku.

## Lieferumfang

1. Ein Modul `firmwareReleases` mit `listReleases()`, `pickImage(release, kind)` und `verifySha256(bytes, sumsFile)`.
2. Die UI-Komponente „Firmware“ mit den Schritten 1–5 und den Warnungen oben.
3. Tests mit gemockter GitHub-API und einem Testbild:
   - Filter auf `fw-…`-Tags,
   - Prüfsumme korrekt und falsch,
   - Auswahl „Produktiv“ als Standard,
   - Warnung bei `flashEncrypted`-Kombinationen,
   - keine Klartext-Anleitung bei aktiver Verschlüsselung.
4. Eine Liste offener Punkte (z. B. `buildType` in `status`, konkreter `--encrypt`-Ablauf, Versionsanzeige per `version`-Befehl).

## Abnahme

- Die Webapp listet nur Releases mit `fw-…`-Tags und zeigt beide Images pro Release.
- „Produktiv“ ist vorausgewählt. Die Entwicklungsvariante braucht eine ausdrückliche Auswahl und zeigt eine Warnung.
- Eine falsche Prüfsumme bricht den Vorgang ab. Die Datei wird nicht zur Anleitung freigegeben.
- Ist `flashEncrypted = true`, zeigt die App keinen Befehl mit `write_flash` ohne `--encrypt`.
- Aufspielen ist nur bei `flashEncrypted = false` möglich. Der Schreibknopf ist sonst deaktiviert, und es wird kein Schreibbefehl gesendet.
- Vor dem Aufspielen gibt es eine Bestätigung und einen Backup-Hinweis. Ohne Bestätigung wird nichts geschrieben.
- Nach einem erfolgreichen Schreiben wird das Gerät neu verbunden und `status` gelesen.
