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
3. **Gerät prüfen, bevor etwas heruntergeladen wird.** Ist ein Gerät verbunden, `status` lesen:
   - `7: flashEncrypted = false` und „Produktiv“ gewählt: Hinweis „Auf diesem Gerät ist die Flash-Verschlüsselung nicht
     aktiv. Mit dem Produktiv-Image bleibt das Pairing gesperrt. Entweder die Verschlüsselung aktivieren
     (Einrichtungsassistent, Schritt 2a) oder das Entwicklungs-Image wählen.“
   - `7: flashEncrypted = true` und „Entwicklung“ gewählt: Warnung „Auf diesem Gerät ist die Flash-Verschlüsselung
     aktiv. Ein Entwicklungs-Image setzt die Verschlüsselung nicht zurück, es passt aber nicht zu dieser Einrichtung.
     Bitte das Produktiv-Image wählen.“
   - Kein Gerät verbunden: Die Auswahl ist erlaubt, es gibt nur den Hinweis, das Gerät vor dem Aufspielen zu prüfen.
4. **Download und Prüfsumme.** Das Image herunterladen. `SHA256SUMS.txt` herunterladen und den SHA-256-Wert mit
   WebCrypto (`crypto.subtle.digest`) prüfen. Stimmt er nicht: Abbruch, Datei verwerfen, Meldung
   „Die Prüfsumme stimmt nicht. Die Datei nicht verwenden.“
5. **Aufspielen (WebSerial).** Nur möglich, wenn `7: flashEncrypted = false` ist.
   - Der Nutzer bestätigt in einem Dialog: „Das Gerät wird mit der Firmware <Version> überschrieben. Der Vorgang
     löscht den Flash-Inhalt, auch gekoppelte Sensordaten. Vorher ein Backup erstellen.“ Ein Backup-Button steht
     im Dialog bereit.
   - Die Übertragung läuft über WebSerial mit einer ESP-Flash-Bibliothek (z. B. `esptool-js` oder esp-web-tools,
     keine eigene Implementierung). Adresse `0x0`, das vollständige Image.
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

## Was die Webapp nicht kann

- Sie erkennt nicht sicher, welches Image auf dem Gerät läuft. Das Gerät meldet nur `flashEncrypted`, nicht den Build-Typ.
  Die Webapp darf deshalb nicht behaupten „Gerät läuft mit Entwicklungs-Image“.
  Offener Punkt: ein Feld `8: buildType` (`"prod"` / `"dev"`) in `status` würde das ermöglichen. Das ist nicht
  implementiert.
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
