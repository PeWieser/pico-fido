# Prompt: Firmware-Downloads und Update-Hinweise in der Pico-FIDO-Webapp

Kopiere den folgenden Abschnitt in die KI, die die Webapp erweitert. Er beschreibt, wo die Firmware-Dateien liegen,
was jede Datei ist und wie die Webapp damit umgehen soll. Er setzt die bestehende Webapp (WebHID, Fingerabdruck-UI,
Einrichtungsassistent) voraus.

---

## Auftrag

Die Webapp für **Pico FIDO** (ESP32-S3) bekommt einen Bereich **„Firmware“**. Er zeigt die verfügbaren Releases,
erklärt die Unterschiede, lädt das gewählte Image herunter, prüft die Prüfsumme und gibt eine klare Anleitung zum
Aufspielen. Die Webapp spielt **kein Image automatisch auf**. Das Aufspielen läuft außerhalb der Webapp über `esptool`
oder ein Flash-Werkzeug, das der Nutzer selbst startet.

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
5. **Anleitung zum Aufspielen.** Keine automatische Ausführung. Die Webapp zeigt den Befehl zum Kopieren:
   ```bash
   esptool.py --chip esp32s3 --port <PORT> write_flash 0x0 pico-fido-esp32s3-<Version>-<Commit>.bin
   ```
   Der Port ist ein Platzhalter, den der Nutzer ersetzt. Dazu der Hinweis: „Vorher den Schalter für den Bootloader
   halten, falls das Gerät nicht von selbst in den Flash-Modus geht.“ Die Anleitung verweist auf
   `docs/platformio/README.md`, Abschnitt 4.

## Wichtig: Updates auf einem verschlüsselten Gerät

Das Klartext-Image darf **nur auf einen Chip ohne aktive Flash-Verschlüsselung** geschrieben werden. Ist die Verschlüsselung
aktiv, schreibt ein gewöhnliches `write_flash` Klartext. Der Chip startet dann nicht mehr, und das Gerät ist unbrauchbar.
Die Warnung dazu gehört in die Anleitung, gut sichtbar:

- Bei aktiver Verschlüsselung nur verschlüsselt schreiben, mit der Option `--encrypt` von `esptool` (siehe ESP-IDF-Doku
  „Flash Encryption“). Das funktioniert nur, solange der Chip im **Entwicklungsmodus** der Verschlüsselung ist.
  Im Release-Modus ist das serielle Schreiben abgeschaltet, dann bleibt nur der Weg aus
  `docs/platformio/README.md`, Abschnitt 9. Die Webapp führt das nicht selbst aus.
- Die Webapp zeigt bei `flashEncrypted = true` **keinen** Klartext-Befehl. Stattdessen den Verweis auf die Doku.

Das Lesen von `status` ist der einzige Schutz, den die Webapp hier bieten kann. Sie muss die Anleitung also
an den gelesenen Zustand anpassen.

## Was die Webapp nicht kann

- Sie erkennt nicht sicher, welches Image auf dem Gerät läuft. Das Gerät meldet nur `flashEncrypted`, nicht den Build-Typ.
  Die Webapp darf deshalb nicht behaupten „Gerät läuft mit Entwicklungs-Image“.
  Offener Punkt: ein Feld `8: buildType` (`"prod"` / `"dev"`) in `status` würde das ermöglichen. Das ist nicht
  implementiert.
- Sie signiert nichts und prüft keine Secure-Boot-Signatur. Secure Boot gehört zur Produktiv-Einrichtung mit eigenem
  Schlüssel und ist nicht Teil der Releases.

## Lieferumfang

1. Ein Modul `firmwareReleases` mit `listReleases()`, `pickImage(release, kind)` und `verifySha256(bytes, sumsFile)`.
2. Die UI-Komponente „Firmware“ mit den Schritten 1–5 und den Warnungen oben.
3. Tests mit gemockter GitHub-API und einem Testbild:
   - Filter auf `fw-…`-Tags,
   - Prüfsumme korrekt und falsch,
   - Auswahl „Produktiv“ als Standard,
   - Warnung bei `flashEncrypted`-Kombinationen,
   - keine Klartext-Anleitung bei aktiver Verschlüsselung.
4. Eine Liste offener Punkte (z. B. `buildType` in `status`, Anleitung für `--encrypt` mit konkretem Befehl).

## Abnahme

- Die Webapp listet nur Releases mit `fw-…`-Tags und zeigt beide Images pro Release.
- „Produktiv“ ist vorausgewählt. Die Entwicklungsvariante braucht eine ausdrückliche Auswahl und zeigt eine Warnung.
- Eine falsche Prüfsumme bricht den Vorgang ab. Die Datei wird nicht zur Anleitung freigegeben.
- Ist `flashEncrypted = true`, zeigt die App keinen Befehl mit `write_flash` ohne `--encrypt`.
- Die Webapp startet selbst keinen Flash-Vorgang.
