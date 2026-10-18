# Prompt: Einrichtungsassistent (Setup-Wizard) für Pico FIDO mit R558-Fingerabdruck

Kopiere den folgenden Abschnitt in die KI, die die Webapp erweitert. Er setzt voraus, dass die Anlern-UI
aus `docs/fingerprint/WEBAPP_PROMPT.md` bereits vorhanden ist. Dieser Prompt ergänzt sie um einen
Einrichtungsassistenten, der bei einem neuen Schlüssel Schritt für Schritt durch die Einrichtung führt.

---

## Auftrag

Du erweiterst die Webapp für **Pico FIDO** (ESP32-S3, WebHID) um einen **Einrichtungsassistenten**.
Der Assistent startet automatisch, wenn ein Schlüssel neu eingerichtet werden muss, und führt den Nutzer in
festen Schritten durch die Einrichtung. Der Assistent darf nichts am Gerät schreiben, was der Nutzer nicht
in einem Schritt bestätigt hat.

Die Anlern-UI (Pairing, Enrollment, Löschen, Entsperren, Backup, Restore) und das Protokoll stehen in
`WEBAPP_PROMPT.md`. Halte dich an deren Tabellen, Auth-Regeln und Fehlercodes. Hier wird nur der Ablauf
des Assistenten beschrieben.

## Wann der Assistent startet

Prüfe beim Verbinden:

1. **Neuer Schlüssel:** Die FIDO-`getInfo`-Antwort enthält in `options` den Eintrag `clientPin` nicht
   oder mit `false`. Dann ist noch keine PIN gesetzt. Der Assistent startet automatisch.
2. **Gerät ohne Fingerabdruck:** `status` liefert `6: supported = false`. Dann keinen Fingerabdruck-Schritt
   anbieten. Der Assistent beschränkt sich auf PIN und Hinweise.
3. **Bestehender Schlüssel:** PIN gesetzt und `paired = true`. Kein Assistent, nur die normale Anlern-UI.
   Im Menü steht trotzdem der Punkt „Einrichtung wiederholen“.

Ein Schlüssel mit PIN, aber `paired = false`, bietet den Assistenten ebenfalls an, mit Schritt „Sensor koppeln“
an der passenden Stelle.

## Grundsätze für den Assistenten

- **Ein Schritt pro Bildschirm.** Jeder Schritt hat: Titel, eine kurze Erklärung, eine Aktion und „Zurück“ (sofern
  der Schritt nichts Irreversibles tut) sowie „Überspringen“ (nur bei optionalen Schritten).
- **Fortschrittsanzeige** mit den Schritten unten und dem aktuellen Schritt markiert.
- **Der Zustand wird nach jedem Schritt aus dem Gerät gelesen** (`getInfo` und `status`), nicht aus dem Gedächtnis
  der App. Bricht die Verbindung ab, setzt der Assistent beim letzten gelesenen Zustand fort.
- **Keine Schreibbefehle ohne PIN-Token** (Regel aus `WEBAPP_PROMPT.md`). Das gilt auch für die PIN-Einrichtung
  selbst (siehe Schritt 3).
- **Kein Tastendruck am Gerät.** Pairing, Anlernen, Löschen und Entsperren brauchen nur die PIN und den Sensor.
- **Irreversible Schritte** (eFuses, Secure Boot) nur nach einer ausdrücklichen Bestätigung, die man nicht
  versehentlich mit Enter auslöst. Die Schaltfläche heißt „Ich habe verstanden, Chip-Sicherungen werden gebrannt“,
  und darunter steht, dass das nicht rückgängig zu machen ist.

## Ablauf (Schritt für Schritt)

### Schritt 1: Willkommen und Geräteprüfung

Erklärung: „Wir richten jetzt den Schlüssel ein. Du brauchst den ESP32-S3, den R558-Sensor und ein paar Minuten.“

Automatisch prüfen und anzeigen:
- Verbindung zum Gerät (WebHID, FIDO-Interface).
- Firmware-Stand: `getInfo` antwortet. Antwortet `status` mit `0x3E` oder `0x02`, ist die Firmware zu alt.
  Dann den Assistenten mit dem Hinweis beenden: „Bitte die Firmware aktualisieren.“
- `status` lesen: `supported`, `flashEncrypted`, `paired`, `locked`, Anzahl der Slots.

Aktion: „Weiter“.

### Schritt 2: Betriebsart wählen

Frage: „Wofür richtest du diesen Schlüssel ein?“ Zwei Optionen, mit Erklärung:

- **Entwicklungsboard (Testbetrieb):** Keine Flash-Verschlüsselung. Das Sensor-Passwort liegt im Klartext im
  Flash. Die App zeigt dauerhaft einen Hinweis „Entwicklungsbetrieb: Sensor-Passwort ist nicht geschützt“.
  Auswahl setzt in der App nur die Anzeige, es schaltet nichts am Gerät um.
- **Produktiv (empfohlen):** Flash-Verschlüsselung und Secure Boot sind aktiv. Der Assistent führt dafür
  durch Schritt 2a.

Wurde `flashEncrypted = true` gelesen, ist „Produktiv“ bereits erfüllt. Dann Schritt 2a überspringen und die
Auswahl „Produktiv“ vorselektieren.

### Schritt 2a: Flash-Verschlüsselung und Secure Boot (nur Produktiv, nur wenn nicht aktiv)

Erklärung (muss gelesen werden, bevor der Nutzer weitergehen kann):
- Die Flash-Verschlüsselung schützt den Speicherinhalt, auch das Sensor-Passwort, vor dem Auslesen des Chips.
- Secure Boot lässt nur Firmware starten, die mit dem eigenen Signaturschlüssel signiert ist.
- Beides brennt **eFuses**. Das ist **nicht rückgängig** zu machen.
- Der Signaturschlüssel wird außerhalb der Webapp erzeugt (`espsecure.py generate_signing_key …`) und sicher
  aufbewahrt. Die Webapp erzeugt ihn nicht und speichert ihn nicht.
- Diese Schritte macht die Webapp nicht selbst. Sie zeigt die Befehle aus `docs/platformio/README.md`
  (Abschnitt 9) an und prüft danach nur den Zustand.

Aktionen:
1. Checkbox: „Ich habe einen Signaturschlüssel erzeugt und gesichert.“ (Pflicht zum Weitermachen.)
2. Checkbox: „Ich habe das auf einem Ersatzboard getestet.“ (Pflicht zum Weitermachen.)
3. Anzeige der Befehle: Bauen mit `pio run -e esp32s3_secure`, Flashen, erster Start. Jeweils mit „Kopieren“-Button.
4. Button „Status neu prüfen“: liest `status`. Erst bei `7: flashEncrypted = true` geht es weiter.
   Solange `false`: Hinweis „Die Flash-Verschlüsselung ist noch nicht aktiv. Pairing und Restore bleiben gesperrt.“

Bei `flashEncrypted = false` bleiben Pairing und Restore deaktiviert. Der Assistent sendet dafür keinen Befehl.

### Schritt 3: PIN festlegen

Erklärung: „Die PIN schützt Pairing, Anlernen, Löschen, Entsperren und Backup. Sie ist die einzige Bestätigung
am Gerät, es gibt keinen Taster. Die PIN hat genau 6 Ziffern. Bewahre sie sicher auf, es gibt keine
Wiederherstellung ohne Backup.“

Eingabe: PIN zweimal eingeben, Ziffernfeld, `autocomplete="off"`. Die App prüft vor dem Senden:
- genau 6 Ziffern (0–9),
- beide Eingaben gleich.

Ablauf: PIN-Protokoll 2 aus `WEBAPP_PROMPT.md` (Schlüsselvereinbarung, ECDH P-256, HKDF). Dann `clientPin`
mit Unterbefehl `setPIN` (`0x03`) nach CTAP 2.1: die neue PIN mit 0x00 auf 64 Byte auffüllen, mit dem
Shared Secret AES-256-CBC (IV 16×0x00) verschlüsseln. `pinUvAuthParam` = HMAC-SHA-256(Shared Secret, newPinEnc),
bei Protokoll 2 also 32 Byte. Die genaue Kodierung ist in der CTAP-2.1-Spezifikation beschrieben und muss gegen die
Firmware getestet werden (siehe offene Punkte).

Nach Erfolg: `getInfo` neu lesen, `clientPin` muss jetzt `true` sein. Nach jedem Schritt die PIN aus dem Speicher
löschen (Regeln für Token und Shared Secret gelten).

Fehler:
- Ist bereits eine PIN gesetzt (`clientPin = true`), diesen Schritt überspringen und zur Anmeldung wechseln.
- Schlägt `setPIN` fehl, Verbindung neu aufbauen und `getInfo` lesen. Dann entscheidet sich, ob die PIN schon
  gesetzt ist. Der Assistent setzt die PIN nicht zweimal.

Hinweis für Bestandskarten: Eine bestehende 4-stellige PIN bleibt gültig. Der Assistent schlägt nur bei einer
Neueinrichtung 6 Ziffern vor.

### Schritt 4: Sensor anschließen und prüfen

Erklärung und Verkabelung (aus `docs/fingerprint/R558_PLAN.md`):
- R558 TX → GPIO18 (ESP32-S3 RX), R558 RX → GPIO17 (ESP32-S3 TX). Die Leitungen sind gekreuzt.
- 3,3 V und GND. **Kein 5 V** am Sensor.
- LED-Ring WS2812, 12 Pixel, an GPIO4.

Anzeige: „Sensor angeschlossen?“ mit Buttons „Ja, ist angeschlossen“ und „Hilfe anzeigen“.

Aktion: `status` lesen. Ist `supported = true` und der Sensor antwortet, weiter. Antwortet der Sensor nicht,
Fehlermeldung „Der Sensor antwortet nicht. Verkabelung und Stromversorgung prüfen.“ und „Erneut prüfen“.

### Schritt 5: Sensor koppeln

Erklärung, bevor die Aktion startet:
- „Der Sensor wird mit diesem Gerät verbunden. Vorhandene Fingerabdrücke im Sensor werden dabei **gelöscht**.“
- „Der Sensor muss im Werkszustand sein (Standardadresse, kein Passwort). Ein gebrauchter Sensor muss am Sensor
  zurückgesetzt werden.“
- Bei `flashEncrypted = false`: Hinweis „Entwicklungsbetrieb: Das Passwort wird im Klartext gespeichert.“

Button „Sensor koppeln“ → PIN → Token (ACFG) → `pair` (`0x02`). Spinner mit „Der Sensor wird eingerichtet.“

Fehler:
- `0x30` NOT_ALLOWED: Entweder ist der Sensor nicht im Werkszustand, oder die Flash-Verschlüsselung ist nicht aktiv
  (in Produktivbetrieb). Die Meldung nennt beide Fälle, ohne zu raten, welcher zutrifft.
- `0x21` PROCESSING: Verkabelung prüfen, zurück zu Schritt 4.

Nach Erfolg: `status` lesen, `paired = true` muss erscheinen.

### Schritt 6: Ersten Fingerabdruck anlernen

Erklärung: „Du legst den Finger zweimal auf den Sensor. Dazwischen hebst du ihn ab. Der Ring leuchtet während
des Anlernens blau, in Stufen von leicht bis stark. Am Ende zeigt er grün (Erfolg) oder rot (Fehler).“

Ablauf wie in `WEBAPP_PROMPT.md`, Abschnitt „Anlernen“: PIN → Token → `enroll` (`0x03`) mit den dort
beschriebenen Texten.

Dieser Schritt ist **optional**. „Überspringen“ ist erlaubt, mit dem Hinweis, dass ohne Fingerabdruck die
PIN allein zur Anmeldung dient.

Nach Erfolg: `status` lesen, der Slot muss in `4: [slots]` stehen.

### Schritt 7: Backup erstellen (dringend empfohlen)

Erklärung: „Ein Backup enthält das Sensor-Passwort. Ohne Backup ist der Fingerabdruck nach einem Gerätereset oder
einem Austausch des Sensors verloren. Das Backup ist mit einer Passphrase verschlüsselt.“

Ablauf wie in `WEBAPP_PROMPT.md`, Abschnitt „Backup“. Passphrase mindestens 12 Zeichen, zweimal eingeben.
Die Datei wird heruntergeladen. Danach die Anweisung: „Lege die Datei an zwei getrennten Orten ab.“

Überspringen ist erlaubt, aber nur nach einer ausdrücklichen Bestätigung: „Ich habe verstanden, dass ich ohne
Backup den Fingerabdruck verliere.“

### Schritt 8: Abschluss

Zusammenfassung in einer Tabelle:

| Punkt | Stand |
|---|---|
| Betriebsart | Entwicklungsbetrieb oder Produktiv |
| Flash-Verschlüsselung | aktiv / nicht aktiv |
| PIN | gesetzt (6 Ziffern) / Altpin (4 Ziffern) |
| Sensor | gekoppelt / nicht gekoppelt |
| Fingerabdrücke | Anzahl und Slots |
| Backup | erstellt am … / nicht erstellt |

Hinweise am Ende, je nach Zustand:
- Entwicklungsbetrieb: „Nicht für den Produktivbetrieb geeignet. Das Sensor-Passwort liegt im Klartext.“
- Kein Backup: „Erstelle ein Backup unter ‚Fingerabdruck → Backup erstellen‘.“
- Nicht gekoppelt: „Der Sensor ist noch nicht gekoppelt. Das kannst du jederzeit im Fingerabdruck-Bereich tun.“

Button „Zur Anmeldung“ führt in die normale Anlern-UI.

## Wiederaufnahme und Abbruch

- Bricht der Nutzer ab, ist jeder bereits geschriebene Schritt gültig. Der Assistent liest beim nächsten Start den
  Zustand neu und bietet an, bei dem Schritt weiterzumachen, der noch offen ist.
- Abbruch mitten in `pair` oder `enroll`: Der Zustand wird neu gelesen. Ein halb gekoppelter Sensor führt zu
  einer Meldung „Sensor nicht vollständig eingerichtet. Bitte Schritt 5 wiederholen.“ Die App versucht nicht,
  selbst zu reparieren.
- „Einrichtung wiederholen“ im Menü startet den Assistenten erneut, überspringt aber Schritte, deren Zustand
  bereits erfüllt ist.

## Texte und Sprache

- Deutsch als Vorlage, wie in der bestehenden Webapp.
- Keine Fachbegriffe ohne Erklärung beim ersten Auftreten (eFuse, Flash-Verschlüsselung, Secure Boot, Shared Secret).
- Fehlermeldungen wie in der Tabelle von `WEBAPP_PROMPT.md`.

## Sicherheitsregeln (zusätzlich zu `WEBAPP_PROMPT.md`)

1. Der Assistent sendet keinen Schreibbefehl, bevor der Nutzer den dazugehörigen Schritt bestätigt hat.
2. Die Betriebsart „Entwicklungsbetrieb“ ist nur eine Anzeige. Sie ändert keine Einstellung am Gerät.
3. Signaturschlüssel und PIN werden nie gespeichert, nie geloggt und nie in die Backup-Datei geschrieben.
4. Die Webapp erzeugt keine Schlüssel und brennt keine eFuses.
5. Irreversible Schritte nur mit der ausdrücklichen Bestätigung aus Schritt 2a.

## Lieferumfang

1. Ein Modul `setupWizard` mit einem Zustandsautomaten für die Schritte 1–8. Jeder Übergang liest den Zustand
   vom Gerät neu.
2. Die UI-Komponente mit Fortschrittsanzeige und den Texten oben.
3. Ein Modul `pinProtocol` für `setPIN` nach CTAP 2.1, das `getPinToken` aus dem Anlern-Prompt wiederverwendet.
4. Tests mit gemockter HID-Verbindung:
   - Wahl des Startzustands (neuer Schlüssel, Altschlüssel, ohne Fingerabdruck),
   - PIN-Prüfung (6 Ziffern, beide Eingaben gleich, Ablehnung vor dem Senden),
   - `setPIN`-Kodierung als Bytevergleich mit einem Testvektor,
   - Weiterschalten nur bei bestätigtem Zustand (kein Schreibbefehl ohne Bestätigung),
   - Fehlercode-Abbildung für `0x30`, `0x35`, `0x21`,
   - Wiederaufnahme nach Verbindungsabbruch.
5. Eine Liste offener Punkte (z. B. genaue `setPIN`-Kodierung gegen die Firmware prüfen, falls der Assistent gegen
   eine ältere Firmware läuft).

## Abnahme

- Ein neuer Schlüssel startet den Assistenten automatisch. Ein eingerichteter Schlüssel nicht.
- Ohne bestätigte Checkbox in Schritt 2a gibt es kein Weiter zum Brennen. Die App zeigt keinen Befehl, der eFuses brennt.
- Die PIN wird nur mit 6 Ziffern und zweimal gleich akzeptiert.
- `setPIN` wird nur einmal gesendet, auch nach einem Klick auf „Zurück“ oder einem Neuladen der Seite.
- Ist `flashEncrypted = false`, bleiben Pairing und Restore im Assistenten deaktiviert.
- Ist `supported = false`, enthält der Assistent keinen Sensor-Schritt.
- Nach Abbruch zeigt der Assistent beim nächsten Start den tatsächlichen Gerätezustand.
- Nach dem Abschluss stimmt die Zusammenfassung mit `status` und `getInfo` überein.
