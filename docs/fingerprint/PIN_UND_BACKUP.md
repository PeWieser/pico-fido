# PIN und Backup des Fingerabdrucksensors

Dieses Dokument beschreibt, was die **PIN** ist, wo du sie eingibst, und wie das **Backup** nach einem
Authenticator-Reset funktioniert. Die Webapp muss sich daran halten (siehe `WEBAPP_PROMPT.md`).

## 1. Was ist die PIN?

Die PIN ist die **FIDO2-PIN des Pico-FIDO-Geräts**. Sie ist ein Geheimnis, das nur du kennst. Sie wird auf dem Gerät
gespeichert, aber nur als Prüfwert (nicht im Klartext). Die Firmware verlangt sie für alle Änderungen am
Fingerabdrucksensor:

- Pairing (Sensor koppeln)
- Anlernen eines Fingers
- Löschen eines oder aller Fingerabdrücke
- Entsperren nach Fehlversuchen
- Backup erstellen und Backup wiederherstellen

Die PIN ersetzt den Tastendruck. Am Gerät gibt es keine Anzeige und keine Eingabe. Die einzige Rückmeldung ist
der LED-Ring.

## 2. Anforderungen an die PIN

- **Mindestens 6 Zeichen.** Neue Geräte verlangen 6 Zeichen. Bestehende PINs mit 4 Zeichen bleiben gültig, bis
  du sie änderst. Danach gilt die Mindestlänge von 6.
- **Neue PIN setzen oder ändern:** die Webapp akzeptiert genau 6 Ziffern (0–9).
- **Anmelden mit einer bestehenden PIN:** die Webapp nimmt die PIN an, wie sie gesetzt wurde (mindestens 4 Zeichen),
  damit Altpins weiter funktionieren.
- Die PIN wird nie gespeichert, nie geloggt und nie in eine URL geschrieben (siehe Sicherheitsregeln im Prompt).

## 3. Wo gibst du die PIN ein?

- **Beim Setzen der PIN** (erstmalig oder Änderung): in der Pico-FIDO-Webapp im Bereich PIN. Der Browser kann
  ebenfalls nach der PIN fragen, wenn er einen Passkey mit Benutzerverifikation anlegt.
- **Beim Fingerabdruck-Bereich** (Pairing, Anlernen, Löschen, Entsperren, Backup, Restore): die Webapp fragt die PIN in
  einem eigenen Dialog ab. Sie wird dort gegen das Gerät geprüft. Eine falsche PIN zählt als Fehlversuch der
  PIN-Versuche auf dem Gerät.
- Die PIN wird **nie am Sensor** eingegeben. Der R558 hat keine Tastatur.

## 4. Backup und Restore (R3)

### Warum es das braucht

Ein Authenticator-Reset löscht die Konfiguration des Fingerabdrucksensors (Passwort, Adresse, belegte Slots) auf dem
ESP. Der Sensor selbst behält Passwort und Adresse. Ohne Backup ist der Sensor dann nur über `RestSetting` am Sensor
wieder verwendbar. Das Backup macht das überflüssig.

### Was das Backup enthält

Eine 43-Byte-Struktur (Version 1):

| Bytes | Inhalt |
|---|---|
| 0 | Version (1) |
| 1–4 | Sensor-Passwort |
| 5–8 | Sensor-Adresse (Big-Endian) |
| 9–10 | Kapazität (Big-Endian) |
| 11–42 | Slot-Bitmap (256 Slots) |

Das Backup enthält **keine** Biometriedaten. Die Templates liegen weiter im Sensor. Es enthält aber das
Sensor-Passwort. Wer es unverschlüsselt besitzt und den Sensor hat, kann einen Sensor anlernen. Deshalb wird das
Backup in der Webapp mit einer Passphrase verschlüsselt, bevor es die Webapp verlässt.

### Ablauf Backup

1. Gerät mit PIN-Token (ACFG) und Befehl `0x06` (backup) abfragen. Es kommt ein 43-Byte-Blob zurück.
2. Webapp fragt eine Passphrase ab (mindestens 12 Zeichen) und verschlüsselt den Blob (siehe `WEBAPP_PROMPT.md`).
3. Die Webapp bietet die Datei zum Download an. Der Blob im Speicher wird genullt.

### Ablauf Restore (nach Authenticator-Reset)

1. Gerät ist frisch: Nach dem Reset gibt es **keine PIN**. Zuerst eine neue PIN setzen (6 Zeichen).
2. Backup-Datei wählen, Passphrase eingeben, Blob entschlüsseln. Bei falscher Passphrase keine Weiterverarbeitung.
3. PIN eingeben → PIN-Token (ACFG) → Befehl `0x07` (restore) mit dem Blob in Schlüssel 2.
4. Das Gerät prüft, ob der Sensor das Passwort an der gespeicherten Adresse akzeptiert, und vergleicht die Zahl der
   Templates mit der Bitmap. Erst dann speichert es die Konfiguration.
5. Danach `status` neu abfragen. Erwartet: `paired = true`, `locked = false`, Anzahl der Slots wie im Backup.

### Was Restore nicht tut

- Restore setzt den Sperrzustand auf „nicht gesperrt“ und die Fehlzähler auf 0. Das entspricht dem Entsperren mit
  PIN. Ein Restore wird nur akzeptiert, wenn der Sensor Passwort und Adresse aus dem Backup bestätigt. Nach einem
  Authenticator-Reset gibt es außerdem keinen gespeicherten Sperrzustand mehr.
- Restore ersetzt keinen gekoppelten Sensor. Ist ein anderer Sensor gekoppelt, lehnt das Gerät mit `ALREADY_PAIRED`
  ab.
- Die Slot-Bitmap wird nur über die Anzahl geprüft. Wenn die Anzahl stimmt, aber die falschen Slots im Backup stehen,
  fällt das beim ersten Abgleich auf (unbekannter Slot → Sperre). Das ist eine bekannte Grenze.

## 5. Flash-Verschlüsselung (R1)

Pairing und Restore sind nur erlaubt, wenn die ESP32-Flash-Verschlüsselung aktiv ist. Die Option heißt
`PICO_FIDO_R558_REQUIRE_FLASH_ENCRYPTION` (Standard: an). Ist sie aus, wird das Pairing ohne Verschlüsselung erlaubt.
Dann liegt das Sensor-Passwort im Klartext im Flash. Der Status `flash_encrypted` (Schlüssel 7 von `status`) zeigt
den aktuellen Zustand.
