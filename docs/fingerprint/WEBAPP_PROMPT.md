# Prompt: Anlern-UI für den R558-Fingerabdrucksensor in die Pico-FIDO-Webapp

Kopiere den folgenden Abschnitt in die KI, die die Webapp erweitert. Der Prompt ist vollständig: Er enthält das
Protokoll, die Sicherheitsregeln und die Abnahmekriterien.

---

## Auftrag

Du erweiterst die Webapp für **Pico FIDO** (Firmware für ESP32-S3, läuft im Browser über **WebHID**) um eine
Oberfläche zum **Koppeln, Anlernen, Löschen und Entsperren** eines **R558-Fingerabdrucksensors**.

Das Gerät akzeptiert Fingerabdrücke **nur** über den unten beschriebenen Vendor-Befehl. Anlernen ist
**ausschließlich über diese Webapp** möglich. Schreibe keine Funktion, die ohne PIN-Token schreibt.

## Rahmenbedingungen

- Browser: Chromium-basiert (WebHID ist nur dort verfügbar). Die Seite muss in einem sicheren Kontext laufen
  (`https://` oder `http://localhost`). WebHID-Zugriffe brauchen eine Benutzeraktion (Klick).
- Kryptografie nur mit **WebCrypto** (ECDH P-256, HMAC-SHA-256, AES-256-CBC, HKDF-SHA-256). Keine eigenen
  Krypto-Implementierungen. Keine Drittbibliotheken, die nicht schon im Projekt sind.
- Sprache der Oberfläche: wie in der bestehenden Webapp. Texte unten sind Deutsch als Vorlage.

## Transport

- Gerät per WebHID öffnen (FIDO-HID-Interface, Usage Page `0xF1D0`, Usage `0x01`).
- CTAPHID-Kanal initialisieren (`CTAPHID_INIT`) und Kanal-ID merken.
- Befehl **`CTAP_VENDOR_CBOR` = `0xC1`** senden (CTAPHID-Befehl mit Initial-Frame, Bit 7 gesetzt).
- Nutzlast (`data`) = **Byte `0x09`** (Vendor-Befehl `CTAP_VENDOR_FP`) **gefolgt von einer CBOR-Map**.
- Antwort: 1 Byte CTAP-Status (`0x00` = OK), danach optional CBOR-Map.
- Die Map muss die Schlüssel **in aufsteigender Reihenfolge** enthalten (1, 2, 3, 4). Der Schlüssel 1 ist Pflicht.
- Keepalive-Frames (`CTAPHID_KEEPALIVE`, `0xBB`) während laufender Befehle ignorieren und weiter warten.
  Die Befehle `enroll` und `pair` blockieren bis zu ca. 60 Sekunden.

### CBOR-Map der Anfrage

| Schlüssel | Typ | Bedeutung |
|---|---|---|
| 1 | uint | Unterbefehl (siehe unten) |
| 2 | map | optional: `{1: bytes}` – Parameter des Unterbefehls. Nur bei `delete` gesetzt. |
| 3 | uint | `pinUvAuthProtocol` (2). Nur wenn Schlüssel 4 vorhanden ist. |
| 4 | bytes(32) | `pinUvAuthParam` (nur bei Unterbefehlen mit Auth, siehe unten) |

### Unterbefehle

| Code | Name | Auth | Parameter | Antwort (Map) |
|---|---|---|---|---|
| `0x01` | status | keine | – | `{1: bool paired, 2: bool locked, 3: uint capacity, 4: [uint slots], 5: uint failedAttempts, 6: bool supported, 7: bool flashEncrypted}` |
| `0x02` | pair | PIN-Token, Berechtigung ACFG | – | `{1: uint capacity}` |
| `0x03` | enroll | PIN-Token, Berechtigung ACFG | – | `{1: uint slot}` |
| `0x04` | delete | PIN-Token, Berechtigung ACFG | Schlüssel 2 optional: `{1: bytes(2)}` = Slot als 2 Byte Big-Endian, `0xFFFF` = alle. Ohne Schlüssel 2 werden **alle** gelöscht. | `{}` |
| `0x05` | unlock | PIN-Token, Berechtigung ACFG | – | `{}` |
| `0x06` | backup | PIN-Token, Berechtigung ACFG | – | `{1: bytes(43) Backup-Blob}`. Der Blob ist **unverschlüsselt**, die Webapp verschlüsselt ihn (siehe „Backup“). |
| `0x07` | restore | PIN-Token, Berechtigung ACFG | Schlüssel 2: `{1: bytes(43) Backup-Blob}` | `{}` |

### Berechnung von `pinUvAuthParam` (Auth)

```
payload = 32 × 0xFF  ||  0x0D  ||  Unterbefehl (1 Byte)  ||  rohe CBOR-Bytes des Wertes von Schlüssel 2 (leer, wenn nicht vorhanden)
pinUvAuthParam = HMAC-SHA-256(pinUvAuthToken, payload)      // 32 Byte bei Protokoll 2
```

- „Rohe CBOR-Bytes“ heißt: exakt die Bytes, mit denen die Map des Schlüssels 2 in der Anfrage kodiert ist.
  Beispiel `delete` Slot 3: Wert `{1: h'0003'}` ergibt die Bytes `A1 01 42 00 03`.
- Diese Bytes müssen **dieselben** sein, die du in die Anfrage schreibst.

## PIN-Token holen (Protokoll 2, Berechtigung ACFG)

Implementiere das CTAP-2.1-PIN-Protokoll 2:

1. `clientPin` (CTAP-Befehl `0x06` über CTAPHID_CBOR) mit `subCommand 0x02` → `getKeyAgreement`. Gerätekey (COSE-EC2 P-256) empfangen.
2. Ephemeres P-256-Schlüsselpaar erzeugen, ECDH, `Z` = x-Koordinate (32 Byte).
3. Shared Secret = `HKDF-SHA-256(Z, salt = 32×0x00, info = "CTAP2 HMAC key", 32 Byte)` ||
   `HKDF-SHA-256(Z, salt = 32×0x00, info = "CTAP2 AES key", 32 Byte)` (64 Byte). Der Code auf dem Gerät macht genau das.
4. `pinHashEnc` = AES-256-CBC(key = AES-Teil, IV = 16×0x00, data = `LEFT(SHA-256(PIN), 16)`).
5. `clientPin` mit `subCommand 0x09` (`getPinUvAuthTokenUsingPinWithPermissions`), Schlüssel: `1: 2` (Protokoll),
   `2: 0x09`, `3: keyAgreement (eigener öffentlicher COSE-Key)`, `6: pinHashEnc`, `9: 0x20` (ACFG).
6. Antwort Schlüssel `2` = verschlüsselter Token (AES-256-CBC, IV 16×0x00, Schlüssel = AES-Teil). Entschlüsseln → 32 Byte Token.
7. Token nur im Speicher halten, nach Gebrauch überschreiben, **nie** speichern oder loggen.
   Token-Lebensdauer: sofort neu holen, wenn das Gerät mit Fehler `0x36` (PUAT_REQUIRED) oder `0x33` antwortet.

Die PIN selbst: nur für den Token-Schritt verwenden, nicht speichern, nicht in Logs, nicht in URLs.

## Ablauf in der UI

1. **Verbinden.** Gerät auswählen, `status` abfragen. Ist `6: supported` = `false`, ist die Firmware ohne
   Fingerabdruck-Unterstützung gebaut. Das klar anzeigen und keinen Fingerabdruck-Bereich zeigen.
   Ein Gerät mit `supported = true`, aber `paired = false`, ist normal: Dann ist der Sensor nur noch nicht gekoppelt.
   Antwortet `status` mit `0x3E` (INVALID_SUBCOMMAND) oder `0x02` (INVALID_PARAMETER), ist die Firmware
   zu alt (ohne `0x09`). Das ebenfalls klar anzeigen.
2. **Nicht gekoppelt (`paired = false`).** Hinweis zeigen: „Koppelt nur den Sensor, der in dieses Gerät eingebaut ist.
   Ein anderer Sensor wird nur akzeptiert, wenn der bisherige Sensor nicht mehr angeschlossen ist.“
   PIN abfragen → Token holen → `pair` senden. Während der Anfrage Spinner und Text „Der Sensor wird eingerichtet.“
   Kein Tastendruck nötig.
3. **Gekoppelt, aber gesperrt (`locked = true`).** Nachricht: „Fingerabdruck gesperrt (zu viele Fehlversuche oder
   Manipulation). Mit PIN entsperren.“ Button → PIN → Token → `unlock`. Kein Tastendruck am Gerät nötig.
   Bei Manipulation ist das Entsperren nur bewusst durch den Benutzer zu bestätigen.
4. **Anlernen (`enroll`).** Vor dem Start erklären:
   „Du legst den Finger zweimal auf den Sensor. Dazwischen hebst du ihn ab.“ Dann einen Button „Anlernen starten“.
   Nach dem Klick: PIN → Token → `enroll`. Während die Anfrage läuft:
   - Hinweis „Finger jetzt auflegen“, dann nach etwa 3 Sekunden „Finger abheben und warten“, dann „Finger erneut auflegen“.
     Die Anfrage liefert **keine** Zwischenstände (sendet aber laufend CTAPHID-Keepalives `0x02` und lässt sich per CTAPHID-Cancel sauber abbrechen). Die Texte sind eine Zeitschätzung.
     Der **integrierte RGB-Leuchtring des GROW R558-S** (angesteuert per UART `PS_ControlBLN`, `0x3C`, sowie parallel ein optionaler WS2812-Ring an `GPIO4` und die Onboard-LED) atmet während des Wartens blau, blinkt nach Scan 1 kurz grün und nach erfolgreichem Speichern 2× grün (bzw. bei Fehler rot). Es gibt keinen Taster.
   - Ergebnis: Erfolg → Slot anzeigen und Liste aktualisieren. Fehler → Fehlermeldung aus der Tabelle unten,
     Button „Erneut versuchen“.
5. **Liste der Slots.** Aus `status` (Schlüssel 4). Pro Slot „Löschen“ (PIN, Bestätigungsdialog).
   „Alle löschen“ mit doppelter Bestätigung (PIN, Bestätigungsdialog mit dem Wort „LÖSCHEN“).
6. Nach jedem schreibenden Befehl `status` neu abfragen.
7. **Flash-Verschlüsselung.** Ist `7: flashEncrypted = false`, zeigt die App einen Warnhinweis: „Die Flash-Verschlüsselung
   ist am Gerät nicht aktiv. Koppeln und Wiederherstellen sind gesperrt, bis sie aktiv ist.“ Pairing und Restore
   sind dann ausgeschaltet. Die App versucht es nicht erst, sondern deaktiviert die Schaltflächen.
8. **Backup (R3).** Im Fingerabdruck-Bereich ein Button „Backup erstellen“ (nur bei `paired = true`).
   Ablauf:
   - PIN → Token → `backup` (0x06) → 43-Byte-Blob.
   - Passphrase abfragen. Mindestens 12 Zeichen. Zweimal eingeben, damit kein Tippfehler die Datei unbrauchbar macht.
   - Blob mit der Passphrase verschlüsseln (Abschnitt „Backup-Verschlüsselung“), Datei herunterladen.
   - Blob-Puffer und Schlüssel nach Gebrauch nullen.
   - Hinweis: „Die Datei enthält das Sensor-Passwort. Bewahre sie sicher auf.“
9. **Restore (R3, nach einem FIDO-Reset).** Ist `paired = false` und die App hat eine Backup-Datei, Button „Backup
   wiederherstellen“:
   - Zuerst eine neue PIN setzen lassen (nach dem Reset gibt es keine PIN). Die App führt den Nutzer dorthin.
   - Datei wählen, Passphrase eingeben, entschlüsseln. Falsche Passphrase → Meldung „Passphrase falsch oder Datei
     beschädigt“, ohne weitere Details.
   - PIN → Token → `restore` (0x07) mit dem Blob in Schlüssel 2 → danach `status`.
   - Erwartet: `paired = true`, `locked = false`, Slots wie im Backup. Bei `NOT_ALLOWED` Hinweis: „Der Sensor passt nicht
     zum Backup, oder die Anzahl der Fingerabdrücke stimmt nicht.“ Die App zeigt nicht, welcher Fall es ist.

## PIN-Regeln

Die PIN ist die FIDO2-PIN des Geräts. Sie wird nur für die Token-Anforderung benutzt (siehe oben). Vollständige
Erklärung für Nutzer: `docs/fingerprint/PIN_UND_BACKUP.md`.

- **Neue PIN setzen oder ändern: genau 6 Ziffern (0–9).** Die App lehnt andere Eingaben vor dem Senden ab.
- **Mit bestehender PIN anmelden** (für Pairing, Anlernen, Löschen, Entsperren, Backup, Restore): die App nimmt
  die PIN so an, wie sie gesetzt wurde, mindestens 4 Zeichen. Bestehende 4-stellige PINs bleiben gültig, bis der
  Nutzer sie ändert. Ein Hinweis erklärt, dass neue PINs 6 Ziffern haben.
- **Eingabe:** eigenes Dialogfeld mit Ziffernfeld, `autocomplete="off"`, kein Speichern im Formular.
- **Wo:** Die PIN wird im Fingerabdruck-Bereich vor jeder schreibenden Aktion abgefragt. Der Sensor hat keine
  Eingabe, das Gerät hat keinen Bildschirm.
- Ein Restore setzt eine **neue** PIN voraus. Ohne PIN antwortet das Gerät mit `0x35` (PIN_NOT_SET).

## Backup-Verschlüsselung (WebCrypto)

- Schlüsselableitung: **PBKDF2-HMAC-SHA-256**, mindestens 600 000 Iterationen, 16 Byte Salt (zufällig pro Datei).
- Verschlüsselung: **AES-256-GCM**, 12 Byte IV (zufällig pro Datei), 16 Byte Tag (Teil von WebCrypto).
- Datei (JSON, UTF-8):
  ```json
  {"format":"pico-fido-r558-backup","version":1,
   "kdf":{"name":"PBKDF2","hash":"SHA-256","iterations":600000,"salt":"<base64>"},
   "cipher":{"name":"AES-GCM","iv":"<base64>"},
   "data":"<base64 of ciphertext+tag>"}
  ```
- Die Metadaten sind nicht geheim, aber als AES-GCM-Additional-Data gebunden: `additionalData` = die UTF-8-Bytes des
  Strings `pico-fido-r558-backup/v1`. Eine geänderte Datei schlägt dann beim Entschlüsseln fehl.
- Entschlüsseln: Format und Version prüfen, Schlüssel ableiten, `decrypt`. Schlägt es fehl, nur die allgemeine
  Meldung zeigen.
- Der Klartext-Blob muss 43 Byte lang sein und mit Version `0x01` beginnen. Sonst abbrechen.

## Fehlercodes (CTAP-Statusbyte) → Meldung

| Code | Bedeutung | Meldung (Vorlage) |
|---|---|---|
| `0x2F` | USER_ACTION_TIMEOUT | Zeit abgelaufen. Bitte erneut versuchen. |
| `0x3F` | UV_INVALID | Finger nicht erkannt bzw. die beiden Scans passen nicht zusammen. Erneut versuchen. |
| `0x3C` | UV_BLOCKED | Fingerabdruck ist gesperrt. Mit PIN entsperren. |
| `0x30` | NOT_ALLOWED | Nicht gekoppelt, oder die Aktion ist nicht erlaubt: Sensor schon gekoppelt, der neue Sensor ist nicht im Werkszustand (ggf. am Sensor zurücksetzen), Flash-Verschlüsselung nicht aktiv (`flashEncrypted = false`), oder ein Restore passt nicht zum Sensor. |
| `0x2C` | INVALID_OPTION | Es ist kein Fingerabdruck angelernt (z. B. beim Löschen eines leeren Slots). |
| `0x21` | PROCESSING | Sensorfehler. Verkabelung und Stromversorgung prüfen. |
| `0x28` | KEY_STORE_FULL | Sensor ist voll. Ein Fingerabdruck muss zuerst gelöscht werden. |
| `0x27` | OPERATION_DENIED | Vorgang abgebrochen. Die Fingerabdruck-Befehle verlangen keinen Tastendruck. |
| `0x33` | PIN_AUTH_INVALID | PIN falsch oder Token ungültig. Neu eingeben. |
| `0x35` | PIN_NOT_SET | Zuerst eine PIN am Gerät setzen. |
| `0x36` | PUAT_REQUIRED | Kein gültiges Token. Neu anmelden. |
| `0x3E` | INVALID_SUBCOMMAND | Gerätefirmware zu alt für diese Funktion. |
| `0x02` | INVALID_PARAMETER | Ungültige Eingabe (z. B. Slot außerhalb des Bereichs, oder ein beschädigter Backup-Blob). |

Eine PIN-Eingabe, die falsch ist, zählt auf dem Gerät als Fehlversuch der PIN-Retries. Die Webapp muss den Zähler
nicht selbst führen, soll aber bei `0x33` deutlich auf die Restversuche hinweisen, wenn das Gerät sie liefert.

## Sicherheitsregeln (verbindlich)

1. Kein Schreibbefehl ohne gültiges PIN-Token mit Berechtigung ACFG (`0x20`).
2. Die PIN nie speichern, nie loggen, nie in den DOM-Text, nie in URLs schreiben.
3. Token und Shared Secret nach Gebrauch mit Nullen überschreiben (Uint8Array `fill(0)`).
4. Löschen und Entsperren immer mit Bestätigungsdialog.
5. Kein Fallback: Schlägt Auth fehl, nichts senden.
6. Fehlermeldungen dürfen nicht verraten, ob ein bestimmter Finger gespeichert ist.
7. Die Webapp darf die Slot-Nummern anzeigen, nie Biometriedaten (es gibt keine, der Sensor hält sie).

## Lieferumfang

1. Ein Modul `fingerprintClient` (oder passend zum Projekt benannt) mit den Funktionen
   `status()`, `pair(token)`, `enroll(token)`, `remove(token, slot | 'all')`, `unlock(token)` und `getPinToken(pin)`.
   Alle Funktionen liefern typisierte Ergebnisse oder werfen einen Fehler mit CTAP-Code.
2. Die UI-Komponente mit den Zuständen aus dem Ablauf oben, einschließlich Backup und Restore.
   Die Backup-Verschlüsselung als eigenes Modul `backupCodec` (encrypt/decrypt mit Passphrase).
3. Tests mit gemockter HID-Verbindung:
   - Anfrage-Kodierung (Schlüsselreihenfolge, Auth-Payload als Bytevergleich mit einem Testvektor),
   - Token-Ableitung (HKDF-Parameter laut Abschnitt oben),
   - Fehlercode-Abbildung,
   - Zustandswechsel (nicht gekoppelt → gekoppelt → gesperrt → entsperrt).
4. Eine kurze Liste offener Punkte (z. B. Verhalten bei Firmwareversionen ohne `0x09`).

## Abnahme

- Ohne PIN-Token sendet die App **keine** Schreibbefehle.
- Ein Enrollment ergibt einen Slot, der in `status` erscheint.
- Ein gelöschter Slot verschwindet aus `status`.
- Bei gesperrtem Zustand ist Enrollment nicht möglich, Entsperren schon.
- Die Anfrage-Kodierung entspricht exakt den Tabellen oben (Tests grün).
- Backup: Verschlüsseln und Entschlüsseln rund um (gleiche Passphrase → gleicher Blob). Falsche Passphrase → Fehler.
  Geänderte Datei → Fehler. Blob mit falscher Länge oder Version → Fehler, nichts wird gesendet.
- Restore: Ohne PIN-Token kein `0x07`. Nach erfolgreichem Restore zeigt `status` die Slots aus dem Backup.
- Ist `flashEncrypted = false`, sind Pairing und Restore deaktiviert, und die App sendet dafür keinen Befehl.
- Neue PIN mit 5 Ziffern oder Buchstaben wird vor dem Senden abgelehnt. Anmeldung mit einer 4-stelligen Altpin geht.
- Ist `supported = false`, zeigt die App keinen Fingerabdruck-Bereich und sendet keine Befehle außer `status`.
