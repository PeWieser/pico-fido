# R558-S wieder benutzbar machen – Passwortsperre auflösen

> **Stand:** 24. Oktober 2026
> **Betrifft:** Pico FIDO auf ESP32-S3 Super Mini mit GROW R558-S
> **Symptom:** Der LED-Ring bleibt dunkel, jede Anweisung wird mit `0x21` beantwortet, Pairing
> scheitert mit einem Kommunikationsfehler.
> **Kurzfassung:** Es gibt jetzt einen nicht-destruktiven Wiederherstellungspfad im Gerät
> (Vendor-Befehl `0x0B`, seit Oktober 2026 mit **Flash-Stufe**). Er stellt den Sensor wieder her,
> solange das Passwort *irgendwie* beschaffbar ist: reproduzierbar (seit Build 47 aus der
> eFuse-MAC abgeleitet) **oder** als Klartext-Rest im ESP32-Flash erhalten (der Fall für
> Zufallspasswörter vor Build 47, z. B. die Sperre bei `A=0x29062D09` – siehe korrigiertes §2.2).
> Praxis-Anleitung: `docs/fingerprint/R558_RETTUNG_ANLEITUNG.md`, Rettungs-Website: `website/`.

---

## 1. Warum der Sensor „tot“ ist

Das R558-S speichert sein **Modulpasswort** (4 Byte) und seine **Chip-Adresse** (4 Byte) im eigenen
NOR-Flash. Handbuch V1.1, Abschnitt „Module password“:

> „If the default password is modified, after the module is powered on, the first instruction … must be
> verify password. Only after the password verification is passed, the module will enter the normal
> working state and receive other instructions. … (the modified password cannot be obtained through the
> communication instruction. If forgotten by mistake, the module cannot communicate, please use with
> caution)“

Daraus folgen zwei harte Tatsachen:

1. Solange das Passwort nicht verifiziert ist, antwortet das Modul auf **alles** außer `VfyPwd (0x13)`
   mit `0x21`. Das betrifft `HandShake (0x35)`, `ControlBLN (0x3C)` (deshalb bleibt der Ring dunkel),
   `RestSetting (0x3B)`, `ReadSysPara (0x0F)` und auch `ReadINFpage (0x16)` – es gibt **keinen**
   Befehl, der das Passwort ausliest.
2. `RestSetting (0x3B)` („Restore factory setting“) setzt Daten und Schlüsselpaare zurück, ist aber
   selbst passwortgeschützt. Es ist **kein** Notausgang.

Das Modul ist also nicht kaputt, sondern wartet auf 4 Byte, die nur das Gerät kennt, das sie damals
gesetzt hat.

### 1.1 Wie es zu dem Zustand kam

Bis Firmware-Build 47 hat `fp_pair()` das Modulpasswort mit `random_fill_buffer()` erzeugt und nur im
eigenen Flash (`EF_FP_CONF`) abgelegt. War dieser Eintrag danach weg – FIDO-Reset, `erase_flash`,
Neuaufspielen, Wechsel des Boards –, existierte das Passwort **nirgends mehr**. Genau das ist die
Ursache des aktuellen Zustands.

Seit Build 47 gilt stattdessen:

| Modus | Passwort | Adresse | Reproduzierbar? |
|---|---|---|---|
| Flash verschlüsselt („prod“) | `SHA-256("pico-fido-r558-efuse-bind-v1" ‖ eFuse-MAC)[0..3]` | `SHA-256(…)[4..7]` | **ja**, auf demselben Chip, auch nach `erase_flash` |
| Entwicklungsmodus („dev“, keine Flash-Verschlüsselung) | `"R558"` | `"PICO"` (0x5049434F) | **ja**, fest im Code |

Beide Ableitungen passen in `esp_dev_efuse_session()` bzw. `esp_dev_shared_session()` in
`src/fido/fp_r558.c`. Ein zufälliges Passwort wird auf echter Hardware **nicht mehr** verwendet
(siehe Abschnitt 5).

---

## 2. Die Wiederherstellungs-Leiter (implementiert)

Neu: `src/fido/fp_r558_recover.c` und `src/fido/fp_r558_recover.h`.

`fp_recover_sensor()` baut eine geordnete Kandidatenliste und schickt für jeden Kandidaten **genau ein**
`VfyPwd (0x13)`. Nichts anderes. Kein `SetPwd`, kein `SetChipAddr`, kein `RestSetting`, kein
Glitch, kein Brownout – der Aufruf ist beliebig oft wiederholbar und verändert das Modul nicht.

### 2.1 Reihenfolge der Stufen

| # | Quelle | Inhalt | Greift wenn … |
|---|---|---|---|
| 1 | `stored` | Passwort + Adresse aus `EF_FP_CONF` | die Konfiguration noch da ist (Normalfall) |
| 2 | `derived` | `SHA-256(Domain ‖ eFuse-MAC)` dieses ESP32-S3 | der Flash gelöscht/neu geflasht wurde, das Board aber dasselbe ist |
| 3 | `shared` | `"R558"` @ `"PICO"` | Entwicklungsmodus (keine Flash-Verschlüsselung) |
| 4 | `user` | bis zu 4 Kandidaten à 4 Byte, die der Besitzer liefert | man kennt das alte Passwort oder hat ein Backup |
| 5 | `factory` | `0x00000000` @ `0xFFFFFFFF` | `SetPwd` nie angekommen ist |

Jedes Passwort wird an **drei** Adressen probiert: gespeicherte Adresse, zuletzt beobachtete Adresse
und Werkadresse `0xFFFFFFFF`. Grund: Wenn `SetChipAddr (0x15)` verloren ging, ist das Passwort gesetzt,
die Adresse steht aber wieder auf Werkseinstellung – ein Fall, den die alte Firmware nicht abdeckte.

### 2.2 Warum das bei deinem Modul greifen kann – **korrigiert (Oktober 2026)**

> **Die früher hier stehende Behauptung ist falsch und wird hiermit ersetzt.** Dort hieß es,
> `A=0x29062D09` sei „die Adresse, die `esp_dev_efuse_session()` aus der MAC ableitet“.
> Das stimmt nicht:
>
> - Eine Vollsuche über **alle 297 Espressif-OUIs × 2²⁴ NIC-Teile** (≈ 4,98 Mrd. SHA-256,
>   `tools/r558_mac_search.c`, Selbsttest + Crosscheck gegen `hashlib`) fand **keine einzige**
>   MAC, die die Adresse `0x29062D09` ableitet – weder auf diesem Board noch auf irgendeinem anderen.
> - Damit steht fest: Das konkrete Modul wurde **vor Build 47** mit dem damaligen
>   `random_fill_buffer()`-Pfad gekoppelt (Passwort **und** Adresse aus der Hardware-RNG).
>   Auch der früher in der Firmware eingebettete Kandidat `0x7BF6B530` („AVX-512 OUI-Match“)
>   war haltlos und wurde entfernt.
>
> Für dieses Modul ist deshalb **nicht Stufe 2 (`derived`), sondern Stufe 3 (`flash`)** der Weg:
> Das Zufallspasswort stand im Klartext in `EF_FP_CONF`; das Dateisystem bewahrt beim
> Überschreiben/Löschen physische Alt-Kopien (Journal/Redo, frühere Sektorinhalte), solange der
> Chip nicht per `erase_flash` gelöscht wurde. Details: `R558_RETTUNG_ANLEITUNG.md` (Wege A–E).

Falls die Konfiguration dagegen intakt ist und nur die Verifikation scheitert, greift Stufe 1,
bei Build-≥-47-Pairings auf demselben Board Stufe 2.

### 2.3 Grenzen (ehrlich)

- Ist das Modul vor Build 47 mit einem **echten Zufallspasswort** gesperrt worden und existiert
  `EF_FP_CONF` nicht mehr, kann **keine** Software der Welt das Passwort zurückholen. 2³²
  `VfyPwd`-Versuche sind keine Option (bei ~20 ms pro Versuch ≈ 2,7 Jahre), und das Modul kann während
  einer solchen Serie die UART sperren. Die Leiter ist deshalb auf 16 Kandidaten begrenzt.
- Stufe 2 setzt voraus, dass es **derselbe ESP32-S3** ist. Bei einem Board-Tausch ist die MAC eine
  andere.
- Ohne Antwort auf der UART (`silent` in der Zusammenfassung) ist es kein Passwortproblem, sondern
  Verkabelung, Versorgung oder ein Modul, das nicht mehr bootet.

---

## 3. Auslösen

### 3.1 Über die Webapp / CTAP-HID

Vendor-Befehl `CTAP_VENDOR_CBOR` (`0xC1`), Nutzlast `0x09` + CBOR-Map:

```text
{ 1: 11 }                                   # 0x0B recover, ohne Kandidaten  →  Daten: 09 A1 01 0B
{ 1: 11, 2: { 1: h'A1B2C3D4' } }            # Schlüssel 2 ist eine MAP {1: bytes}! (Kandidaten à 4 Byte verkettet)
                                            # → Daten: 09 A2 01 0B 02 A1 01 44 A1 B2 C3 D4
```

> **Achtung, frühere Fassung war falsch:** Dort stand `{1: 11, 2: h'…'}` (Byte-String direkt unter
> Schlüssel 2). `cbor_vendor.c` erwartet aber wie bei allen Unterbefehlen Schlüssel 2 als **Map**
> `{1: bytes}`. Mit der alten Form wurden Besitzer-Kandidaten still ignoriert.

Kein PIN-Token nötig (wie bei `0x09` Reset und `0x0A` Unlock-Pass): Die Leiter kann nur Zugang
*wiederherstellen*, den das Gerät ohnehin ableiten kann. Sie zeigt kein Passwort an und schwächt die
Bindung nicht.

Antwort: die bekannte Status-Map, erweitert um

| Schlüssel | Bedeutung |
|---|---|
| `0x0A` | Telemetrie-Zeile, z. B. `recover: OK src=derived A=29062D09 try=3/11` |
| `0x0E` | `true`, wenn ein Kandidat geprüft werden konnte |
| `0x0F` | Quelle: `stored`, `derived`, `flash`, `shared`, `user`, `factory` oder `none` |

Bei Erfolg werden die geprüften Zugangsdaten als `STAGED` gespeichert. Ein anschließendes
`{1: 2}` (`pair`) setzt den Vorgang an seinen Endprüfungen fort, **ohne** `SetPwd`/`SetChipAddr` erneut
zu senden – das Modul kann also nicht ein zweites Mal verloren gehen.

Beispiel-Telemetrie:

```text
recover: OK src=derived A=29062D09 try=3/11      -> verbunden, Pairing fortsetzen
recover: no match (try=11 wrong=8 last=13 alive) -> Modul lebt, Passwort unbekannt
recover: no match (try=11 wrong=0 last=FF silent)-> kein Frame: Verkabelung/Versorgung prüfen
```

### 3.2 Über die Firmware-Konsole

```c
fp_recover_report_t rep;
if (fp_recover_sensor(NULL, 0, &rep) == FP_OK) {
    // rep.address / rep.password sind jetzt gültig, rep.summary für das Log
}
```

`fp_factory_reset_sensor()` ruft die Leiter jetzt selbst auf, wenn das gespeicherte Passwort nicht
mehr verifiziert. Ein Werksreset eines gesperrten Moduls ist damit möglich, sobald eine Stufe greift.

---

## 4. Wenn keine Stufe greift

Dann ist das Passwort unwiederbringlich (Abschnitt 2.3). Es bleiben genau drei Wege:

| Weg | Aufwand | Erfolgsaussicht | Risiko |
|---|---|---|---|
| **A. Backup einspielen** (`0x07 restore`), falls je eines gezogen wurde | Minuten | hoch, wenn das Backup zum Sensor passt | keins |
| **B. Modul tauschen** | Minuten, ~10–20 € | 100 % | keins – neues Modul ist werksfrisch, Pairing klappt sofort |
| **C. Modul-Flash löschen (Hardware-Eingriff)** | Stunden, Löten/Messtechnik | mittel | Modul kann unbrauchbar werden |

### 4.1 Zu Weg C – und warum er nicht der Normalfall sein sollte

Das Passwort liegt in der Parametertabelle im Flash des GD32VF103 auf dem Modul. Setzt man diesen
Flash auf Werkseinstellung zurück, sind Passwort und Adresse weg. Zwei Zugänge sind denkbar:

1. **UART-ISP-Bootloader des GD32.** Der GD32VF103 bootet bei angezogenem `BOOT0` aus dem
   System-ROM-Bootloader, der über USART0 mit `0x7F` synchronisiert (danach `0x11 0xEE` lesen,
   `0x44 0xBB` löschen, `0x92 0x6D` Mass-Erase). Auf den üblichen R558-Trägerplatten ist `BOOT0`
   fest auf GND gelegt und **nicht** als Pad herausgeführt; der Zugriff verlangt also einen
   Lötpunkt direkt am MCU-Pin. Ein Mass-Erase löscht auch alle Templates und – falls gesetzt – den
   Read-Out-Schutz.
2. **SWD/JTAG.** `SWCLK`/`SWDIO` sind je nach Trägerplatte als Testpunkte erreichbar. Mit einem
   Debugger, der den GD32VF103 unterstützt (RISC-V-OpenOCD), lässt sich der Flash ebenfalls löschen.
   Laut Handbuch steht `JtagLockFlag` in der Parametertabelle standardmäßig auf `0x00000000`
   (entsperrt) – ob die Option-Bytes des konkreten Moduls SWD freigeben, ist aber nicht garantiert.

> **Wichtig:** Beide Wege sind hier **nicht verifiziert**. Sie stehen bewusst nicht als Automatik in
> der Firmware. Die vorhandene `fp_r558_unlock.c` (Brownout-/Glitch-Sweeps über GP3/GP4) ist der
> Versuch, Weg C ohne Löten zu erreichen; 32 Durchläufe auf dem Prüfstand haben das Passwort nicht
> entfernt. Diese Engine bleibt als Experiment erhalten, ist aber **kein** empfohlener Pfad – und sie
> kann ein Modul durch Strompulse zusätzlich beschädigen. Wer den Sensor zuverlässig nutzen will,
> nimmt Weg A oder B.

---

## 5. Damit es nicht wieder passiert

1. **Kein Zufallspasswort mehr auf echter Hardware.** In `fp_pair()` ist der `random_fill_buffer()`-Zweig
   für `ESP_PLATFORM` entfernt; ohne deterministische Ableitung wird das Pairing mit
   `FP_ERR_NOT_SECURE` abgelehnt, statt ein Modul unwiederbringlich zu sperren.
2. **Credentials werden vor dem Sensor geschrieben.** `EF_FP_CONF` wird mit `FP_FLAG_STAGED` befüllt,
   *bevor* `SetPwd` gesendet wird; ein Abbruch dazwischen ist wieder aufnehmbar.
3. **Wiederherstellbarkeit ist Teil des Sicherheitsmodells.** Passwort und Adresse sind aus dem
   eFuse der MCU abgeleitet. Ein `erase_flash` kostet damit keine Hardware mehr – nur die
   FIDO-Credentials.
4. **Backup ziehen.** `0x06 backup` liefert 43 Byte (Passwort, Adresse, Kapazität, Slot-Bitmap). Das
   ist der einzige Weg, der auch bei einem Board-Tausch noch funktioniert. Aufbewahren wie ein
   Passwort, nicht im Klartext weitergeben.
5. **Vor jedem `erase_flash` prüfen**, ob ein Backup existiert.

---

## 6. Was geprüft ist – und was nicht

| Prüfung | Status |
|---|---|
| Wiederherstellungs-Leiter gegen simuliertes, gesperrtes Modul (`tests/fingerprint/recover_test.c`) | **bestanden** (32 Prüfungen, u. a.: nur `VfyPwd` verlässt den Host, Prioritätsreihenfolge, Adressvarianten, stille Leitung, harte Obergrenze) |
| Ausführung: `tests/fingerprint/run_r558_recover_test.sh` | braucht nur `gcc`, keinen Emulations-Build |
| Build der Gesamtfirmware / ESP-IDF | **nicht ausgeführt** (ESP-IDF und SDK-Submodul in der Arbeitsumgebung nicht vorhanden) |
| Verdrahtung `CTAP_VENDOR_FP 0x0B` in `cbor_vendor.c` | kompiliert nicht geprüft, Status-Map auf 15 Schlüssel erweitert |
| Echte Hardware | **offen** – der erste Lauf am gesperrten Modul entscheidet, welche Stufe greift |

**Nächster Schritt am Gerät:** Firmware flashen, Webapp mit der neuen Status-Map verbinden,
`{1: 11}` senden und die Telemetriezeile `0x0A` lesen. `src=derived` heißt: der Sensor ist zurück und
das Pairing kann fortgesetzt werden.

---

## 7. Prompt-Baustein für die Webapp

Für die Key-Management-Webapp (siehe `docs/fingerprint/WEBAPP_PROMPT.md` für den restlichen Aufbau):

> Ergänze im Fingerprint-Bereich eine Karte „Sensor entsperren“. Sie sendet den Vendor-Befehl
> `CTAP_VENDOR_FP` mit Unterbefehl `0x0B` (optional Schlüssel 2 = 4-Byte-Kandidaten als Byte-String,
> Länge ein Vielfaches von 4). Werte die Antwort-Map aus: `0x0E` = gefunden, `0x0F` = Quelle
> (`stored` / `derived` / `shared` / `user` / `factory` / `none`), `0x0A` = Telemetriezeile im
> Rohformat. Zeige bei Erfolg „Sensor wiederhergestellt – Pairing fortsetzen“ und biete direkt
> `0x02 pair` an. Bei `none` unterscheide anhand der Telemetrie: enthält sie `alive`, ist das Passwort
> unbekannt (Backup einspielen oder Modul tauschen); enthält sie `silent`, liegt ein Verkabelungs-
> oder Versorgungsproblem vor. Kein Passwort und keine Adresse im Klartext anzeigen.
