# Gmail Guard - Schnellstart-Anleitung

## 📦 Installation in 5 Schritten

### Schritt 1: Plugin hochladen
1. Öffnen Sie Ihr WoltLab Suite ACP (Admin Control Panel)
2. Navigieren Sie zu: **Pakete → Paket installieren**
3. Laden Sie die Datei `com.example.gmailguard.tar.gz` hoch
4. Folgen Sie dem Installations-Assistenten

### Schritt 2: API-Schlüssel besorgen (empfohlen)
1. Besuchen Sie: https://emailrep.io
2. Klicken Sie auf "Get API Key"
3. Registrieren Sie sich (kostenlos)
4. Kopieren Sie Ihren API-Key

### Schritt 3: Plugin konfigurieren
1. ACP → **Konfiguration → Optionen → Benutzer → Registrierung → Gmail Guard**
2. Setzen Sie folgende Optionen:

```
✓ Gmail Guard aktivieren: JA
✓ Pattern-Erkennung aktivieren: JA
✓ API-Reputation-Check aktivieren: JA
✓ EmailRep.io API-Schlüssel: [Ihr Key einfügen]
✓ Verdachts-Schwellenwert: 50
✓ Aktion bei verdächtigen Adressen: Zusätzliche Verifikation verlangen
✓ Verdächtige Versuche protokollieren: JA
```

### Schritt 4: Testen
1. Versuchen Sie, sich mit einer Test-Gmail-Adresse zu registrieren
2. Nutzen Sie eine verdächtige Adresse wie: `test123456789@gmail.com`
3. Das Plugin sollte die Registrierung erkennen und entsprechend handeln

### Schritt 5: Monitoring einrichten (optional)
1. **E-Mail-Benachrichtigungen:**
   - Tragen Sie Ihre Admin-E-Mail ein bei: "Benachrichtigungs-E-Mail"

2. **Datenbank-Logging:**
   - Führen Sie `install.sql` in Ihrer Datenbank aus
   - Aktivieren Sie "Datenbank-Protokollierung"

## 🎯 Empfohlene Einstellungen

### Für maximale Sicherheit:
```
Schwellenwert: 40
Aktion: Registrierung blockieren
```

### Für ausgewogene Sicherheit:
```
Schwellenwert: 50
Aktion: Zusätzliche Verifikation verlangen
```

### Für minimale False Positives:
```
Schwellenwert: 70
Aktion: Admin-Freigabe erforderlich
```

## 🔍 So erkennt das Plugin Spam-Adressen

### Pattern-Erkennung (offline):
- ✗ `test12345678@gmail.com` → Zu viele Zahlen
- ✗ `kjhf8sd7f@gmail.com` → Zufällige Zeichen
- ✗ `a.b.c.d.e@gmail.com` → Zu viele Punkte
- ✗ `abc@gmail.com` → Zu kurz
- ✗ `tempmail123@gmail.com` → Spam-Keyword

### API-Reputation-Check (online):
- Prüft E-Mail-Reputation bei EmailRep.io
- Erkennt Wegwerf-E-Mail-Dienste
- Identifiziert bekannte Spam-Quellen
- Analysiert verdächtige Aktivitäten

## ⚠️ Wichtige Hinweise

1. **API-Key erforderlich**: Ohne API-Key funktioniert nur die Pattern-Erkennung
2. **Performance**: API-Check dauert ca. 50-500ms pro Anfrage
3. **False Positives**: Passen Sie den Schwellenwert an, falls legitime Nutzer blockiert werden
4. **DSGVO**: IP-Adressen werden geloggt - Datenschutzerklärung anpassen!

## 🐛 Troubleshooting

**Problem:** Plugin funktioniert nicht
- **Lösung:** Cache leeren (ACP → Wartung → Cache leeren)

**Problem:** API-Fehler
- **Lösung:** API-Key überprüfen, cURL-Funktion verfügbar?

**Problem:** Zu viele False Positives
- **Lösung:** Schwellenwert erhöhen (z.B. auf 60 oder 70)

## 📊 Logging auswerten

Error-Log-Einträge finden Sie hier:
```
/path/to/woltlab/log/YYYY-MM-DD.txt
```

Beispiel-Eintrag:
```
[GmailGuard] Suspicious Gmail registration: test123@gmail.com | Score: 55 | Reasons: many_consecutive_numbers, spam_keyword
```

## 📁 Plugin-Struktur

```
com.example.gmailguard/
├── package.xml                          # Plugin-Metadaten
├── eventListener.xml                    # Event-Listener-Registrierung
├── option.xml                           # ACP-Optionen
├── install.sql                          # Optionale DB-Tabelle
├── files/
│   └── lib/
│       ├── data/user/
│       │   └── GmailValidator.class.php    # Validierungs-Logik
│       └── system/event/listener/
│           └── GmailGuardRegistrationListener.class.php
└── language/
    ├── de.xml                           # Deutsche Übersetzung
    └── en.xml                           # Englische Übersetzung
```

## 💡 Tipps & Tricks

1. **Kombination ist am besten:** Nutzen Sie Pattern + API für maximale Erkennungsrate
2. **Schwellenwert anpassen:** Beobachten Sie das Log und passen Sie an
3. **Whitelist-Funktion:** Erstellen Sie eine Whitelist für bekannte legitime Nutzer
4. **Testen Sie regelmäßig:** Prüfen Sie, ob das Plugin noch korrekt funktioniert

## 📞 Support

Bei Problemen oder Fragen:
1. Prüfen Sie das Error-Log
2. Lesen Sie die vollständige README.md
3. Überprüfen Sie die Konfiguration

---

**Version:** 1.0.0
**Kompatibel mit:** WoltLab Suite™ 6.0+
**Lizenz:** Apache License 2.0
