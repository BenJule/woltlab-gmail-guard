# Gmail Guard - Anti-Spam Plugin für WoltLab Suite™

Schützt Ihr Forum vor Spam-Registrierungen durch intelligente Erkennung verdächtiger Gmail-Adressen.

## Features

✅ **Kombinierte Erkennungsmethoden:**
- Pattern-basierte Analyse (zufällige Zeichen, Zahlenfolgen, etc.)
- E-Mail Reputation API (EmailRep.io)
- Konfigurierbarer Verdachts-Schwellenwert

✅ **Flexible Aktionen:**
- Registrierung komplett blockieren
- Zusätzliche Verifikation verlangen
- Admin-Freigabe erforderlich

✅ **Umfangreiches Logging:**
- Error-Log für verdächtige Versuche
- Optionale Datenbank-Protokollierung
- E-Mail-Benachrichtigungen an Admins

## Installation

### 1. Plugin-Paket erstellen

```bash
cd woltlab-gmail-guard
tar -czf com.example.gmailguard.tar.gz *
```

### 2. In WoltLab Suite installieren

1. ACP → Pakete → Paket installieren
2. `com.example.gmailguard.tar.gz` hochladen
3. Installation abschließen

### 3. API-Schlüssel besorgen (optional, aber empfohlen)

1. Besuchen Sie https://emailrep.io
2. Registrieren Sie sich für einen kostenlosen API-Key
3. Kopieren Sie den API-Schlüssel

### 4. Konfiguration

1. ACP → Konfiguration → Optionen → Benutzer → Registrierung → Gmail Guard
2. **Gmail Guard aktivieren:** Ja
3. **Pattern-Erkennung aktivieren:** Ja
4. **API-Reputation-Check aktivieren:** Ja
5. **EmailRep.io API-Schlüssel:** [Ihr API-Key einfügen]
6. **Verdachts-Schwellenwert:** 50 (empfohlen)
7. **Aktion bei verdächtigen Adressen:** Zusätzliche Verifikation verlangen
8. **Verdächtige Versuche protokollieren:** Ja

### 5. Optionale Datenbank-Tabelle (nur für DB-Logging)

Falls Sie "Datenbank-Protokollierung" aktivieren möchten:

```sql
-- In phpMyAdmin oder MySQL-Client ausführen
-- Siehe install.sql
```

## Konfigurationsoptionen

### Erkennungsmethoden

**Pattern-Erkennung** (funktioniert offline):
- Erkennt zufällige Zeichenfolgen
- Zu viele aufeinanderfolgende Zahlen
- Übermäßige Nutzung von Punkten
- Spam-Schlüsselwörter (test, temp, fake, etc.)
- Sich wiederholende Muster

**API-Reputation-Check** (benötigt Internet):
- Reputation-Score von EmailRep.io
- Erkennung von Wegwerf-E-Mails
- Spam-Assoziation
- Verdächtige Aktivitäten

### Scoring-System

Jede Erkennungsmethode vergibt Punkte:
- 10-20 Punkte: Geringe Verdächtigkeit
- 25-40 Punkte: Mittlere Verdächtigkeit
- 50+ Punkte: Hohe Verdächtigkeit

Der **Verdachts-Schwellenwert** (Standard: 50) bestimmt, ab welcher Punktzahl eine Aktion ausgelöst wird.

### Aktionstypen

1. **Registrierung blockieren:**
   - E-Mail wird sofort abgelehnt
   - Benutzer sieht Fehlermeldung
   - Keine Registrierung möglich

2. **Zusätzliche Verifikation verlangen:**
   - Registrierung wird durchgeführt
   - Benutzer erhält Hinweis auf zusätzliche Prüfung
   - Ideal für manuelles Review

3. **Admin-Freigabe erforderlich:**
   - Account wird erstellt, aber inaktiv
   - Admin erhält E-Mail-Benachrichtigung
   - Account muss manuell freigeschaltet werden

## Beispiel-Szenarien

### Szenario 1: Maximale Sicherheit

```
Gmail Guard aktivieren: Ja
Pattern-Erkennung: Ja
API-Check: Ja
API-Schlüssel: [Ihr Key]
Schwellenwert: 40
Aktion: Registrierung blockieren
```

### Szenario 2: Moderate Sicherheit

```
Gmail Guard aktivieren: Ja
Pattern-Erkennung: Ja
API-Check: Ja
API-Schlüssel: [Ihr Key]
Schwellenwert: 50
Aktion: Zusätzliche Verifikation verlangen
```

### Szenario 3: Nur Pattern-Erkennung (kein API-Key)

```
Gmail Guard aktivieren: Ja
Pattern-Erkennung: Ja
API-Check: Nein
Schwellenwert: 60
Aktion: Zusätzliche Verifikation verlangen
```

## Logging und Monitoring

### Error-Log Beispiel

```
[GmailGuard] Suspicious Gmail registration attempt: test123456789@gmail.com | Score: 55 | Reasons: many_consecutive_numbers, spam_keyword | IP: 192.168.1.100 | Time: 2025-12-30 14:30:00
```

### Datenbank-Log Abfragen

```sql
-- Letzte 10 verdächtige Versuche
SELECT * FROM wcf1_gmail_guard_log
ORDER BY time DESC
LIMIT 10;

-- Verdächtige Versuche pro E-Mail
SELECT email, COUNT(*) as attempts
FROM wcf1_gmail_guard_log
GROUP BY email
HAVING attempts > 1;

-- Verdächtige Versuche pro IP
SELECT ipAddress, COUNT(*) as attempts
FROM wcf1_gmail_guard_log
GROUP BY ipAddress
ORDER BY attempts DESC;
```

## Troubleshooting

### Plugin funktioniert nicht

1. Cache leeren: ACP → Wartung → Cache leeren
2. Event-Listener prüfen: ACP → Entwickler → Event-Listener
3. Optionen prüfen: `gmail_guard_enabled` sollte auf 1 stehen

### API-Fehler

1. API-Schlüssel überprüfen
2. Error-Log aktivieren und prüfen
3. cURL-Funktion auf Server verfügbar?

```php
// Test in PHP:
var_dump(function_exists('curl_init'));
```

### False Positives

Wenn legitime Gmail-Adressen blockiert werden:
- Schwellenwert erhöhen (z.B. auf 60 oder 70)
- Pattern-Erkennung deaktivieren
- Nur API-Check nutzen

## Performance

- **Pattern-Erkennung:** < 1ms (sehr schnell)
- **API-Check:** 50-500ms (abhängig von Netzwerk)
- **Caching:** Validierungsergebnisse werden während Registrierung gecacht

## Sicherheit

- Keine Speicherung von Passwörtern
- IP-Adressen werden nur geloggt (DSGVO beachten!)
- API-Kommunikation über HTTPS
- Keine Weitergabe von Benutzerdaten an Dritte (außer E-Mail-Hash an EmailRep.io)

## Deinstallation

1. ACP → Pakete → Gmail Guard
2. Deinstallieren
3. Optional: Datenbank-Tabelle manuell löschen:

```sql
DROP TABLE IF EXISTS wcf1_gmail_guard_log;
```

## Support & Entwicklung

- Version: 1.0.0
- Kompatibel mit: WoltLab Suite™ 6.0+
- Lizenz: Apache License 2.0

## Changelog

### Version 1.0.0 (2025-12-30)
- Initiales Release
- Pattern-basierte Erkennung
- EmailRep.io API-Integration
- Konfigurierbares Scoring-System
- Mehrsprachig (DE/EN)

## Credits

Entwickelt mit Claude Code
