# Changelog - Gmail Guard

## Version 2.0.0 (2025-12-30) - MAJOR UPDATE

### 🎉 Neue Features

#### Erweiterte Erkennung
- ✅ **Whitelist/Blacklist-System** - Manuelle Listen für erlaubte/blockierte E-Mail-Adressen und Domains
- ✅ **StopForumSpam.com Integration** - Abgleich gegen weltweite Spam-Datenbank
- ✅ **Erweiterte Wegwerf-E-Mail-Erkennung** - 60+ bekannte Disposable-Email-Dienste + API-Check
- ✅ **Custom Disposable-Domains** - Eigene Liste verdächtiger Domains hinzufügen

#### Anti-Bot-Maßnahmen
- ✅ **Honeypot-Felder** - Unsichtbare Felder gegen automatische Bots
- ✅ **Zeit-basierte Prüfungen** - Erkennt zu schnelle/langsame Formular-Ausf\u00fcllungen
- ✅ **Browser-Fingerprinting** - Identifiziert Headless-Browser und verdächtige User-Agents
- ✅ **Zeitliche Einschränkungen** - Optional: Registrierung nur zu bestimmten Uhrzeiten

#### Rate Limiting & Schutz
- ✅ **IP-Raten-Limitierung** - Max. X Versuche pro IP in Y Minuten (konfigurierbar)
- ✅ **Automatische IP-Sperren** - Temporäre Bans bei wiederholten verdächtigen Versuchen
- ✅ **Intelligente Schwellenwerte** - Anpassbare Auto-Ban-Parameter

#### Monitoring & Verwaltung
- ✅ **Erweiterte Datenbank-Logs** - Detaillierte Speicherung mit User-Agent und Details
- ✅ **4 Datenbank-Tabellen** - Logs, Rate-Limits, IP-Bans, Statistiken
- ✅ **Verbesserte Admin-Benachrichtigungen** - Detaillierte E-Mails mit Score und Gründen

### 📊 Statistiken

- **+5 neue PHP-Klassen** (WhitelistBlacklistManager, RateLimiter, StopForumSpamChecker, AntiBotValidator, DisposableEmailChecker)
- **+30 neue ACP-Optionen** (Total: 38 Optionen in 5 Kategorien)
- **+4 Datenbank-Tabellen**
- **10-stufiger Validierungs-Prozess** (von Whitelist bis Time Restriction)
- **Scoring-System erweitert** - Bis zu 200+ Punkte möglich

### 🔄 Änderungen

- Haupt-Validator komplett überarbeitet (`validateEmail()` Methode)
- Event Listener erweitert (3 Events: readFormParameters, validate, saved)
- Pattern-Erkennung verbessert (2 neue Spam-Keywords)
- API User-Agent aktualisiert (v2.0)

### 📚 Neue Optionen (Auswahl)

**Erkennung:**
- `gmail_guard_sfs_enabled` - StopForumSpam aktivieren
- `gmail_guard_sfs_api_key` - StopForumSpam API-Key (optional, für Spam-Reporting)
- `gmail_guard_disposable_check_enabled` - Wegwerf-E-Mail-Erkennung
- `gmail_guard_custom_disposable_domains` - Eigene Disposable-Domains

**Anti-Bot:**
- `gmail_guard_honeypot_enabled` - Honeypot-Felder
- `gmail_guard_timing_check_enabled` - Zeitbasierte Prüfungen
- `gmail_guard_min_form_time` - Mindest-Zeit (Standard: 3 Sekunden)
- `gmail_guard_browser_check_enabled` - Browser-Fingerprinting
- `gmail_guard_time_restriction_enabled` - Zeitliche Einschränkungen
- `gmail_guard_allowed_start_hour` / `_end_hour` - Erlaubte Uhrzeiten

**Rate Limiting:**
- `gmail_guard_rate_limit_enabled` - Rate Limiting aktivieren
- `gmail_guard_rate_limit_max` - Max. Versuche (Standard: 3)
- `gmail_guard_rate_limit_window` - Zeitfenster in Minuten (Standard: 60)
- `gmail_guard_auto_ban_enabled` - Automatische Sperren
- `gmail_guard_auto_ban_threshold` - Verdächtige Versuche bis Ban (Standard: 5)
- `gmail_guard_ban_duration` - Sperr-Dauer in Stunden (Standard: 24)

**Whitelist/Blacklist:**
- `gmail_guard_whitelist` - Immer erlaubte E-Mails/Domains
- `gmail_guard_blacklist` - Immer blockierte E-Mails/Domains

### 🐛 Bugfixes

- Legacy-Methode `validateGmailAddress()` für Abwärtskompatibilität
- Verbesserte Error-Messages mit spezifischen Gründen
- Session-Handling für Honeypot und Timing-Tokens

### ⚠️ Breaking Changes

- Keine! v1.x-Konfigurationen funktionieren weiter
- Automatisches Upgrade von v1.x auf v2.0.0 möglich
- Neue Features sind optional (alle Default-Werte gesetzt)

### 📦 Upgrade von v1.x

1. Backup der Datenbank erstellen
2. Plugin-Paket v2.0.0 im ACP hochladen
3. Upgrade durchführen (neue Tabellen werden automatisch erstellt)
4. Optionale neue Features im ACP aktivieren

---

## Version 1.0.0 (2025-12-30) - Initial Release

- Pattern-basierte Gmail-Erkennung
- EmailRep.io API-Integration
- Konfigurierbares Scoring-System
- 3 Aktionstypen (Block/Verify/Moderate)
- Mehrsprachig (DE/EN)
- Basic Logging

