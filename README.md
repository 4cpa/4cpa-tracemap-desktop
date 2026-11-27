# 4CPA TraceMap – Desktop-App

Verfolgt **Webadressen** (Traceroute) und **E-Mails** (Header) und zeigt die Route auf einer Weltkarte – mit Standorten, Netzbetreibern, Abuse-Kontakten, Reputation, PDF-Bericht und Export (JSON, CSV, GeoJSON). Sprachen: Deutsch, Englisch, Französisch. Die App läuft **lokal auf deinem Rechner**; Verlauf und Berichte bleiben dort.

> Online-Version (nur E-Mail-Analyse und IP-/Domain-Abfrage, ohne Traceroute von deinem Rechner): https://4cpa-tracemap.vercel.app

## Download

Fertige Programme für **Windows, Linux und macOS** gibt es auf der Seite **Releases** dieses Repositorys:

➡️ **https://github.com/4cpa/4cpa-tracemap-desktop/releases/latest**

| System | Datei | Hinweis |
|---|---|---|
| Windows 10/11 (64 Bit) | `4CPA-TraceMap-windows-x64.zip` | entpacken, `4CPA TraceMap.exe` starten |
| Linux (64 Bit) | `4CPA-TraceMap-linux-x64.tar.gz` | Programm `traceroute` muss installiert sein |
| macOS (Apple Silicon) | `4CPA-TraceMap-macos-arm64.zip` | entpacken, `4CPA TraceMap.app` öffnen |

Mit `SHA256SUMS.txt` aus dem Release kannst du die Dateien prüfen:

```bash
shasum -a 256 4CPA-TraceMap-*.zip      # macOS/Linux; unter Windows: Get-FileHash <Datei>
```

## Installation

Die Apps sind **nicht signiert**. Beim ersten Start warnt das Betriebssystem deshalb.

- **Windows:** SmartScreen zeigt «Der Computer wurde durch Windows geschützt». Klick auf **Weitere Informationen → Trotzdem ausführen**. Falls die Windows-Firewall nachfragt: Zugriff auf private Netzwerke genügt (die App hört nur auf `127.0.0.1`).
- **macOS:** Rechtsklick auf die App → **Öffnen** → **Öffnen**. Falls macOS die App als «beschädigt» meldet: `xattr -dr com.apple.quarantine "4CPA TraceMap.app"` im Terminal ausführen.
- **Linux:**

  ```bash
  tar xzf 4CPA-TraceMap-linux-x64.tar.gz
  "./4CPA TraceMap/4CPA TraceMap"
  ```

  Fehlt `traceroute`: `sudo apt install traceroute` (Debian/Ubuntu) oder `sudo dnf install traceroute` (Fedora).

Beim Start öffnet sich dein Browser mit der Oberfläche unter http://127.0.0.1:8765. Zum Beenden: ⚙ **Einstellungen → App beenden**. Startest du die App ein zweites Mal, öffnet sie nur den Browser.

## Daten und Datenschutz

- **Speicherort** (Verlauf, Einstellungen, Protokoll `server.log`):
  Windows `%APPDATA%\4CPA TraceMap`, macOS `~/Library/Application Support/4CPA TraceMap`, Linux `~/.local/share/4CPA TraceMap`.
- **Netzabfragen:** Standardmäßig gehen die IP-Adressen der Route an **ip-api.com** (Standort), PeeringDB (Rechenzentren, per AS-Nummer), die Regional Internet Registries (RDAP, Abuse-Kontakt) und – bei Domains – DNS und TLS zum Ziel; optional an DNS-Sperrlisten. Der Dienst ip-api.com ist in der kostenlosen Form nur nichtkommerziell und nur per HTTP nutzbar.
- **Datenschutzmodus (⚙):** Mit der kostenlosen MaxMind-**GeoLite2**-Datenbank (`GeoLite2-City.mmdb`, optional `GeoLite2-ASN.mmdb`; Registrierung bei MaxMind nötig) in den Speicherordner gelegt, werden Standorte lokal bestimmt und es werden keine IP-Adressen an Datendienste gesendet. Die Datenbank darf nicht weitergegeben werden und sollte etwa monatlich erneuert werden.
- Die eigentliche Wegverfolgung (`tracert`/`traceroute`) sendet natürlich Pakete ins Netz – das ist ihr Zweck.

## Funktionen

Traceroute mit Mehrfachmessung (Verlust, Schwankung) und Plausibilitätsprüfung der Standorte · Großkreis-Karte mit Rechenzentren (PeeringDB) · E-Mail-Prüfung (SPF/DKIM, Reply-To/Return-Path, Links, Nachahmer-Domains) · Reputation (Tor, optional Sperrlisten/AbuseIPDB) · Domain-Infos (RDAP, DNS, TLS, Weiterleitungen, CDN) · Entwurf einer Missbrauchsmeldung · SHA-256-Prüfwert · Notizen, Stichworte, Suche, Vergleich · Stapelverarbeitung von `.eml`-Dateien · PDF-Bericht.

## Aus dem Quellcode starten / selbst bauen

```bash
python -m venv .venv
.venv/bin/pip install -r requirements-desktop.txt        # Windows: .venv\Scripts\pip
.venv/bin/python launcher.py                              # startet Server und öffnet den Browser
.venv/bin/python packaging/make_icons.py
.venv/bin/pyinstaller --noconfirm packaging/4cpa-tracemap.spec
.venv/bin/python packaging/smoke_test.py                  # prüft die gebaute App
```

Die Release-Dateien entstehen automatisch per GitHub Actions (`.github/workflows/build.yml`) beim Anlegen eines Tags `v*`; jede Plattform wird auf ihrem eigenen System gebaut und vor dem Veröffentlichen getestet.

## Lizenz und Hinweise

Der Code dieses Repositorys steht unter der **MIT-Lizenz** (siehe `LICENSE`). Eingebundene Drittkomponenten behalten ihre eigenen Lizenzen und Bedingungen, siehe `NOTICE.md` (u. a. MaxMind GeoLite2, Natural Earth, Leaflet, OpenStreetMap). Name und Logo «4CPA» sind von der MIT-Lizenz nicht umfasst.

Betreiber: Transivroom Division, Transivroom, Kasparstrasse 17, 3027 Bern, Schweiz – admin@4cpa.ch. © Transivroom Division 2026.
