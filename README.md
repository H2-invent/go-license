# go-license

Offline-Lizenzprüfung für Go-Anwendungen mit Ed25519-signierten Lizenzschlüsseln. Nur Standardbibliothek, keine Netzwerkverbindung.

- Lizenzschlüssel als einzeiliger Text (z. B. per ENV `LICENSE_KEY`)
- öffentlicher Schlüssel **einkompiliert** und maskiert, keine Datei nötig
- Prüfung beim Start (`NewGuard`) und pro Ereignis (`Guard.Valid`, ~70 ns, 0 Allokationen)
- periodische Neuprüfung der Signatur, Warnung vor Ablauf
- Erkennung zurückgestellter Systemzeit (im Prozess und optional über Neustarts per Zustandsdatei)
- Produktbindung, Features, numerische Limits, Metadaten, Schlüsselrotation

## Format

```
H2L1.<base64url(payload-json)>.<base64url(ed25519-signatur über "H2L1.<payload>")>
```

Payload: `v`, `id`, `product`, `licensee`, `iat`, optional `nbf`, `exp` (Unix-Sekunden, `exp` exklusiv; fehlt `exp`, ist die Lizenz unbefristet), `features`, `limits`, `meta`.

## Ablauf beim Hersteller

```bash
go install github.com/h2-invent/go-license/cmd/licensectl@latest

# 1. Schlüsselpaar einmalig erzeugen – privaten Schlüssel sicher verwahren (Vault/Passwortmanager), NIE ins Repo
licensectl genkey -out license-private.pem -pub license-public.pem

# 2. öffentlichen Schlüssel als Go-Code in die Anwendung einbetten (Datei wird committet)
licensectl gocode -pub license-public.pem -pkg main -func licensePublicKey -out cmd/app/license_pubkey.go

# 3. Lizenz ausstellen (Ausgabe = Lizenzschlüssel für den Kunden)
licensectl issue -key license-private.pem -product my-app -licensee "Kunde GmbH" \
  -expires 2027-12-31 -feature forward -limit clients=50 -meta order=4711

# Lizenz anzeigen/prüfen
licensectl inspect -pub license-public.pem -product my-app "H2L1.…"
```

`-expires 2027-12-31` gilt einschließlich (bis Tagesende UTC). Alternativ `-days 365` oder `-perpetual`.

## Einbindung in die Anwendung

```go
import license "github.com/h2-invent/go-license"

v := license.NewVerifier([]ed25519.PublicKey{licensePublicKey()}, license.WithProduct("my-app"))
g, err := license.NewGuard(v, license.FromEnv("LICENSE_KEY"),
    license.WithLogger(log),
    license.WithStateFile("/data/license_state.json"), // optional
)
if err != nil {
    log.Error("lizenz ungültig", "error", err)
    os.Exit(1)
}
go g.Run(ctx) // Neuprüfung, Ablaufwarnung, Zustandsdatei

// pro Ereignis
if err := g.Valid(); err != nil { /* ablehnen */ }

g.License().HasFeature("forward")
g.License().Limit("clients")
g.Status() // für /stats
```

Fehler sind mit `errors.Is` prüfbar: `ErrMissing`, `ErrMalformed`, `ErrSignature`, `ErrWrongProduct`, `ErrNotYetValid`, `ErrExpired`, `ErrClockRollback`, `ErrNoKeys`.

### Optionen

| Verifier | Standard | |
|---|---|---|
| `WithProduct(p)` | – | Lizenz muss für `p` ausgestellt sein |
| `WithLeeway(d)` | 5 min | Uhrtoleranz für `iat`/`nbf` |

| Guard | Standard | |
|---|---|---|
| `WithStateFile(path)` | – | speichert zuletzt gesehene Zeit (Rückstell-Erkennung über Neustarts) |
| `WithRollbackTolerance(d)` | 1 h | erlaubter Rücksprung der Uhr, `0` = aus |
| `WithCheckInterval(d)` | 1 min | Intervall von `Run` |
| `WithExpiryWarning(d)` | 30 Tage | Warnung (1× täglich) vor Ablauf |

### Schlüsselrotation

`NewVerifier` nimmt mehrere öffentliche Schlüssel; eine Version mit altem und neuem Schlüssel ausliefern, neue Lizenzen mit dem neuen Schlüssel signieren.

## Schutzwirkung und Grenzen

- Ohne den privaten Schlüssel lässt sich keine gültige Lizenz erzeugen oder eine bestehende verändern (Laufzeit, Produkt, Features).
- Der öffentliche Schlüssel liegt nur maskiert (zwei XOR-Hälften) im Binary, nicht als Datei und nicht als String; `-ldflags -X` kann ihn nicht ersetzen.
- Eine rein clientseitige Prüfung lässt sich durch Patchen des Binarys grundsätzlich umgehen. Die Maßnahmen erhöhen den Aufwand, verhindern es aber nicht. Wirksame Ergänzungen sind rechtliche Mittel (Lizenzvertrag) und signierte Images.
- Die Zustandsdatei lässt sich löschen; sie fängt nur das einfache Zurückstellen der Uhr ab.
