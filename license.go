// Package license prüft offline signierte Lizenzschlüssel (Ed25519).
//
// Ein Lizenzschlüssel ist ein einzeiliger Text:
//
//	H2L1.<base64url(payload-json)>.<base64url(signatur)>
//
// Die Signatur deckt "H2L1." + payload ab. Der öffentliche Schlüssel wird
// in die Anwendung einkompiliert (siehe UnmaskKey und licensectl gocode);
// der private Schlüssel bleibt beim Hersteller (Paket issuer, licensectl).
//
// Typischer Einsatz:
//
//	v := license.NewVerifier([]ed25519.PublicKey{licensePublicKey()}, license.WithProduct("my-app"))
//	g, err := license.NewGuard(v, license.FromEnv("LICENSE_KEY"))
//	if err != nil { ... Start abbrechen ... }
//	go g.Run(ctx)
//	...
//	if err := g.Valid(); err != nil { ... Ereignis ablehnen ... } // pro Ereignis, sehr günstig
package license

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"
)

// Prefix kennzeichnet Format und Version eines Lizenzschlüssels.
const Prefix = "H2L1"

// Fehler, die bei der Prüfung auftreten können (mit errors.Is prüfbar).
var (
	ErrMissing       = errors.New("lizenz: kein Lizenzschlüssel angegeben")
	ErrMalformed     = errors.New("lizenz: Lizenzschlüssel hat ein ungültiges Format")
	ErrSignature     = errors.New("lizenz: Signatur ist ungültig")
	ErrNoKeys        = errors.New("lizenz: kein öffentlicher Schlüssel konfiguriert")
	ErrWrongProduct  = errors.New("lizenz: Lizenz gilt nicht für dieses Produkt")
	ErrNotYetValid   = errors.New("lizenz: Lizenz ist noch nicht gültig")
	ErrExpired       = errors.New("lizenz: Lizenz ist abgelaufen")
	ErrClockRollback = errors.New("lizenz: Systemzeit wurde zurückgestellt")
)

// License ist der signierte Inhalt eines Lizenzschlüssels.
type License struct {
	ID        string    // eindeutige Lizenz-ID
	Product   string    // Produktkennung, gegen WithProduct geprüft
	Licensee  string    // Lizenznehmer
	IssuedAt  time.Time // Ausstellungszeitpunkt
	NotBefore time.Time // gültig ab (Null = sofort)
	ExpiresAt time.Time // gültig bis, exklusiv (Null = unbefristet)
	Features  []string
	Limits    map[string]int64
	Meta      map[string]string
}

// Perpetual meldet, ob die Lizenz unbefristet ist.
func (l *License) Perpetual() bool { return l.ExpiresAt.IsZero() }

// HasFeature meldet, ob die Lizenz ein Feature freischaltet.
func (l *License) HasFeature(name string) bool { return slices.Contains(l.Features, name) }

// Limit liefert ein numerisches Limit; ok ist false, wenn es fehlt.
func (l *License) Limit(name string) (v int64, ok bool) {
	v, ok = l.Limits[name]
	return v, ok
}

// payload ist das Wire-Format (kompakt, Zeiten als Unix-Sekunden).
type payload struct {
	V         int               `json:"v"`
	ID        string            `json:"id"`
	Product   string            `json:"product"`
	Licensee  string            `json:"licensee"`
	IssuedAt  int64             `json:"iat"`
	NotBefore int64             `json:"nbf,omitempty"`
	ExpiresAt int64             `json:"exp,omitempty"`
	Features  []string          `json:"features,omitempty"`
	Limits    map[string]int64  `json:"limits,omitempty"`
	Meta      map[string]string `json:"meta,omitempty"`
}

func unix(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func fromUnix(s int64) time.Time {
	if s == 0 {
		return time.Time{}
	}
	return time.Unix(s, 0).UTC()
}

// MarshalPayload erzeugt den zu signierenden JSON-Inhalt (für das Paket issuer).
func MarshalPayload(l License) ([]byte, error) {
	if strings.TrimSpace(l.ID) == "" || strings.TrimSpace(l.Product) == "" || strings.TrimSpace(l.Licensee) == "" {
		return nil, errors.New("lizenz: ID, Product und Licensee sind Pflichtfelder")
	}
	if l.IssuedAt.IsZero() {
		return nil, errors.New("lizenz: IssuedAt fehlt")
	}
	if !l.ExpiresAt.IsZero() && !l.ExpiresAt.After(l.IssuedAt) {
		return nil, errors.New("lizenz: ExpiresAt muss nach IssuedAt liegen")
	}
	if !l.ExpiresAt.IsZero() && !l.NotBefore.IsZero() && !l.ExpiresAt.After(l.NotBefore) {
		return nil, errors.New("lizenz: ExpiresAt muss nach NotBefore liegen")
	}
	return json.Marshal(payload{
		V:         1,
		ID:        l.ID,
		Product:   l.Product,
		Licensee:  l.Licensee,
		IssuedAt:  unix(l.IssuedAt),
		NotBefore: unix(l.NotBefore),
		ExpiresAt: unix(l.ExpiresAt),
		Features:  l.Features,
		Limits:    l.Limits,
		Meta:      l.Meta,
	})
}

// SigningInput liefert die Bytes, die signiert bzw. geprüft werden.
func SigningInput(encodedPayload string) []byte {
	return []byte(Prefix + "." + encodedPayload)
}

var b64 = base64.RawURLEncoding

// split zerlegt einen Schlüssel in (payload-base64, payload, signatur).
func split(token string) (string, []byte, []byte, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return "", nil, nil, ErrMissing
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != Prefix {
		return "", nil, nil, ErrMalformed
	}
	p, err := b64.DecodeString(parts[1])
	if err != nil {
		return "", nil, nil, fmt.Errorf("%w: payload: %v", ErrMalformed, err)
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil || len(sig) != ed25519.SignatureSize {
		return "", nil, nil, fmt.Errorf("%w: signatur", ErrMalformed)
	}
	return parts[1], p, sig, nil
}

func decodePayload(p []byte) (*License, error) {
	var w payload
	dec := json.NewDecoder(bytes.NewReader(p))
	if err := dec.Decode(&w); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if w.V != 1 {
		return nil, fmt.Errorf("%w: unbekannte Version %d", ErrMalformed, w.V)
	}
	if w.ID == "" || w.Product == "" || w.IssuedAt == 0 {
		return nil, fmt.Errorf("%w: Pflichtfelder fehlen", ErrMalformed)
	}
	return &License{
		ID:        w.ID,
		Product:   w.Product,
		Licensee:  w.Licensee,
		IssuedAt:  fromUnix(w.IssuedAt),
		NotBefore: fromUnix(w.NotBefore),
		ExpiresAt: fromUnix(w.ExpiresAt),
		Features:  w.Features,
		Limits:    w.Limits,
		Meta:      w.Meta,
	}, nil
}

// Decode liest einen Lizenzschlüssel OHNE Signaturprüfung (nur zur Anzeige).
func Decode(token string) (*License, error) {
	_, p, _, err := split(token)
	if err != nil {
		return nil, err
	}
	return decodePayload(p)
}

// FromEnv liest einen Lizenzschlüssel aus einer Umgebungsvariablen.
// Leerraum und Zeilenumbrüche (z. B. aus Secrets) werden entfernt.
func FromEnv(name string) string {
	return strings.Join(strings.Fields(os.Getenv(name)), "")
}

// Fingerprint liefert eine kurze Kennung eines öffentlichen Schlüssels
// (die ersten 8 Byte von SHA-256, hex).
func Fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// ---------------------------------------------------------------------------
// Verifier
// ---------------------------------------------------------------------------

// Verifier prüft Signatur und Gültigkeit von Lizenzschlüsseln.
type Verifier struct {
	keys    []ed25519.PublicKey
	product string
	leeway  time.Duration
	now     func() time.Time
}

// Option konfiguriert einen Verifier.
type Option func(*Verifier)

// WithProduct verlangt, dass die Lizenz für dieses Produkt ausgestellt ist.
func WithProduct(p string) Option { return func(v *Verifier) { v.product = p } }

// WithLeeway erlaubt eine Abweichung der Uhr bei NotBefore und IssuedAt
// (Standard: 5 Minuten). ExpiresAt wird ohne Toleranz geprüft.
func WithLeeway(d time.Duration) Option { return func(v *Verifier) { v.leeway = d } }

// WithClock ersetzt time.Now (für Tests).
func WithClock(now func() time.Time) Option { return func(v *Verifier) { v.now = now } }

// NewVerifier erzeugt einen Verifier. Mehrere Schlüssel erlauben eine
// Schlüsselrotation (jede gültige Signatur eines der Schlüssel wird akzeptiert).
func NewVerifier(keys []ed25519.PublicKey, opts ...Option) *Verifier {
	v := &Verifier{leeway: 5 * time.Minute, now: time.Now}
	for _, k := range keys {
		if len(k) == ed25519.PublicKeySize {
			v.keys = append(v.keys, slices.Clone(k))
		}
	}
	for _, o := range opts {
		o(v)
	}
	return v
}

// Parse prüft die Signatur und das Produkt, aber nicht die Laufzeit.
func (v *Verifier) Parse(token string) (*License, error) {
	if len(v.keys) == 0 {
		return nil, ErrNoKeys
	}
	enc, p, sig, err := split(token)
	if err != nil {
		return nil, err
	}
	msg := SigningInput(enc)
	ok := false
	for _, k := range v.keys {
		if ed25519.Verify(k, msg, sig) {
			ok = true
			break
		}
	}
	if !ok {
		return nil, ErrSignature
	}
	l, err := decodePayload(p)
	if err != nil {
		return nil, err
	}
	if v.product != "" && l.Product != v.product {
		return l, fmt.Errorf("%w (%q statt %q)", ErrWrongProduct, l.Product, v.product)
	}
	return l, nil
}

// CheckTime prüft die Laufzeit einer (bereits verifizierten) Lizenz.
func (v *Verifier) CheckTime(l *License, now time.Time) error {
	if now.Add(v.leeway).Before(l.IssuedAt) {
		return fmt.Errorf("%w (Systemzeit %s liegt vor Ausstellung %s)", ErrClockRollback,
			now.UTC().Format(time.RFC3339), l.IssuedAt.Format(time.RFC3339))
	}
	if !l.NotBefore.IsZero() && now.Add(v.leeway).Before(l.NotBefore) {
		return fmt.Errorf("%w (ab %s)", ErrNotYetValid, l.NotBefore.Format(time.RFC3339))
	}
	if !l.ExpiresAt.IsZero() && !now.Before(l.ExpiresAt) {
		return fmt.Errorf("%w (seit %s)", ErrExpired, l.ExpiresAt.Format(time.RFC3339))
	}
	return nil
}

// Verify prüft Signatur, Produkt und Laufzeit.
func (v *Verifier) Verify(token string) (*License, error) {
	l, err := v.Parse(token)
	if err != nil {
		return l, err
	}
	return l, v.CheckTime(l, v.now())
}
