package license_test

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	license "github.com/h2-invent/go-license"
	"github.com/h2-invent/go-license/issuer"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

var t0 = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

func keys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := issuer.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func sign(t *testing.T, priv ed25519.PrivateKey, mod func(*license.License)) string {
	t.Helper()
	l := license.License{
		ID: "L1", Product: "app", Licensee: "Kunde GmbH",
		IssuedAt: t0, ExpiresAt: t0.AddDate(1, 0, 0),
		Features: []string{"forward"}, Limits: map[string]int64{"clients": 5},
	}
	if mod != nil {
		mod(&l)
	}
	tok, err := issuer.Sign(priv, l)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

type clock struct{ ns atomic.Int64 }

func newClock(t time.Time) *clock    { c := &clock{}; c.set(t); return c }
func (c *clock) set(t time.Time)     { c.ns.Store(t.UnixNano()) }
func (c *clock) now() time.Time      { return time.Unix(0, c.ns.Load()) }
func (c *clock) add(d time.Duration) { c.ns.Add(int64(d)) }

func TestVerifyRoundTrip(t *testing.T) {
	pub, priv := keys(t)
	tok := sign(t, priv, nil)
	v := license.NewVerifier([]ed25519.PublicKey{pub}, license.WithProduct("app"),
		license.WithClock(func() time.Time { return t0.Add(time.Hour) }))
	l, err := v.Verify(tok)
	if err != nil {
		t.Fatal(err)
	}
	if l.ID != "L1" || l.Licensee != "Kunde GmbH" || !l.HasFeature("forward") || l.HasFeature("x") {
		t.Fatalf("unerwarteter inhalt: %+v", l)
	}
	if n, ok := l.Limit("clients"); !ok || n != 5 {
		t.Fatalf("limit: %d %v", n, ok)
	}
	if !l.ExpiresAt.Equal(t0.AddDate(1, 0, 0)) {
		t.Fatalf("exp: %v", l.ExpiresAt)
	}
}

func TestVerifyErrors(t *testing.T) {
	pub, priv := keys(t)
	otherPub, otherPriv := keys(t)
	good := sign(t, priv, nil)
	at := func(ts time.Time) license.Option { return license.WithClock(func() time.Time { return ts }) }

	// Payload austauschen, Signatur behalten
	parts := strings.Split(sign(t, priv, func(l *license.License) { l.Licensee = "Anderer" }), ".")
	goodParts := strings.Split(good, ".")
	tampered := goodParts[0] + "." + parts[1] + "." + goodParts[2]

	cases := []struct {
		name string
		tok  string
		keys []ed25519.PublicKey
		opts []license.Option
		want error
	}{
		{"leer", "  ", []ed25519.PublicKey{pub}, nil, license.ErrMissing},
		{"format", "abc.def", []ed25519.PublicKey{pub}, nil, license.ErrMalformed},
		{"prefix", "X" + good, []ed25519.PublicKey{pub}, nil, license.ErrMalformed},
		{"manipuliert", tampered, []ed25519.PublicKey{pub}, []license.Option{at(t0)}, license.ErrSignature},
		{"fremder schlüssel", sign(t, otherPriv, nil), []ed25519.PublicKey{pub}, []license.Option{at(t0)}, license.ErrSignature},
		{"keine schlüssel", good, nil, nil, license.ErrNoKeys},
		{"produkt", good, []ed25519.PublicKey{pub}, []license.Option{license.WithProduct("other"), at(t0)}, license.ErrWrongProduct},
		{"abgelaufen", good, []ed25519.PublicKey{pub}, []license.Option{at(t0.AddDate(1, 0, 0))}, license.ErrExpired},
		{"vor ausstellung", good, []ed25519.PublicKey{pub}, []license.Option{at(t0.Add(-time.Hour))}, license.ErrClockRollback},
		{"noch nicht gültig", sign(t, priv, func(l *license.License) { l.NotBefore = t0.Add(48 * time.Hour) }),
			[]ed25519.PublicKey{pub}, []license.Option{at(t0.Add(time.Hour))}, license.ErrNotYetValid},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := license.NewVerifier(c.keys, c.opts...).Verify(c.tok)
			if !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}

	// Rotation: zweiter Schlüssel akzeptiert
	if _, err := license.NewVerifier([]ed25519.PublicKey{otherPub, pub}, at(t0)).Verify(good); err != nil {
		t.Fatalf("rotation: %v", err)
	}
	// Leeway: knapp vor Ausstellung ok
	if _, err := license.NewVerifier([]ed25519.PublicKey{pub}, at(t0.Add(-time.Minute))).Verify(good); err != nil {
		t.Fatalf("leeway: %v", err)
	}
	// Unbefristet
	perp := sign(t, priv, func(l *license.License) { l.ExpiresAt = time.Time{} })
	if l, err := license.NewVerifier([]ed25519.PublicKey{pub}, at(t0.AddDate(50, 0, 0))).Verify(perp); err != nil || !l.Perpetual() {
		t.Fatalf("unbefristet: %v", err)
	}
}

func TestSignRejectsInvalid(t *testing.T) {
	_, priv := keys(t)
	if _, err := issuer.Sign(priv, license.License{Product: "app", Licensee: "x"}); err == nil {
		t.Fatal("fehlende ID muss abgelehnt werden")
	}
	if _, err := issuer.Sign(priv, license.License{ID: "1", Product: "app", Licensee: "x", IssuedAt: t0, ExpiresAt: t0}); err == nil {
		t.Fatal("exp <= iat muss abgelehnt werden")
	}
}

func TestGuard(t *testing.T) {
	pub, priv := keys(t)
	tok := sign(t, priv, nil)
	c := newClock(t0.Add(time.Hour))
	v := license.NewVerifier([]ed25519.PublicKey{pub}, license.WithProduct("app"))
	g, err := license.NewGuard(v, tok, license.WithGuardClock(c.now), license.WithLogger(quiet))
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Valid(); err != nil {
		t.Fatal(err)
	}
	if s := g.Status(); !s.Valid || s.DaysLeft == nil || *s.DaysLeft < 360 {
		t.Fatalf("status: %+v", s)
	}

	// Uhr zurückstellen (über Toleranz) -> abgelehnt, danach wieder gültig
	c.add(10 * 24 * time.Hour)
	_ = g.Valid()
	c.add(-3 * time.Hour)
	if err := g.Valid(); !errors.Is(err, license.ErrClockRollback) {
		t.Fatalf("rollback: %v", err)
	}
	c.add(3 * time.Hour)
	if err := g.Valid(); err != nil {
		t.Fatal(err)
	}

	// Ablauf zur Laufzeit
	c.set(t0.AddDate(1, 0, 0))
	if err := g.Valid(); !errors.Is(err, license.ErrExpired) {
		t.Fatalf("expired: %v", err)
	}
}

func TestGuardStartFails(t *testing.T) {
	pub, priv := keys(t)
	v := license.NewVerifier([]ed25519.PublicKey{pub})
	if _, err := license.NewGuard(v, "", license.WithLogger(quiet)); !errors.Is(err, license.ErrMissing) {
		t.Fatalf("leer: %v", err)
	}
	expired := sign(t, priv, nil)
	c := newClock(t0.AddDate(2, 0, 0))
	if _, err := license.NewGuard(v, expired, license.WithGuardClock(c.now), license.WithLogger(quiet)); !errors.Is(err, license.ErrExpired) {
		t.Fatalf("abgelaufen: %v", err)
	}
}

func TestGuardStateFileDetectsRollbackAcrossRestart(t *testing.T) {
	pub, priv := keys(t)
	tok := sign(t, priv, nil)
	v := license.NewVerifier([]ed25519.PublicKey{pub})
	path := filepath.Join(t.TempDir(), "license_state.json")

	c := newClock(t0.AddDate(0, 6, 0))
	if _, err := license.NewGuard(v, tok, license.WithGuardClock(c.now), license.WithStateFile(path), license.WithLogger(quiet)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("zustandsdatei fehlt: %v", err)
	}
	// "Neustart" mit zurückgestellter Uhr
	c.set(t0.AddDate(0, 1, 0))
	_, err := license.NewGuard(v, tok, license.WithGuardClock(c.now), license.WithStateFile(path), license.WithLogger(quiet))
	if !errors.Is(err, license.ErrClockRollback) {
		t.Fatalf("got %v", err)
	}
	// Nicht schreibbares Verzeichnis: nur Warnung, Start klappt
	if _, err := license.NewGuard(v, tok, license.WithGuardClock(newClock(t0.Add(time.Hour)).now),
		license.WithStateFile("/nonexistent/dir/state.json"), license.WithLogger(quiet)); err != nil {
		t.Fatal(err)
	}
}

func TestValidDoesNotAllocate(t *testing.T) {
	pub, priv := keys(t)
	v := license.NewVerifier([]ed25519.PublicKey{pub})
	g, err := license.NewGuard(v, sign(t, priv, func(l *license.License) { l.IssuedAt = time.Now().Add(-time.Hour) }), license.WithLogger(quiet))
	if err != nil {
		t.Fatal(err)
	}
	if n := testing.AllocsPerRun(1000, func() { _ = g.Valid() }); n != 0 {
		t.Fatalf("Valid allokiert %.1f mal", n)
	}
}

func BenchmarkValid(b *testing.B) {
	pub, priv, _ := issuer.GenerateKey()
	tok, _ := issuer.Sign(priv, license.License{ID: "1", Product: "a", Licensee: "b", IssuedAt: time.Now().Add(-time.Hour), ExpiresAt: time.Now().Add(time.Hour)})
	g, _ := license.NewGuard(license.NewVerifier([]ed25519.PublicKey{pub}), tok, license.WithLogger(quiet))
	b.ReportAllocs()
	for b.Loop() {
		_ = g.Valid()
	}
}

func TestUnmaskKeyAndGoSource(t *testing.T) {
	pub, _ := keys(t)
	src, err := issuer.GoSource("main", "licensePublicKey", pub)
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	if !strings.Contains(s, "func licensePublicKey() ed25519.PublicKey") || !strings.Contains(s, license.Fingerprint(pub)) {
		t.Fatalf("quelltext:\n%s", s)
	}
	// Der Schlüssel darf nicht am Stück im Quelltext stehen.
	plain := fmt.Sprintf("0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x", pub[0], pub[1], pub[2], pub[3], pub[4], pub[5])
	if strings.Contains(s, plain) {
		t.Fatal("öffentlicher schlüssel steht unmaskiert im quelltext")
	}
	if license.UnmaskKey(make([]byte, 31), make([]byte, 32)) != nil {
		t.Fatal("falsche länge muss nil liefern")
	}

	// Erzeugten Code tatsächlich kompilieren und ausführen.
	if testing.Short() {
		t.Skip("kompiliert ein Testprogramm")
	}
	modRoot, _ := filepath.Abs(".")
	dir := t.TempDir()
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module x\n\ngo 1.24\n\nrequire github.com/h2-invent/go-license v0.0.0\n\nreplace github.com/h2-invent/go-license => "+modRoot+"\n")
	write("key.go", s)
	write("main.go", `package main

import (
	"encoding/hex"
	"fmt"
)

func main() { fmt.Print(hex.EncodeToString(licensePublicKey())) }
`)
	cmd := exec.Command("go", "run", ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOFLAGS=-mod=mod")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go run: %v\n%s", err, out)
	}
	if got := string(out); got != hexString(pub) {
		t.Fatalf("schlüssel %s, erwartet %s", got, hexString(pub))
	}
}

func hexString(b []byte) string {
	const h = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, h[c>>4], h[c&15])
	}
	return string(out)
}
