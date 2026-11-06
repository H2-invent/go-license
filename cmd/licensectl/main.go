// licensectl erzeugt Schlüsselpaare, bettet öffentliche Schlüssel in Go-Code
// ein und stellt Lizenzschlüssel aus bzw. zeigt sie an.
//
//	licensectl genkey  -out license-private.pem [-pub license-public.pem]
//	licensectl gocode  (-key license-private.pem | -pub license-public.pem) -pkg main -func licensePublicKey -out license_pubkey.go
//	licensectl issue   -key license-private.pem -product log-collector -licensee "Firma GmbH" -expires 2027-12-31 [-feature x]... [-limit name=1]... [-meta k=v]...
//	licensectl inspect [-key …|-pub …] [-product …] <lizenzschlüssel>
package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	license "github.com/h2-invent/go-license"
	"github.com/h2-invent/go-license/issuer"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "genkey":
		err = genkey(os.Args[2:])
	case "gocode":
		err = gocode(os.Args[2:])
	case "issue":
		err = issue(os.Args[2:])
	case "inspect":
		err = inspect(os.Args[2:])
	case "help", "-h", "--help":
		usage()
	default:
		err = fmt.Errorf("unbekannter Befehl %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "fehler:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `Aufruf: licensectl <befehl> [optionen]

  genkey   neues Ed25519-Schlüsselpaar erzeugen
  gocode   Go-Datei mit einkompiliertem (maskiertem) öffentlichem Schlüssel erzeugen
  issue    Lizenzschlüssel ausstellen
  inspect  Lizenzschlüssel anzeigen und prüfen

"licensectl <befehl> -h" zeigt die Optionen.`)
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func genkey(args []string) error {
	fs := flag.NewFlagSet("genkey", flag.ExitOnError)
	out := fs.String("out", "license-private.pem", "Datei für den privaten Schlüssel (wird nicht überschrieben)")
	pubOut := fs.String("pub", "license-public.pem", "Datei für den öffentlichen Schlüssel (leer = keine)")
	_ = fs.Parse(args)

	pub, priv, err := issuer.GenerateKey()
	if err != nil {
		return err
	}
	privPEM, err := issuer.EncodePrivateKey(priv)
	if err != nil {
		return err
	}
	if err := writeNew(*out, privPEM, 0o600); err != nil {
		return err
	}
	if *pubOut != "" {
		pubPEM, err := issuer.EncodePublicKey(pub)
		if err != nil {
			return err
		}
		if err := writeNew(*pubOut, pubPEM, 0o644); err != nil {
			return err
		}
	}
	fmt.Printf("privater Schlüssel: %s (geheim halten, nicht ins Repository!)\n", *out)
	if *pubOut != "" {
		fmt.Printf("öffentlicher Schlüssel: %s\n", *pubOut)
	}
	fmt.Printf("fingerprint: %s\n", license.Fingerprint(pub))
	return nil
}

func writeNew(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// loadPub liest den öffentlichen Schlüssel aus -pub oder leitet ihn aus -key ab.
func loadPub(keyPath, pubPath string) (ed25519.PublicKey, error) {
	switch {
	case pubPath != "":
		b, err := os.ReadFile(pubPath)
		if err != nil {
			return nil, err
		}
		return issuer.ParsePublicKey(b)
	case keyPath != "":
		priv, err := loadPriv(keyPath)
		if err != nil {
			return nil, err
		}
		return priv.Public().(ed25519.PublicKey), nil
	}
	return nil, errors.New("-key oder -pub angeben")
}

func loadPriv(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return issuer.ParsePrivateKey(b)
}

func gocode(args []string) error {
	fs := flag.NewFlagSet("gocode", flag.ExitOnError)
	key := fs.String("key", "", "privater Schlüssel (PEM)")
	pubPath := fs.String("pub", "", "öffentlicher Schlüssel (PEM)")
	pkg := fs.String("pkg", "main", "Go-Paketname")
	fn := fs.String("func", "licensePublicKey", "Name der erzeugten Funktion")
	out := fs.String("out", "", "Zieldatei (leer = stdout)")
	_ = fs.Parse(args)

	pub, err := loadPub(*key, *pubPath)
	if err != nil {
		return err
	}
	src, err := issuer.GoSource(*pkg, *fn, pub)
	if err != nil {
		return err
	}
	if *out == "" {
		_, err = os.Stdout.Write(src)
		return err
	}
	if err := os.WriteFile(*out, src, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%s geschrieben (fingerprint %s)\n", *out, license.Fingerprint(pub))
	return nil
}

func parseDate(s string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("datum %q: erwartet YYYY-MM-DD oder RFC 3339", s)
}

func issue(args []string) error {
	fs := flag.NewFlagSet("issue", flag.ExitOnError)
	key := fs.String("key", "license-private.pem", "privater Schlüssel (PEM)")
	product := fs.String("product", "", "Produktkennung (Pflicht)")
	licensee := fs.String("licensee", "", "Lizenznehmer (Pflicht)")
	id := fs.String("id", "", "Lizenz-ID (leer = zufällig)")
	expires := fs.String("expires", "", "gültig bis einschließlich YYYY-MM-DD (Tagesende UTC) oder bis RFC-3339-Zeitpunkt")
	days := fs.Int("days", 0, "alternativ: gültig für N Tage ab jetzt")
	perpetual := fs.Bool("perpetual", false, "unbefristete Lizenz")
	notBefore := fs.String("not-before", "", "gültig ab (YYYY-MM-DD oder RFC 3339)")
	var features, limits, meta multi
	fs.Var(&features, "feature", "freigeschaltetes Feature (mehrfach)")
	fs.Var(&limits, "limit", "Limit name=zahl (mehrfach)")
	fs.Var(&meta, "meta", "Zusatzangabe key=value (mehrfach)")
	_ = fs.Parse(args)

	if *product == "" || *licensee == "" {
		return errors.New("-product und -licensee sind Pflicht")
	}
	l := license.License{
		ID:       *id,
		Product:  *product,
		Licensee: *licensee,
		IssuedAt: time.Now().UTC().Truncate(time.Second),
		Features: features,
	}
	if l.ID == "" {
		l.ID = issuer.NewID()
	}
	n := 0
	if *expires != "" {
		n++
		t, err := parseDate(*expires)
		if err != nil {
			return err
		}
		if len(*expires) == len("2006-01-02") {
			t = t.AddDate(0, 0, 1) // Datum = einschließlich, bis Tagesende UTC
		}
		l.ExpiresAt = t
	}
	if *days > 0 {
		n++
		l.ExpiresAt = l.IssuedAt.AddDate(0, 0, *days)
	}
	if *perpetual {
		n++
	}
	if n != 1 {
		return errors.New("genau eine Angabe aus -expires, -days oder -perpetual nötig")
	}
	if *notBefore != "" {
		t, err := parseDate(*notBefore)
		if err != nil {
			return err
		}
		l.NotBefore = t
	}
	for _, kv := range limits {
		k, v, ok := strings.Cut(kv, "=")
		n, err := strconv.ParseInt(v, 10, 64)
		if !ok || k == "" || err != nil {
			return fmt.Errorf("-limit %q: erwartet name=zahl", kv)
		}
		if l.Limits == nil {
			l.Limits = map[string]int64{}
		}
		l.Limits[k] = n
	}
	for _, kv := range meta {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			return fmt.Errorf("-meta %q: erwartet key=value", kv)
		}
		if l.Meta == nil {
			l.Meta = map[string]string{}
		}
		l.Meta[k] = v
	}

	priv, err := loadPriv(*key)
	if err != nil {
		return err
	}
	tok, err := issuer.Sign(priv, l)
	if err != nil {
		return err
	}
	fmt.Println(tok)
	return nil
}

func inspect(args []string) error {
	fs := flag.NewFlagSet("inspect", flag.ExitOnError)
	key := fs.String("key", "", "privater Schlüssel (PEM) zur Prüfung")
	pubPath := fs.String("pub", "", "öffentlicher Schlüssel (PEM) zur Prüfung")
	product := fs.String("product", "", "erwartetes Produkt")
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("genau einen Lizenzschlüssel angeben")
	}
	tok := fs.Arg(0)

	l, err := license.Decode(tok)
	if err != nil {
		return err
	}
	out := map[string]any{
		"id": l.ID, "product": l.Product, "licensee": l.Licensee,
		"issued_at": l.IssuedAt, "features": l.Features, "limits": l.Limits, "meta": l.Meta,
	}
	if !l.NotBefore.IsZero() {
		out["not_before"] = l.NotBefore
	}
	if l.Perpetual() {
		out["expires_at"] = "unbefristet"
	} else {
		out["expires_at"] = l.ExpiresAt
	}
	if *key != "" || *pubPath != "" {
		pub, err := loadPub(*key, *pubPath)
		if err != nil {
			return err
		}
		var opts []license.Option
		if *product != "" {
			opts = append(opts, license.WithProduct(*product))
		}
		_, verr := license.NewVerifier([]ed25519.PublicKey{pub}, opts...).Verify(tok)
		out["valid"] = verr == nil
		if verr != nil {
			out["error"] = verr.Error()
		}
	} else {
		out["valid"] = "nicht geprüft (-key oder -pub angeben)"
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
