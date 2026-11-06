package license

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
)

// Guard hält eine geprüfte Lizenz zur Laufzeit.
//
//   - NewGuard prüft Signatur, Produkt und Laufzeit; schlägt das fehl, soll
//     die Anwendung nicht starten.
//   - Valid ist für den Aufruf bei jedem Ereignis gedacht: ein atomarer Load
//     und ein Zeitvergleich, ohne Allokation im Gutfall.
//   - Run prüft die Signatur periodisch erneut (Schutz gegen Manipulation
//     im Speicher), schreibt den Zeitstempel für die Rückstell-Erkennung fort
//     und warnt vor Ablauf.
type Guard struct {
	v     *Verifier
	token string

	log         *slog.Logger
	now         func() time.Time
	statePath   string
	tolerance   time.Duration
	interval    time.Duration
	warnBefore  time.Duration
	lastWarnDay atomic.Int64
	stateWarned atomic.Bool

	st        atomic.Pointer[guardState]
	highWater atomic.Int64 // höchste beobachtete Zeit (Unix-Sekunden)
}

type guardState struct {
	lic *License
	err error // Fehler der Signaturprüfung (dauerhaft)
}

// GuardOption konfiguriert einen Guard.
type GuardOption func(*Guard)

// WithLogger setzt den Logger (Standard: slog.Default()).
func WithLogger(l *slog.Logger) GuardOption { return func(g *Guard) { g.log = l } }

// WithStateFile speichert die zuletzt gesehene Uhrzeit in einer Datei, damit
// ein Zurückstellen der Systemzeit auch über Neustarts erkannt wird. Fehlt
// die Datei oder ist sie nicht schreibbar, wird nur gewarnt.
func WithStateFile(path string) GuardOption { return func(g *Guard) { g.statePath = path } }

// WithRollbackTolerance legt fest, wie weit die Uhr zurückspringen darf, bevor
// ErrClockRollback gemeldet wird (Standard: 1 Stunde). 0 schaltet die
// Erkennung ab.
func WithRollbackTolerance(d time.Duration) GuardOption {
	return func(g *Guard) { g.tolerance = d }
}

// WithCheckInterval setzt das Intervall von Run (Standard: 1 Minute).
func WithCheckInterval(d time.Duration) GuardOption { return func(g *Guard) { g.interval = d } }

// WithExpiryWarning warnt (einmal täglich) so lange vor Ablauf (Standard: 30 Tage).
func WithExpiryWarning(d time.Duration) GuardOption { return func(g *Guard) { g.warnBefore = d } }

// WithGuardClock ersetzt time.Now (für Tests).
func WithGuardClock(now func() time.Time) GuardOption { return func(g *Guard) { g.now = now } }

// NewGuard prüft den Lizenzschlüssel vollständig. Bei einem Fehler wird kein
// Guard geliefert – die Anwendung soll dann nicht starten.
func NewGuard(v *Verifier, token string, opts ...GuardOption) (*Guard, error) {
	g := &Guard{
		v:          v,
		token:      token,
		log:        slog.Default(),
		now:        time.Now,
		tolerance:  time.Hour,
		interval:   time.Minute,
		warnBefore: 30 * 24 * time.Hour,
	}
	for _, o := range opts {
		o(g)
	}
	g.log = g.log.With("component", "license")

	lic, err := v.Parse(token)
	if err != nil {
		return nil, err
	}
	now := g.now()
	if err := v.CheckTime(lic, now); err != nil {
		return nil, err
	}

	g.highWater.Store(now.Unix())
	if g.statePath != "" && g.tolerance > 0 {
		if last, ok := g.loadState(lic.ID); ok {
			if now.Unix() < last-int64(g.tolerance/time.Second) {
				return nil, fmt.Errorf("%w (zuletzt gesehen %s, jetzt %s)", ErrClockRollback,
					time.Unix(last, 0).UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
			}
			if last > now.Unix() {
				g.highWater.Store(last)
			}
		}
	}
	g.st.Store(&guardState{lic: lic})
	g.saveState()
	return g, nil
}

// License liefert die geprüfte Lizenz.
func (g *Guard) License() *License { return g.st.Load().lic }

// Valid meldet, ob die Lizenz in diesem Moment gültig ist. Für den Aufruf
// pro Ereignis gedacht.
func (g *Guard) Valid() error {
	s := g.st.Load()
	if s.err != nil {
		return s.err
	}
	now := g.now()
	if g.tolerance > 0 {
		n := now.Unix()
		hw := g.highWater.Load()
		if n < hw-int64(g.tolerance/time.Second) {
			return ErrClockRollback
		}
		if n > hw {
			g.highWater.CompareAndSwap(hw, n) // best effort genügt
		}
	}
	return g.v.CheckTime(s.lic, now)
}

// Status fasst den Zustand zusammen (z. B. für /stats).
type Status struct {
	Valid     bool       `json:"valid"`
	Error     string     `json:"error,omitempty"`
	ID        string     `json:"id"`
	Product   string     `json:"product"`
	Licensee  string     `json:"licensee"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	DaysLeft  *int       `json:"days_left,omitempty"`
	Features  []string   `json:"features,omitempty"`
}

// Status liefert den aktuellen Zustand.
func (g *Guard) Status() Status {
	l := g.License()
	s := Status{ID: l.ID, Product: l.Product, Licensee: l.Licensee, Features: l.Features}
	if err := g.Valid(); err != nil {
		s.Error = err.Error()
	} else {
		s.Valid = true
	}
	if !l.Perpetual() {
		exp := l.ExpiresAt
		days := int(exp.Sub(g.now()).Hours() / 24)
		s.ExpiresAt, s.DaysLeft = &exp, &days
	}
	return s
}

// Run prüft periodisch erneut, bis ctx beendet ist.
func (g *Guard) Run(ctx context.Context) {
	t := time.NewTicker(g.interval)
	defer t.Stop()
	prev := g.Valid()
	for {
		select {
		case <-ctx.Done():
			g.saveState()
			return
		case <-t.C:
		}
		prev = g.recheck(prev)
	}
}

// recheck prüft die Signatur erneut und protokolliert Zustandswechsel.
func (g *Guard) recheck(prev error) error {
	if _, err := g.v.Parse(g.token); err != nil {
		g.st.Store(&guardState{lic: g.License(), err: err})
	}
	err := g.Valid()
	switch {
	case err != nil && (prev == nil || err.Error() != prev.Error()):
		g.log.Error("lizenz ist nicht mehr gültig – ereignisse werden abgelehnt", "error", err)
	case err == nil && prev != nil:
		g.log.Info("lizenz ist wieder gültig")
	}
	if err == nil {
		g.warnExpiry()
	}
	g.saveState()
	return err
}

func (g *Guard) warnExpiry() {
	l := g.License()
	if l.Perpetual() || g.warnBefore <= 0 {
		return
	}
	now := g.now()
	left := l.ExpiresAt.Sub(now)
	if left > g.warnBefore {
		return
	}
	day := now.Unix() / 86400
	if g.lastWarnDay.Swap(day) == day {
		return
	}
	g.log.Warn("lizenz läuft bald ab", "expires_at", l.ExpiresAt.Format(time.RFC3339),
		"days_left", int(left.Hours()/24), "license_id", l.ID)
}

// ---------------------------------------------------------------------------
// Zustandsdatei (Rückstell-Erkennung über Neustarts)
// ---------------------------------------------------------------------------

type stateFile struct {
	LicenseID string `json:"license_id"`
	LastSeen  int64  `json:"last_seen"`
}

func (g *Guard) loadState(id string) (int64, bool) {
	b, err := os.ReadFile(g.statePath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			g.log.Warn("lizenz-zustandsdatei nicht lesbar", "path", g.statePath, "error", err)
		}
		return 0, false
	}
	var s stateFile
	if err := json.Unmarshal(b, &s); err != nil || s.LicenseID != id {
		return 0, false
	}
	return s.LastSeen, true
}

func (g *Guard) saveState() {
	if g.statePath == "" || g.tolerance <= 0 {
		return
	}
	s := g.st.Load()
	if s == nil {
		return
	}
	b, _ := json.Marshal(stateFile{LicenseID: s.lic.ID, LastSeen: g.highWater.Load()})
	tmp, err := os.CreateTemp(filepath.Dir(g.statePath), ".license-state-*")
	if err == nil {
		_, err = tmp.Write(b)
		if cerr := tmp.Close(); err == nil {
			err = cerr
		}
		if err == nil {
			err = os.Rename(tmp.Name(), g.statePath)
		}
		if err != nil {
			_ = os.Remove(tmp.Name())
		}
	}
	if err != nil && !g.stateWarned.Swap(true) {
		g.log.Warn("lizenz-zustandsdatei nicht schreibbar", "path", g.statePath, "error", err)
	}
}
