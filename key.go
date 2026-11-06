package license

import (
	"crypto/ed25519"
	"crypto/subtle"
)

// UnmaskKey setzt einen einkompilierten öffentlichen Schlüssel aus zwei
// gleich langen Byte-Arrays zusammen (key = a XOR b).
//
// Hintergrund: Liegt der Schlüssel als Klartext im Binary, lässt er sich per
// Mustersuche finden und austauschen. Als zwei zufällig maskierte Arrays (die
// licensectl gocode als Go-Quelltext erzeugt) taucht er nirgends am Stück auf.
// Arrays statt Strings verhindern zudem, dass er per -ldflags "-X …" beim
// Bauen überschrieben werden kann. Eine Datei wird nicht benötigt.
//
// Das ist eine Erschwernis, kein absoluter Schutz: Wer das Binary
// disassembliert und patcht, kann jede clientseitige Prüfung entfernen.
func UnmaskKey(a, b []byte) ed25519.PublicKey {
	if len(a) != ed25519.PublicKeySize || len(b) != ed25519.PublicKeySize {
		return nil
	}
	out := make([]byte, ed25519.PublicKeySize)
	subtle.XORBytes(out, a, b)
	return out
}
