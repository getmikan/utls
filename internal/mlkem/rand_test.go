package mlkem

import (
	"crypto/rand"
	"errors"
	"testing"
)

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("entropy source failed") }

// A failing randomness source must not yield a key or ciphertext built from
// zero bytes.
func TestRandFailurePanics(t *testing.T) {
	dk, err := GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	ek := dk.EncapsulationKey()

	orig := rand.Reader
	rand.Reader = failingReader{}
	defer func() { rand.Reader = orig }()

	for name, f := range map[string]func(){
		"GenerateKey768":  func() { GenerateKey768() },
		"GenerateKey1024": func() { GenerateKey1024() },
		"Encapsulate768":  func() { ek.Encapsulate() },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s did not panic when crypto/rand failed", name)
				}
			}()
			f()
		}()
	}
}
