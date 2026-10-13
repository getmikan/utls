package hkdf

import (
	"crypto/sha256"
	"testing"
)

func TestKeyLengthBounds(t *testing.T) {
	prk, err := Extract(sha256.New, []byte("secret"), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{-1, 255*sha256.Size + 1, 1 << 20} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("length %d panicked: %v", n, r)
				}
			}()
			if _, err := Expand(sha256.New, prk, "info", n); err == nil {
				t.Errorf("Expand(length %d) = nil error", n)
			}
			if _, err := Key(sha256.New, []byte("secret"), nil, "info", n); err == nil {
				t.Errorf("Key(length %d) = nil error", n)
			}
		}()
	}
	for _, n := range []int{0, 32, 255 * sha256.Size} {
		out, err := Key(sha256.New, []byte("secret"), nil, "info", n)
		if err != nil || len(out) != n {
			t.Errorf("Key(length %d) = %d bytes, %v", n, len(out), err)
		}
	}
}
