package mlkem

import (
	"crypto/rand"
	"io"
)

// randRead fills b with random bytes from crypto/rand.Reader and panics if
// that fails.
//
// Go's own ML-KEM draws from crypto/internal/fips140/drbg, which crashes the
// program when the system randomness source fails (as crypto/rand.Read does
// since Go 1.24). Before Go 1.24 crypto/rand.Read returns the error instead,
// and ignoring it would leave keys and encapsulation messages all-zero.
// Panicking keeps that guarantee on every Go version this module supports.
func randRead(b []byte) {
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic("mlkem: failed to read random data: " + err.Error())
	}
}
