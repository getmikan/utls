package tls

import (
	"bytes"
	"testing"

	"github.com/metacubex/utls/internal/mlkem"
)

func TestRealityClientPeerPub(t *testing.T) {
	x := keyShare{group: X25519, data: bytes.Repeat([]byte{1}, 32)}
	h := keyShare{group: X25519MLKEM768, data: append(make([]byte, mlkem.EncapsulationKeySize768), bytes.Repeat([]byte{2}, 32)...)}
	h2 := keyShare{group: X25519MLKEM768, data: append(make([]byte, mlkem.EncapsulationKeySize768), bytes.Repeat([]byte{3}, 32)...)}
	p := keyShare{group: CurveP256, data: make([]byte, 65)}
	bad := keyShare{group: X25519MLKEM768, data: make([]byte, 32)}
	hx := h.data[mlkem.EncapsulationKeySize768:]
	for _, tc := range []struct {
		name    string
		shares  []keyShare
		lenient []byte
		strict  []byte
	}{
		{"none", nil, nil, nil},
		{"x25519 only", []keyShare{x}, x.data, nil},
		{"mlkem only", []keyShare{h}, hx, hx},
		{"mlkem then x25519", []keyShare{h, x}, x.data, x.data},
		{"x25519 then mlkem", []keyShare{x, h}, x.data, nil},
		{"p256 mlkem x25519", []keyShare{p, h, x}, x.data, x.data},
		{"duplicate mlkem", []keyShare{h, h2, x}, x.data, nil},
		{"malformed mlkem", []keyShare{bad, x}, x.data, nil},
	} {
		if got := realityClientPeerPub(tc.shares, false); !bytes.Equal(got, tc.lenient) {
			t.Errorf("%s lenient: got %x, want %x", tc.name, got, tc.lenient)
		}
		if got := realityClientPeerPub(tc.shares, true); !bytes.Equal(got, tc.strict) {
			t.Errorf("%s strict: got %x, want %x", tc.name, got, tc.strict)
		}
	}
}

func TestRealityRequireX25519MLKEM768(t *testing.T) {
	tt := realityTestBigTarget(t, 6000)
	config, pub := newRealityTestConfig(t, tt.addr())
	config.RequireX25519MLKEM768 = true
	addr := newRealityTestServer(t, config)

	for _, tc := range []struct {
		groups []CurveID
		accept bool
	}{
		{[]CurveID{X25519MLKEM768, X25519}, true},
		{[]CurveID{X25519}, false},
		{[]CurveID{X25519, X25519MLKEM768}, false},
	} {
		uconn, authKey := realityTestDialShares(t, addr, pub, tc.groups)
		if got := realityTestIsReality(t, uconn, authKey); got != tc.accept {
			t.Fatalf("%v: accepted=%v, want %v", tc.groups, got, tc.accept)
		}
		if tc.accept {
			realityTestReadMarker(t, uconn)
		}
		uconn.Close()
	}
}
