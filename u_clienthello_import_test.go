package tls

import "testing"

func TestClientHelloSpecUnmarshalJSONMissingFields(t *testing.T) {
	for _, in := range []string{
		`{}`,
		`{"cipher_suites":["TLS_AES_128_GCM_SHA256"]}`,
		`{"cipher_suites":["TLS_AES_128_GCM_SHA256"],"compression_methods":["NULL"]}`,
		`{"compression_methods":["NULL"],"extensions":[]}`,
	} {
		var spec ClientHelloSpec
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("UnmarshalJSON(%s) panicked: %v", in, r)
				}
			}()
			if err := spec.UnmarshalJSON([]byte(in)); err == nil {
				t.Errorf("UnmarshalJSON(%s) = nil error; want an error", in)
			}
		}()
	}

	// A zero ClientHelloSpecJSONUnmarshaler must not panic either.
	_ = (&ClientHelloSpecJSONUnmarshaler{}).ClientHelloSpec()

	var spec ClientHelloSpec
	if err := spec.UnmarshalJSON([]byte(`{"cipher_suites":["TLS_AES_128_GCM_SHA256"],"compression_methods":["NULL"],"extensions":[]}`)); err != nil {
		t.Errorf("UnmarshalJSON of a minimal spec: %v", err)
	}
}

func TestImportTLSClientHelloKeyShare(t *testing.T) {
	base := func(keyShare []byte) map[string][]byte {
		return map[string][]byte{
			"cipher_suites":       {0x13, 0x01},
			"compression_methods": {0},
			"extensions":          {0, 51},
			"key_share":           keyShare,
		}
	}

	for _, ks := range [][]byte{
		{0x0a},
		{0x0a, 0x0a, 0x00},
		{0x0a, 0x0a, 0x00, 0x01, 0x00, 0x1d},
	} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("ImportTLSClientHello(key_share=%v) panicked: %v", ks, r)
				}
			}()
			var spec ClientHelloSpec
			if err := spec.ImportTLSClientHello(base(ks)); err == nil {
				t.Errorf("ImportTLSClientHello(key_share=%v) = nil error; want an error", ks)
			}
		}()
	}

	// GREASE (1 byte), X25519 (32 bytes) and X25519MLKEM768 (1216 bytes, a
	// length that does not fit in one byte).
	var spec ClientHelloSpec
	if err := spec.ImportTLSClientHello(base([]byte{0x0a, 0x0a, 0x00, 0x01, 0x00, 0x1d, 0x00, 0x20, 0x11, 0xec, 0x04, 0xc0})); err != nil {
		t.Fatalf("ImportTLSClientHello: %v", err)
	}
	ext, ok := spec.Extensions[0].(*KeyShareExtension)
	if !ok || len(ext.KeyShares) != 3 || ext.KeyShares[2].Group != X25519MLKEM768 {
		t.Fatalf("unexpected key_share extension: %#v", spec.Extensions[0])
	}
}
