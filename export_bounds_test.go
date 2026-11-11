package tls

import (
	"strings"
	"testing"
)

func TestExportKeyingMaterialBounds(t *testing.T) {
	for _, v := range []uint16{VersionTLS12, VersionTLS13} {
		clientConfig := testConfig.Clone()
		clientConfig.MaxVersion = v
		clientConfig.CipherSuites = []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}
		serverConfig := testConfig.Clone()
		serverConfig.MaxVersion = v
		_, cs, err := testHandshake(t, clientConfig, serverConfig)
		if err != nil {
			t.Fatal(err)
		}

		bad := []struct {
			label  string
			length int
		}{
			{"label", -1},
		}
		if v == VersionTLS13 {
			bad = append(bad,
				struct {
					label  string
					length int
				}{strings.Repeat("a", 250), 32},
				struct {
					label  string
					length int
				}{"label", 255*32 + 1},
				struct {
					label  string
					length int
				}{"label", 0x10000},
			)
		}
		for _, b := range bad {
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("%s: ExportKeyingMaterial(len(label)=%d, %d) panicked: %v", VersionName(v), len(b.label), b.length, r)
					}
				}()
				if _, err := cs.ExportKeyingMaterial(b.label, nil, b.length); err == nil {
					t.Errorf("%s: ExportKeyingMaterial(len(label)=%d, %d) = nil error", VersionName(v), len(b.label), b.length)
				}
			}()
		}

		if out, err := cs.ExportKeyingMaterial("label", []byte("ctx"), 64); err != nil || len(out) != 64 {
			t.Errorf("%s: ExportKeyingMaterial(64) = %d bytes, %v", VersionName(v), len(out), err)
		}
	}
}
