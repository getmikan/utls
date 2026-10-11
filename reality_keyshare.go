package tls

// REALITY server: choice of the client key share that authenticates a
// REALITY ClientHello, optionally requiring X25519MLKEM768 like Xray
// (XTLS/REALITY@8cdf7bf).

import "github.com/metacubex/utls/internal/mlkem"

// realityClientPeerPub picks the X25519 public key used to derive the REALITY
// auth key: the X25519 key share, else the X25519 part of X25519MLKEM768.
//
// With requireMLKEM it mirrors Xray (XTLS/REALITY@8cdf7bf) and returns nil,
// rejecting the ClientHello, unless exactly one X25519MLKEM768 key share comes
// before an optional X25519 key share.
func realityClientPeerPub(keyShares []keyShare, requireMLKEM bool) []byte {
	var x25519, hybrid []byte
	for _, ks := range keyShares {
		if ks.group == X25519MLKEM768 && len(ks.data) == mlkem.EncapsulationKeySize768+32 {
			if hybrid != nil {
				if requireMLKEM {
					return nil
				}
				continue
			}
			hybrid = ks.data[mlkem.EncapsulationKeySize768:]
			continue
		}
		if ks.group == X25519 && len(ks.data) == 32 {
			x25519 = ks.data
			break
		}
	}
	if requireMLKEM && hybrid == nil {
		return nil
	}
	if x25519 != nil {
		return x25519
	}
	return hybrid
}
