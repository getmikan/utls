package tls

// REALITY server: learn and imitate the configured target's TLS 1.3
// post-handshake records.
//
// A TLS 1.3 server may send encrypted records after its Finished message, most
// commonly NewSessionTicket. Some servers send them in their first flight
// (reproduced per connection via handshakeLen[6]), others only after they have
// received the client's Finished. The REALITY server cannot observe the latter
// on the live connection, because the real client's Finished is never
// forwarded to the target once the client has been authenticated. Instead, the
// wire lengths of those records are learned once per (target, SNI, ALPN,
// cipher suite) with a probe handshake and replayed as empty application_data
// records of the same length after the client's Finished.
//
// A client that came before the pattern was learned would get no such records
// while the target sends them: the first connection after a start would look
// unlike every later one and unlike the target. So the patterns of the usual
// handshakes are learned ahead, on the first connection of any kind
// (warmPostHandshake), the probe of a new key starts as soon as the target's
// ServerHello names the cipher suite, and a client whose pattern is still being
// learned waits for it, for a short bounded time.

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"
)

const (
	realityALPNNone uint8 = iota
	realityALPNHTTP1
	realityALPNH2
)

const (
	// realityMaxPostHandshakeRecords bounds how many records are imitated. A
	// target emitting more than this in the probe window is not imitated.
	realityMaxPostHandshakeRecords = 8
	// realityMinPostHandshakeRecordLen is the smallest TLS 1.3 encrypted record:
	// header, one byte of TLSInnerPlaintext (the content type) and the AEAD tag.
	realityMinPostHandshakeRecordLen = recordHeaderLen + 1 + 16
	// realityMaxPostHandshakeRecordLen is the largest record that can carry an
	// empty application_data fragment padded to length.
	realityMaxPostHandshakeRecordLen = recordHeaderLen + maxPlaintext + 1 + 16
)

// Probe tunables. Variables so tests can shorten them.
var (
	// realityPostHandshakeProbeTimeout bounds dial plus handshake of a probe.
	realityPostHandshakeProbeTimeout = 15 * time.Second
	// realityPostHandshakeCollectWindow is how long a probe waits for
	// post-handshake records after its handshake completed.
	realityPostHandshakeCollectWindow = 5 * time.Second
	// realityPostHandshakeRetryInterval is the minimum delay before a failed
	// probe is attempted again for the same key.
	realityPostHandshakeRetryInterval = time.Minute
	// realityPostHandshakeQuiet ends a probe's collection early: once the
	// target has sent nothing for this long, or for as long as the probe's own
	// dial and handshake took if that is longer, it is taken to be done. A
	// target sends these records right after the client's Finished, so the
	// whole collect window is only for one that keeps sending.
	realityPostHandshakeQuiet = 400 * time.Millisecond
	// realityPostHandshakeWait bounds how long a client waits for a pattern
	// that is being learned, counted from the start of the probe: a probe that
	// hangs holds up only the clients of its first moments.
	realityPostHandshakeWait = 2 * time.Second
)

// realityWarmServerNames bounds the server names whose patterns are learned
// ahead; a config with more learns the rest on demand.
const realityWarmServerNames = 4

// realityPostHandshakeKey identifies a learned post-handshake record pattern.
// The key space is bounded by RealityConfig.ServerNames, the three ALPN modes
// and the TLS 1.3 cipher suites, because lookups only happen for authenticated
// clients whose ClientHello the target already answered.
type realityPostHandshakeKey struct {
	network     string
	dest        string
	serverName  string
	alpn        uint8
	cipherSuite uint16
}

type realityPostHandshakeEntry struct {
	started time.Time     // when the probe began
	done    chan struct{} // closed when the probe finished; fields below are valid after that

	lens     []uint16
	ok       bool
	finished time.Time
}

// realityPostHandshakeCache is shared by a RealityConfig and all its clones.
type realityPostHandshakeCache struct {
	mu      sync.Mutex
	entries map[realityPostHandshakeKey]*realityPostHandshakeEntry
	warmed  bool // warmPostHandshake ran
}

func newRealityPostHandshakeCache() *realityPostHandshakeCache {
	return &realityPostHandshakeCache{entries: make(map[realityPostHandshakeKey]*realityPostHandshakeEntry)}
}

// start returns the entry of key, beginning at most one probe for it: when
// nothing was learned yet, or when the last probe failed long enough ago. It
// does not block.
func (c *realityPostHandshakeCache) start(config *RealityConfig, key realityPostHandshakeKey) *realityPostHandshakeEntry {
	c.mu.Lock()
	defer c.mu.Unlock()

	if e := c.entries[key]; e != nil {
		select {
		case <-e.done:
			if e.ok || time.Since(e.finished) < realityPostHandshakeRetryInterval {
				return e
			}
			// A stale failure: probe again below.
		default:
			return e // probe in flight
		}
	}

	e := &realityPostHandshakeEntry{started: time.Now(), done: make(chan struct{})}
	c.entries[key] = e
	go e.run(config, key)
	return e
}

// lookup returns the learned record lengths for key. A pattern that is still
// being learned is waited for until realityPostHandshakeWait after its probe
// began; past that, and after a probe that failed, it returns ok=false at once.
func (c *realityPostHandshakeCache) lookup(config *RealityConfig, key realityPostHandshakeKey) (lens []uint16, ok bool) {
	e := c.start(config, key)
	select {
	case <-e.done:
	default:
		wait := time.Until(e.started.Add(realityPostHandshakeWait))
		if wait <= 0 {
			return nil, false
		}
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-e.done:
		case <-timer.C:
			return nil, false
		}
	}
	if !e.ok {
		return nil, false
	}
	return e.lens, true
}

// warmPostHandshake learns, once for a config and its clones, the patterns of
// the handshakes clients usually make: each server name with h2 and each
// TLS 1.3 cipher suite. It is called on every connection and returns at once;
// the probes run one after another in the background, so the first client
// after a start finds its pattern learned and neither waits for it nor differs
// from the clients after it.
func (a *RealityConfig) warmPostHandshake() {
	if a.noPostHandshakeWarm {
		return
	}
	c := a.postHandshakeCache()
	c.mu.Lock()
	warmed := c.warmed
	c.warmed = true
	c.mu.Unlock()
	if warmed {
		return
	}
	names := make([]string, 0, realityWarmServerNames)
	for name, on := range a.ServerNames {
		if on && name != "" && len(names) < realityWarmServerNames {
			names = append(names, name)
		}
	}
	go func() {
		for _, name := range names {
			for _, suite := range []uint16{TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256} {
				<-c.start(a, realityPostHandshakeKey{network: a.Type, dest: a.Dest, serverName: name, alpn: realityALPNH2, cipherSuite: suite}).done
			}
		}
	}()
}

func (e *realityPostHandshakeEntry) run(config *RealityConfig, key realityPostHandshakeKey) {
	lens, err := realityProbePostHandshakeRecords(config, key)
	if config.Log != nil {
		config.Log("REALITY probe dest: %v sni: %v alpn: %v suite: %x lens: %v err: %v", key.dest, key.serverName, key.alpn, key.cipherSuite, lens, err)
	}
	e.lens = lens
	e.ok = err == nil
	e.finished = time.Now()
	close(e.done)
}

// realityALPNMode reduces the client's ALPN list to the mode the probe offers.
// Servers typically apply their own preference, so any offer of h2 is treated
// as an h2 negotiation.
func realityALPNMode(protos []string) uint8 {
	if len(protos) == 0 {
		return realityALPNNone
	}
	for _, p := range protos {
		if p == "h2" {
			return realityALPNH2
		}
	}
	return realityALPNHTTP1
}

func realityProbeALPN(mode uint8) []string {
	switch mode {
	case realityALPNH2:
		return []string{"h2", "http/1.1"}
	case realityALPNHTTP1:
		return []string{"http/1.1"}
	default:
		return nil
	}
}

// realityProbeClientHelloSpec builds a minimal TLS 1.3-only ClientHello that
// pins the negotiation to the observed cipher suite and ALPN mode.
func realityProbeClientHelloSpec(key realityPostHandshakeKey) *ClientHelloSpec {
	extensions := []TLSExtension{
		&SNIExtension{ServerName: key.serverName},
		&SupportedCurvesExtension{Curves: []CurveID{X25519}},
		&SupportedPointsExtension{SupportedPoints: []uint8{pointFormatUncompressed}},
		&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
			ECDSAWithP256AndSHA256,
			PSSWithSHA256,
			PKCS1WithSHA256,
			ECDSAWithP384AndSHA384,
			PSSWithSHA384,
			PKCS1WithSHA384,
			PSSWithSHA512,
			PKCS1WithSHA512,
			Ed25519,
		}},
	}
	if protos := realityProbeALPN(key.alpn); protos != nil {
		extensions = append(extensions, &ALPNExtension{AlpnProtocols: protos})
	}
	extensions = append(extensions,
		&KeyShareExtension{KeyShares: []KeyShare{{Group: X25519}}},
		&PSKKeyExchangeModesExtension{Modes: []uint8{PskModeDHE}},
		&SupportedVersionsExtension{Versions: []uint16{VersionTLS13}},
	)
	return &ClientHelloSpec{
		CipherSuites:       []uint16{key.cipherSuite},
		CompressionMethods: []uint8{compressionNone},
		Extensions:         extensions,
	}
}

// realityProbePostHandshakeRecords performs one handshake with the target and
// returns the wire lengths of every record the target sent after its Finished
// within the collection window.
func realityProbePostHandshakeRecords(config *RealityConfig, key realityPostHandshakeKey) ([]uint16, error) {
	ctx, cancel := context.WithTimeout(context.Background(), realityPostHandshakeProbeTimeout)
	defer cancel()

	began := time.Now()
	target, err := config.DialContext(ctx, key.network, key.dest)
	if err != nil {
		return nil, err
	}
	defer target.Close()

	uconn := UClient(target, &Config{
		ServerName:         key.serverName,
		InsecureSkipVerify: true, // only record lengths are of interest
	}, HelloCustom)
	if err := uconn.ApplyPreset(realityProbeClientHelloSpec(key)); err != nil {
		return nil, err
	}
	if err := uconn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	// The target answers within about a round trip, and the dial and the
	// handshake just took several: a target farther away gets longer.
	quiet := realityPostHandshakeQuiet
	if took := time.Since(began); took > quiet {
		quiet = took
	}
	if state := uconn.ConnectionState(); state.Version != VersionTLS13 || state.CipherSuite != key.cipherSuite {
		return nil, errors.New("REALITY: probe negotiated unexpected parameters")
	}

	// The client handshake consumed records up to and including the server
	// Finished. Whatever it read beyond that is the start of the
	// post-handshake stream.
	data := append([]byte(nil), uconn.rawInput.Bytes()...)

	// Bound the collection: a read deadline where supported, and a hard close
	// for transports that ignore deadlines. It ends when the target hangs up,
	// when it has been quiet for long enough, or at the end of the window.
	stop := time.AfterFunc(realityPostHandshakeCollectWindow, func() { target.Close() })
	defer stop.Stop()
	end := time.Now().Add(realityPostHandshakeCollectWindow)

	const maxCollect = (realityMaxPostHandshakeRecords + 1) * realityMaxPostHandshakeRecordLen
	buf := make([]byte, 4096)
	for len(data) <= maxCollect {
		deadline := time.Now().Add(quiet)
		if deadline.After(end) {
			deadline = end
		}
		target.SetReadDeadline(deadline)
		n, err := target.Read(buf)
		data = append(data, buf[:n]...)
		if err != nil {
			break
		}
	}

	lens, ok := realityParsePostHandshakeRecords(data)
	if !ok {
		return nil, errors.New("REALITY: probe observed an unusable post-handshake record stream")
	}
	return lens, nil
}

// realityParsePostHandshakeRecords splits data into TLS 1.3 encrypted records
// and returns their wire lengths. It reports ok=false when the stream holds
// anything other than complete application_data records of imitable size.
func realityParsePostHandshakeRecords(data []byte) (lens []uint16, ok bool) {
	lens = make([]uint16, 0, 2)
	for len(data) > 0 {
		if len(data) < recordHeaderLen {
			return nil, false // cut inside a record header
		}
		if recordType(data[0]) != recordTypeApplicationData ||
			data[1] != 0x03 || data[2] != 0x03 { // record-layer version is frozen to TLS 1.2
			return nil, false
		}
		length := recordHeaderLen + int(binary.BigEndian.Uint16(data[3:5]))
		if length < realityMinPostHandshakeRecordLen || length > realityMaxPostHandshakeRecordLen {
			return nil, false
		}
		if len(data) < length {
			return nil, false // cut inside a record
		}
		if len(lens) == realityMaxPostHandshakeRecords {
			return nil, false
		}
		lens = append(lens, uint16(length))
		data = data[length:]
	}
	return lens, true
}

// realityWritePostHandshakeRecord writes a single TLS 1.3 record of exactly
// length bytes on the wire. The record carries an empty application_data
// fragment and zero padding, so clients ignore it, and it consumes one
// sequence number of the server application traffic keys like the record it
// imitates.
func (c *Conn) realityWritePostHandshakeRecord(length int) error {
	c.out.Lock()
	defer c.out.Unlock()

	sealer, ok := c.out.cipher.(aead)
	if !ok || c.vers != VersionTLS13 {
		return errors.New("REALITY: post-handshake record without TLS 1.3 application keys")
	}
	inner := length - recordHeaderLen - sealer.Overhead()
	if inner < 1 || inner > maxPlaintext+1 {
		return fmt.Errorf("REALITY: invalid post-handshake record length %d", length)
	}

	record := make([]byte, recordHeaderLen, length)
	record[0] = byte(recordTypeApplicationData)
	record[1] = 0x03 // record-layer version is frozen to TLS 1.2
	record[2] = 0x03
	record[3] = byte((length - recordHeaderLen) >> 8)
	record[4] = byte(length - recordHeaderLen)

	// TLSInnerPlaintext: empty content, the real content type, zero padding.
	plaintext := make([]byte, inner)
	plaintext[0] = byte(recordTypeApplicationData)

	record = sealer.Seal(record, c.out.seq[:], plaintext, record[:recordHeaderLen])
	c.out.incSeq()
	_, err := c.write(record)
	return err
}

// postHandshakeCache returns the cache shared by this config and its clones,
// creating it on first use.
func (a *RealityConfig) postHandshakeCache() *realityPostHandshakeCache {
	if c := a.postHandshake.Load(); c != nil {
		return c
	}
	c := newRealityPostHandshakeCache()
	if a.postHandshake.CompareAndSwap(nil, c) {
		return c
	}
	return a.postHandshake.Load()
}

// postHandshakeKey is the key of the pattern this handshake has to imitate.
// It is known once the target's ServerHello was read.
func (hs *realityServerHandshakeStateTLS13) postHandshakeKey() realityPostHandshakeKey {
	return realityPostHandshakeKey{
		network:     hs.Config.Type,
		dest:        hs.Config.Dest,
		serverName:  hs.clientHello.serverName,
		alpn:        realityALPNMode(hs.clientHello.alpnProtocols),
		cipherSuite: hs.hello.cipherSuite,
	}
}

// imitatePostHandshakeRecords is called after the client's Finished was
// verified. It replays the target's learned post-handshake records, minus the
// ones already mirrored in the first flight. Without a usable cache entry it
// changes nothing.
func (hs *realityServerHandshakeStateTLS13) imitatePostHandshakeRecords() error {
	config := hs.Config
	lens, ok := config.postHandshakeCache().lookup(config, hs.postHandshakeKey())
	if !ok {
		return nil
	}
	skip := hs.firstFlightPostHandshakeRecords
	if skip > len(lens) {
		skip = len(lens)
	}
	for _, length := range lens[skip:] {
		if err := hs.c.realityWritePostHandshakeRecord(int(length)); err != nil {
			return err
		}
		if config.Log != nil {
			config.Log("REALITY remoteAddr: %v post-handshake record: %v", hs.c.RemoteAddr(), length)
		}
	}
	return nil
}
