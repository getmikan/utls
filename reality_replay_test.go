package tls

import (
	"context"
	"io"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRealityReplayGuard(t *testing.T) {
	var g realityReplayGuard
	now := time.Unix(1_800_000_000, 0)
	id := func(b byte) []byte {
		r := make([]byte, 32)
		r[0], r[31] = b, b
		return r
	}
	const window = 10 * time.Minute
	if g.seen(id(1), now, window) {
		t.Fatal("the first ClientHello was taken for a copy")
	}
	if !g.seen(id(1), now.Add(time.Second), window) {
		t.Fatal("a copy passed")
	}
	if g.seen(id(2), now.Add(time.Second), window) {
		t.Fatal("another ClientHello was taken for a copy")
	}
	// A generation later the first one is still remembered: an entry lives
	// for at least one window.
	if g.seen(id(3), now.Add(window+time.Second), window) {
		t.Fatal("a new ClientHello after the turn was taken for a copy")
	}
	if !g.seen(id(1), now.Add(window+2*time.Second), window) {
		t.Fatal("a copy passed within the window after the generations turned")
	}
	// Two turns later it is forgotten: its time ran out long before.
	if g.seen(id(4), now.Add(2*window+3*time.Second), window) {
		t.Fatal("a new ClientHello was taken for a copy")
	}
	if g.seen(id(1), now.Add(2*window+4*time.Second), window) {
		t.Fatal("a ClientHello is remembered past two windows")
	}
	// A clock set back does not make the guard forget.
	if !g.seen(id(4), now, window) {
		t.Fatal("a copy passed after the clock went back")
	}
}

// Memory stays bounded: a full generation turns early, and what it held is
// still remembered as the old one.
func TestRealityReplayGuardIsBounded(t *testing.T) {
	var g realityReplayGuard
	now := time.Unix(1_800_000_000, 0)
	r := make([]byte, 32)
	put := func(i int) bool {
		r[0], r[1], r[2] = byte(i), byte(i>>8), byte(i>>16)
		return g.seen(r, now, time.Hour)
	}
	for i := 0; i < realityReplayGeneration+10; i++ {
		if put(i) {
			t.Fatalf("ClientHello %d was taken for a copy", i)
		}
	}
	if len(g.cur) > realityReplayGeneration || len(g.old) > realityReplayGeneration {
		t.Fatalf("generations hold %d and %d entries, want at most %d each", len(g.cur), len(g.old), realityReplayGeneration)
	}
	if !put(realityReplayGeneration - 1) {
		t.Fatal("a ClientHello of the generation just turned was forgotten")
	}
}

func TestRealityReplayWindow(t *testing.T) {
	if got := (&RealityConfig{MaxTimeDiff: 10 * time.Minute}).replayWindow(); got != 20*time.Minute {
		t.Fatalf("window = %v, want both sides of the time check", got)
	}
	if got := (&RealityConfig{}).replayWindow(); got != realityReplayDefaultWindow {
		t.Fatalf("window without a time check = %v, want %v", got, realityReplayDefaultWindow)
	}
	config := &RealityConfig{}
	clone := config.Clone()
	if clone.replayGuard() != config.replayGuard() || clone.Clone().replayGuard() != config.replayGuard() {
		t.Fatal("clones do not share the replay guard")
	}
}

// realitySentConn keeps a copy of everything written to the wrapped connection.
type realitySentConn struct {
	net.Conn
	mu   sync.Mutex
	sent []byte
}

func (c *realitySentConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	c.sent = append(c.sent, b...)
	c.mu.Unlock()
	return c.Conn.Write(b)
}

// realityTestLog collects what a RealityConfig logs.
type realityTestLog struct {
	mu    sync.Mutex
	lines []string
}

func (l *realityTestLog) add(format string, v ...any) {
	l.mu.Lock()
	l.lines = append(l.lines, format)
	l.mu.Unlock()
}

func (l *realityTestLog) count(part string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, line := range l.lines {
		if strings.Contains(line, part) {
			n++
		}
	}
	return n
}

// A ClientHello a client authenticated with is accepted once. Sent again, as
// someone who recorded it on the wire would send it, it is handed to the target
// like a stranger's: what comes back is the target's own answer, and the
// REALITY server does not answer it itself.
func TestRealityReplayedClientHelloGoesToTheTarget(t *testing.T) {
	tt := newRealityTestTarget(t, realityTestTargetConfig(nil, false), nil, true)
	config, pub := newRealityTestConfig(t, tt.addr())
	config.MaxTimeDiff = time.Minute
	log := new(realityTestLog)
	config.Log = log.add
	addr := newRealityTestServer(t, config)

	// A real client: its ClientHello is recorded on its way out.
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	rec := &realitySentConn{Conn: raw}
	uconn := UClient(rec, &Config{ServerName: realityTestServerName, InsecureSkipVerify: true, SessionTicketsDisabled: true}, HelloCustom)
	spec := realityProbeClientHelloSpec(realityPostHandshakeKey{serverName: realityTestServerName, cipherSuite: realityTestSuites[0]})
	if err := uconn.ApplyPreset(spec); err != nil {
		t.Fatal(err)
	}
	realityTestAuthenticate(t, uconn, pub)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := uconn.HandshakeContext(ctx); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	marker := make([]byte, len(realityTestMarker))
	uconn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(uconn, marker); err != nil || string(marker) != string(realityTestMarker) {
		t.Fatalf("the client was not served by the REALITY server: %q %v", marker, err)
	}
	rec.mu.Lock()
	sent := append([]byte(nil), rec.sent...)
	rec.mu.Unlock()
	if len(sent) < recordHeaderLen || recordType(sent[0]) != recordTypeHandshake {
		t.Fatalf("no ClientHello recorded: %d bytes sent", len(sent))
	}
	hello := sent[:recordHeaderLen+int(sent[3])<<8+int(sent[4])]
	if log.count("replayed ClientHello") != 0 {
		t.Fatal("the client's own ClientHello was taken for a copy")
	}
	completed := tt.completed.Load()

	// The same bytes again, on a new connection. The target answers them
	// itself: its first flight comes back, and nothing after it, for whoever
	// replays cannot finish the handshake.
	answer := func(to string) []int {
		c, err := net.Dial("tcp", to)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if _, err := c.Write(hello); err != nil {
			t.Fatal(err)
		}
		c.SetReadDeadline(time.Now().Add(time.Second))
		got, _ := io.ReadAll(c)
		return realityTestRecordLens(t, got)
	}
	viaReality := answer(addr)
	if n := log.count("replayed ClientHello"); n != 1 {
		t.Fatalf("the copy was noticed %d times, want once", n)
	}
	// The signature in the target's flight is a byte or two longer or shorter
	// from one handshake to the next, so the flights are compared by their
	// shape: as many records, the same ServerHello and ChangeCipherSpec.
	direct := answer(tt.addr())
	if len(direct) < 3 || len(viaReality) != len(direct) || !reflect.DeepEqual(viaReality[:2], direct[:2]) {
		t.Fatalf("a replayed ClientHello got records %v through the REALITY server, the target itself answers %v", viaReality, direct)
	}
	if tt.completed.Load() != completed {
		t.Fatal("the target completed a handshake with a replayed ClientHello")
	}

	// A new ClientHello of the same client is served as before.
	if _, _ = realityTestConnect(t, addr, pub, nil, realityTestSuites); log.count("replayed ClientHello") != 1 {
		t.Fatal("a fresh ClientHello was taken for a copy")
	}
}
