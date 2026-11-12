package tls

// REALITY server: a ClientHello authenticates once.
//
// The proof of a REALITY client sits in its ClientHello, so whoever recorded
// one on the wire can send it again. The time in it (MaxTimeDiff) only bounds
// for how long. A replayed ClientHello would pass the check, and the server
// would answer it itself: the sender cannot finish that handshake, but how the
// server behaves towards it is not how the target would, and that tells the two
// apart. The server therefore remembers the ClientHellos it accepted for as
// long as their time stays valid, and hands a second copy to the target as it
// does with any stranger, so the copy gets the target's own answer.

import (
	"sync"
	"time"
)

const (
	// realityReplayGeneration bounds the ClientHellos remembered in one
	// generation. A server that accepts more than this within the window
	// starts the next generation early: memory stays bounded, at the price of
	// forgetting the oldest ones before their time is up.
	realityReplayGeneration = 1 << 16
	// realityReplayDefaultWindow is how long a ClientHello is remembered when
	// the config sets no MaxTimeDiff, that is, when its time is not checked
	// and it would otherwise be accepted forever.
	realityReplayDefaultWindow = time.Hour
)

// realityReplayGuard remembers accepted ClientHellos by their random, which the
// client draws anew for each one and which the proof covers, so no other
// ClientHello carries the same. Two generations are kept: an entry lives for at
// least one window and at most two. It is shared by a RealityConfig and all
// its clones.
type realityReplayGuard struct {
	mu     sync.Mutex
	cur    map[[32]byte]struct{}
	old    map[[32]byte]struct{}
	turned time.Time // when cur was started
}

// seen records the ClientHello with the given random and reports whether it was
// recorded before, within window at least.
func (g *realityReplayGuard) seen(random []byte, now time.Time, window time.Duration) bool {
	var id [32]byte
	copy(id[:], random)

	g.mu.Lock()
	defer g.mu.Unlock()
	if g.cur == nil {
		g.cur = make(map[[32]byte]struct{})
		g.turned = now
	}
	if _, ok := g.cur[id]; ok {
		return true
	}
	if _, ok := g.old[id]; ok {
		return true
	}
	// The clock going back does not turn the generations early.
	if age := now.Sub(g.turned); age >= window || len(g.cur) >= realityReplayGeneration {
		g.old = g.cur
		g.cur = make(map[[32]byte]struct{})
		g.turned = now
	}
	g.cur[id] = struct{}{}
	return false
}

// replayWindow is how long an accepted ClientHello has to be remembered: its
// time is valid from MaxTimeDiff before the server's clock to MaxTimeDiff
// after it, twice MaxTimeDiff in all.
func (a *RealityConfig) replayWindow() time.Duration {
	if a.MaxTimeDiff <= 0 {
		return realityReplayDefaultWindow
	}
	return 2 * a.MaxTimeDiff
}

// replayGuard returns the guard shared by this config and its clones, creating
// it on first use.
func (a *RealityConfig) replayGuard() *realityReplayGuard {
	if g := a.replay.Load(); g != nil {
		return g
	}
	g := new(realityReplayGuard)
	if a.replay.CompareAndSwap(nil, g) {
		return g
	}
	return a.replay.Load()
}
