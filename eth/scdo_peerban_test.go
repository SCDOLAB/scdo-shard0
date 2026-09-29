package eth

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/core"
)

func TestSCDOPeerBans(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	b := newSCDOPeerBans()
	b.now = func() time.Time { return now }

	if b.banned("a", "1.2.3.4") {
		t.Fatal("banned before any offence")
	}
	if d := b.note("a", "1.2.3.4"); d != 10*time.Minute {
		t.Fatalf("first ban %v", d)
	}
	if !b.banned("a", "") {
		t.Fatal("id not banned after offence")
	}
	if b.banned("b", "1.2.3.4") {
		t.Fatal("IP banned after only one offence")
	}
	// second offence from same IP with a new node key -> IP banned too
	b.note("b", "1.2.3.4")
	if !b.banned("c", "1.2.3.4") {
		t.Fatal("IP not banned after second offence")
	}
	// escalation for the same id
	now = now.Add(11 * time.Minute)
	if b.banned("a", "9.9.9.9") {
		t.Fatal("ban did not expire")
	}
	if d := b.note("a", "9.9.9.9"); d != 20*time.Minute {
		t.Fatalf("second ban %v", d)
	}
	for i := 0; i < 20; i++ {
		b.note("a", "")
	}
	if d := scdoBanDuration(30); d != 24*time.Hour {
		t.Fatalf("cap %v", d)
	}
	// counters forgotten after quiet period
	now = now.Add(72 * time.Hour)
	if d := b.note("a", ""); d != 10*time.Minute {
		t.Fatalf("not forgotten: %v", d)
	}
	// loopback never IP-banned
	b.note("x", "127.0.0.1")
	b.note("y", "127.0.0.1")
	if b.banned("z", "127.0.0.1") {
		t.Fatal("loopback IP banned")
	}
	if len(b.list()) == 0 {
		t.Fatal("list empty")
	}
}

func TestSCDOCheckpointConflictDetect(t *testing.T) {
	wrapped := fmt.Errorf("retrieved hash chain is invalid: %v", fmt.Errorf("%w: number 80", core.ErrSCDOCheckpointMismatch))
	if !isSCDOCheckpointConflict(wrapped) {
		t.Fatal("flattened downloader error not detected")
	}
	if isSCDOCheckpointConflict(errors.New("timeout")) || isSCDOCheckpointConflict(nil) {
		t.Fatal("false positive")
	}
}
