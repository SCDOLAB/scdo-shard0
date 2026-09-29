// Copyright 2026 9Y9 PTY LTD (SCDO shard0). LGPL-3.0, same as go-ethereum.
//
// Temporary bans for peers that serve chains conflicting with the SCDO signed
// checkpoint. Without this, a peer that keeps reconnecting with a heavier but
// checkpoint-conflicting chain triggers sync over and over, and a sync attempt
// against an already-dropped peer waits for the downloader timeout (~60 s),
// pausing local mining. Bans are by node ID from the first offence and by IP
// from the second offence from the same IP (loopback is never IP-banned).
// Durations escalate 10 min, 20 min, 40 min ... capped at 24 h.

package eth

import (
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/core"
)

const (
	scdoBanBase   = 10 * time.Minute
	scdoBanMax    = 24 * time.Hour
	scdoBanForget = 48 * time.Hour // offence counters are forgotten after this much quiet time
)

type scdoBan struct {
	count int
	until time.Time
	last  time.Time
}

type scdoPeerBans struct {
	mu   sync.Mutex
	byID map[string]*scdoBan
	byIP map[string]*scdoBan
	now  func() time.Time
}

func newSCDOPeerBans() *scdoPeerBans {
	return &scdoPeerBans{byID: map[string]*scdoBan{}, byIP: map[string]*scdoBan{}, now: time.Now}
}

func scdoBanDuration(count int) time.Duration {
	d := scdoBanBase
	for i := 1; i < count && d < scdoBanMax; i++ {
		d *= 2
	}
	if d > scdoBanMax {
		d = scdoBanMax
	}
	return d
}

func scdoIPOf(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}
	return host
}

func scdoBanIPAllowed(ip string) bool {
	p := net.ParseIP(ip)
	return p != nil && !p.IsLoopback() && !p.IsUnspecified()
}

// isSCDOCheckpointConflict reports whether a sync/import error was caused by a
// chain conflicting with the signed checkpoint (the downloader flattens error chains).
func isSCDOCheckpointConflict(err error) bool {
	return err != nil && strings.Contains(err.Error(), core.ErrSCDOCheckpointMismatch.Error())
}

func (b *scdoPeerBans) bump(m map[string]*scdoBan, key string, now time.Time) *scdoBan {
	e := m[key]
	if e == nil || now.Sub(e.last) > scdoBanForget {
		e = &scdoBan{}
		m[key] = e
	}
	e.count++
	e.last = now
	return e
}

// note records an offence and returns the ID ban duration.
func (b *scdoPeerBans) note(id, ip string) time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	e := b.bump(b.byID, id, now)
	d := scdoBanDuration(e.count)
	e.until = now.Add(d)
	if scdoBanIPAllowed(ip) {
		ipe := b.bump(b.byIP, ip, now)
		if ipe.count >= 2 {
			ipe.until = now.Add(scdoBanDuration(ipe.count - 1))
		}
	}
	return d
}

// banned reports whether the peer (by ID or IP) is currently banned.
func (b *scdoPeerBans) banned(id, ip string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	if e := b.byID[id]; e != nil && now.Before(e.until) {
		return true
	}
	if ip != "" {
		if e := b.byIP[ip]; e != nil && now.Before(e.until) {
			return true
		}
	}
	return false
}

// list returns the active bans (for scdo_status).
func (b *scdoPeerBans) list() []map[string]interface{} {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	var out []map[string]interface{}
	for k, e := range b.byID {
		if now.Before(e.until) {
			id := k
			if len(id) > 16 {
				id = id[:16]
			}
			out = append(out, map[string]interface{}{"id": id, "offences": e.count, "until": e.until.Unix()})
		}
	}
	for k, e := range b.byIP {
		if now.Before(e.until) {
			out = append(out, map[string]interface{}{"ip": k, "offences": e.count, "until": e.until.Unix()})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i]["until"].(int64) < out[j]["until"].(int64) })
	return out
}
