// scdostratum: a small solo stratum <-> getwork proxy for SCDO shard0 (core-geth, Ethash).
//
// Modern GPU miners (Rigel, lolMiner, BzMiner, ...) speak stratum only; core-geth offers
// getwork (eth_getWork / eth_submitWork). This proxy sits in front of ONE node:
//
//	miner --stratum--> scdostratum --getwork(HTTP JSON-RPC)--> core-geth (--miner.etherbase decides rewards)
//
// Supported miner protocols on the same port (auto-detected from the first request):
//   - ETHPROXY / "stratum1" (eth_submitLogin, eth_getWork, eth_submitWork, id:0 pushes)
//   - EthereumStratum/1.0.0 (NiceHash: mining.subscribe/authorize/set_difficulty/notify/submit)
//
// Every share is verified with an ethash light cache; shares that also meet the block
// target are forwarded to the node with eth_submitWork. The login/wallet sent by the miner
// is only used as a label: block rewards always go to the node's --miner.etherbase.
//
// Optional safety for a local node (-autostart): the proxy calls miner_start only once the
// node has peers, is not syncing and has reached the head reported by -ref-rpc, and stops
// serving work (miner_stop) if the node loses all peers, so a fresh node never mines its
// own fork from genesis.
package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/consensus/ethash"
)

const version = "scdostratum/1.0.1"

var (
	two256 = new(big.Int).Lsh(big.NewInt(1), 256)
	// NiceHash / EthereumStratum difficulty 1 target: 0x00000000ffff0000...0000
	nhDiff1 = new(big.Int).Lsh(big.NewInt(0xffff), 208)
)

// ---------------------------------------------------------------- config

type config struct {
	rpcURL        string
	listen        string
	shareDiff     float64 // default share difficulty in ethash units (hashes per share)
	minClientDiff float64
	poll          time.Duration
	epochLength   uint64
	maxConns      int
	maxConnsPerIP int
	autostart     bool
	refRPC        string
	maxLag        uint64
	requirePeers  bool
	statsEvery    time.Duration
	verbose       bool
	verifyThreads int
	maxSubmits    int    // per-connection submissions per second
	maxAhead      uint64 // with -ref-rpc: pause when the local head is this far ahead of the network
	logFile       string
}

// ---------------------------------------------------------------- node RPC

type rpcClient struct {
	url string
	hc  *http.Client
	id  atomic.Int64
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *rpcError) Error() string { return fmt.Sprintf("rpc error %d: %s", e.Code, e.Message) }

func newRPC(url string) *rpcClient {
	return &rpcClient{url: url, hc: &http.Client{Timeout: 10 * time.Second}}
}

func (c *rpcClient) call(method string, params []interface{}, out interface{}) error {
	if params == nil {
		params = []interface{}{}
	}
	body, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": c.id.Add(1), "method": method, "params": params})
	req, err := http.NewRequest("POST", c.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", version)
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("http %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	var r struct {
		Result json.RawMessage `json:"result"`
		Error  *rpcError       `json:"error"`
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return err
	}
	if r.Error != nil {
		return r.Error
	}
	if out != nil {
		return json.Unmarshal(r.Result, out)
	}
	return nil
}

func hexUint(s string) (uint64, error) {
	return strconv.ParseUint(strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X"), 16, 64)
}

// ---------------------------------------------------------------- work + ethash

type work struct {
	header      [32]byte
	seed        [32]byte
	blockTarget *big.Int
	blockDiff   *big.Int
	number      uint64
	parentTime  uint64 // unix timestamp of block number-1 (0 = unknown)
	jobID       string
	at          time.Time

	mu        sync.Mutex
	seen      map[uint64]struct{}
	found     bool
	submitted bool // one block per work: further solutions would only create sibling blocks
}

func (w *work) headerHex() string { return "0x" + hex.EncodeToString(w.header[:]) }
func (w *work) seedHex() string   { return "0x" + hex.EncodeToString(w.seed[:]) }

type cacheSet struct {
	mu          sync.Mutex
	epochLength uint64
	caches      map[uint64]*ethash.LightCache
	building    map[uint64]chan struct{}
}

func (cs *cacheSet) get(epoch uint64) *ethash.LightCache {
	cs.mu.Lock()
	if c, ok := cs.caches[epoch]; ok {
		cs.mu.Unlock()
		return c
	}
	if ch, ok := cs.building[epoch]; ok {
		cs.mu.Unlock()
		<-ch
		return cs.get(epoch)
	}
	ch := make(chan struct{})
	cs.building[epoch] = ch
	cs.mu.Unlock()

	start := time.Now()
	c := ethash.NewLightCache(epoch, cs.epochLength)
	log.Printf("ethash light cache for epoch %d ready (%s)", epoch, time.Since(start).Round(time.Millisecond))

	cs.mu.Lock()
	cs.caches[epoch] = c
	delete(cs.building, epoch)
	for e := range cs.caches { // keep at most 3 epochs
		if len(cs.caches) <= 3 {
			break
		}
		if e+1 < epoch {
			delete(cs.caches, e)
		}
	}
	cs.mu.Unlock()
	close(ch)
	return c
}

// ---------------------------------------------------------------- proxy

type proxy struct {
	cfg    config
	node   *rpcClient
	ref    *rpcClient
	caches *cacheSet
	verify chan struct{}

	mu       sync.RWMutex
	current  *work
	recent   []*work // newest last
	byHeader map[[32]byte]*work
	byJob    map[string]*work
	paused   atomic.Bool
	pauseMsg atomic.Value

	sessMu   sync.Mutex
	sessions map[*session]struct{}
	perIP    map[string]int
	nextEN   uint32

	sharesOK, sharesBad, blocksSent, blocksOK, blocksHeld atomic.Int64

	gateMu       sync.Mutex
	lastBlockSec int64 // wall-clock second of the last block submitted to the node
}

func newProxy(cfg config) *proxy {
	p := &proxy{
		cfg:      cfg,
		node:     newRPC(cfg.rpcURL),
		caches:   &cacheSet{epochLength: cfg.epochLength, caches: map[uint64]*ethash.LightCache{}, building: map[uint64]chan struct{}{}},
		verify:   make(chan struct{}, max(1, cfg.verifyThreads)),
		byHeader: map[[32]byte]*work{},
		byJob:    map[string]*work{},
		sessions: map[*session]struct{}{},
		perIP:    map[string]int{},
		nextEN:   uint32(time.Now().UnixNano()) & 0xffff,
	}
	if cfg.refRPC != "" {
		p.ref = newRPC(cfg.refRPC)
	}
	p.pauseMsg.Store("")
	return p
}

func (p *proxy) getCurrent() *work {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.paused.Load() {
		return nil
	}
	return p.current
}

// pollWork fetches eth_getWork and installs new work when the header changes.
func (p *proxy) pollWork() {
	var lastErr string
	for {
		var res []string
		err := p.node.call("eth_getWork", nil, &res)
		if err == nil && len(res) < 3 {
			err = errors.New("short eth_getWork result")
		}
		if err != nil {
			if err.Error() != lastErr {
				log.Printf("node: no work yet (%v)", err)
				lastErr = err.Error()
			}
			time.Sleep(time.Second)
			continue
		}
		if lastErr != "" {
			log.Printf("node: work available again")
			lastErr = ""
		}
		if w, err := p.parseWork(res); err != nil {
			log.Printf("node: bad work %v: %v", res, err)
		} else {
			p.installWork(w)
		}
		time.Sleep(p.cfg.poll)
	}
}

func parse32(s string) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X"))
	if err != nil {
		return out, err
	}
	if len(b) != 32 {
		return out, fmt.Errorf("want 32 bytes, got %d", len(b))
	}
	copy(out[:], b)
	return out, nil
}

func (p *proxy) parseWork(res []string) (*work, error) {
	h, err := parse32(res[0])
	if err != nil {
		return nil, err
	}
	p.mu.RLock()
	old := p.byHeader[h]
	p.mu.RUnlock()
	if old != nil {
		return old, nil
	}
	seed, err := parse32(res[1])
	if err != nil {
		return nil, err
	}
	tgt, err := parse32(res[2])
	if err != nil {
		return nil, err
	}
	target := new(big.Int).SetBytes(tgt[:])
	if target.Sign() == 0 {
		return nil, errors.New("zero target")
	}
	w := &work{header: h, seed: seed, blockTarget: target, blockDiff: new(big.Int).Div(two256, target),
		jobID: hex.EncodeToString(h[:8]), at: time.Now(), seen: map[uint64]struct{}{}}
	if len(res) >= 4 {
		if n, err := hexUint(res[3]); err == nil {
			w.number = n
		}
	}
	if w.number == 0 { // derive epoch from seed if the node did not report the height
		for e := uint64(0); e < 4096; e++ {
			if bytes.Equal(ethash.SeedHashFor(e, p.cfg.epochLength), seed[:]) {
				w.number = e*p.cfg.epochLength + 1
				break
			}
		}
	} else {
		var parent struct {
			Timestamp string `json:"timestamp"`
		}
		if err := p.node.call("eth_getBlockByNumber", []interface{}{fmt.Sprintf("0x%x", w.number-1), false}, &parent); err == nil {
			w.parentTime, _ = hexUint(parent.Timestamp)
		}
	}
	return w, nil
}

func (p *proxy) installWork(w *work) {
	p.mu.Lock()
	if p.current == w {
		p.mu.Unlock()
		return
	}
	prev := p.current
	p.current = w
	if _, ok := p.byHeader[w.header]; !ok {
		p.byHeader[w.header] = w
		p.byJob[w.jobID] = w
		p.recent = append(p.recent, w)
		for len(p.recent) > 32 {
			o := p.recent[0]
			p.recent = p.recent[1:]
			delete(p.byHeader, o.header)
			delete(p.byJob, o.jobID)
		}
	}
	p.mu.Unlock()

	epoch := w.number / p.cfg.epochLength
	p.caches.get(epoch)
	if (w.number+300)/p.cfg.epochLength > epoch { // pre-build the next epoch cache
		go p.caches.get(epoch + 1)
	}
	clean := prev == nil || prev.number != w.number
	if p.cfg.verbose || clean {
		log.Printf("new work: block %d diff %s header %s…", w.number, w.blockDiff, w.headerHex()[:18])
	}
	if !p.paused.Load() {
		p.broadcast(w, clean)
	}
}

func (p *proxy) broadcast(w *work, clean bool) {
	p.sessMu.Lock()
	list := make([]*session, 0, len(p.sessions))
	for s := range p.sessions {
		list = append(list, s)
	}
	p.sessMu.Unlock()
	for _, s := range list {
		go s.pushWork(w, clean)
	}
}

// shareResult is the outcome of a share verification.
type shareResult int

const (
	shareOK shareResult = iota
	shareStale
	shareDup
	shareLowDiff
	shareBadMix
	sharePaused
)

func (r shareResult) String() string {
	return [...]string{"accepted", "stale/unknown job", "duplicate share", "low difficulty share", "invalid mix digest", "node not ready"}[r]
}

// checkShare verifies a share for work w. mixIn may be nil (EthereumStratum does not send it).
func (p *proxy) checkShare(w *work, nonce uint64, mixIn []byte, shareTarget *big.Int, who string) shareResult {
	if w == nil {
		return shareStale
	}
	if p.paused.Load() {
		return sharePaused
	}
	w.mu.Lock()
	if _, dup := w.seen[nonce]; dup {
		w.mu.Unlock()
		return shareDup
	}
	w.seen[nonce] = struct{}{}
	w.mu.Unlock()

	cache := p.caches.get(w.number / p.cfg.epochLength)
	p.verify <- struct{}{}
	mix, result := cache.Hashimoto(w.header[:], nonce)
	<-p.verify

	if mixIn != nil && !bytes.Equal(mixIn, mix) {
		return shareBadMix
	}
	r := new(big.Int).SetBytes(result)
	// A result meeting the block target is always a valid share, even if the session
	// target was lowered/raised meanwhile.
	isBlock := r.Cmp(w.blockTarget) <= 0
	if !isBlock && r.Cmp(shareTarget) > 0 {
		return shareLowDiff
	}
	if isBlock {
		if p.blockAllowed(w) {
			p.submitBlock(w, nonce, mix, who)
		} else {
			p.blocksHeld.Add(1)
		}
	}
	return shareOK
}

// blockAllowed is the timestamp gate. core-geth stamps new work with max(now, parent+1), so a
// fast miner on a low-difficulty chain (e.g. one GPU on shard0) would otherwise produce several
// blocks per second with timestamps running into the future: peers reject blocks more than
// 15 s ahead, drop the node and it ends up mining a private fork. A block is therefore only
// submitted when its timestamp cannot be in the future (now >= parent time + 1, at most one
// block per wall-clock second from this proxy) and only once per work; other solutions are
// still accepted as shares.
func (p *proxy) blockAllowed(w *work) bool {
	p.gateMu.Lock()
	defer p.gateMu.Unlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.submitted {
		return false
	}
	now := time.Now().Unix()
	need := p.lastBlockSec + 1
	if pt := int64(w.parentTime) + 1; pt > need {
		need = pt
	}
	if now < need {
		return false
	}
	w.submitted = true
	p.lastBlockSec = now
	return true
}

func (p *proxy) submitBlock(w *work, nonce uint64, mix []byte, who string) {
	p.blocksSent.Add(1)
	var ok bool
	err := p.node.call("eth_submitWork", []interface{}{fmt.Sprintf("0x%016x", nonce), w.headerHex(), "0x" + hex.EncodeToString(mix)}, &ok)
	if err != nil {
		log.Printf("BLOCK candidate %d from %s: eth_submitWork error: %v", w.number, who, err)
		w.mu.Lock()
		w.submitted = false // allow another solution for this work
		w.mu.Unlock()
		return
	}
	if ok {
		p.blocksOK.Add(1)
		w.mu.Lock()
		w.found = true
		w.mu.Unlock()
		log.Printf("*** BLOCK FOUND: height %d nonce 0x%016x by %s (accepted by node; it becomes canonical unless another block for the same height wins) ***", w.number, nonce, who)
	} else {
		log.Printf("BLOCK candidate %d nonce 0x%016x by %s rejected by node (stale)", w.number, nonce, who)
	}
}

// ---------------------------------------------------------------- local-node safety (-autostart / -require-peers)

func (p *proxy) setPaused(on bool, why string) {
	was := p.paused.Swap(on)
	p.pauseMsg.Store(why)
	if on && !was {
		log.Printf("PAUSED: %s", why)
	}
	if !on && was {
		log.Printf("resumed: %s", why)
		if w := p.getCurrent(); w != nil {
			p.broadcast(w, true)
		}
	}
}

func (p *proxy) watchNode() {
	if !p.cfg.autostart && !p.cfg.requirePeers {
		return
	}
	if p.cfg.autostart {
		p.setPaused(true, "waiting for the local node to sync before mining")
	}
	var noPeersSince time.Time
	var lastStatus string
	status := func(s string) {
		if s != lastStatus {
			log.Printf("node status: %s", s)
			lastStatus = s
		}
	}
	for ; ; time.Sleep(5 * time.Second) {
		var peersHex string
		if err := p.node.call("net_peerCount", nil, &peersHex); err != nil {
			status("node RPC not reachable yet: " + err.Error())
			continue
		}
		peers, _ := hexUint(peersHex)
		if peers == 0 {
			if noPeersSince.IsZero() {
				noPeersSince = time.Now()
			}
			if time.Since(noPeersSince) > 30*time.Second {
				if p.cfg.autostart {
					p.node.call("miner_stop", nil, nil)
				}
				p.setPaused(true, "node has 0 peers (not mining alone on a private fork)")
			}
			status("0 peers")
			continue
		}
		noPeersSince = time.Time{}
		if !p.cfg.autostart {
			p.setPaused(false, fmt.Sprintf("node has %d peers", peers))
			continue
		}
		var syncing interface{}
		if err := p.node.call("eth_syncing", nil, &syncing); err != nil {
			status("eth_syncing error: " + err.Error())
			continue
		}
		var headHex string
		if err := p.node.call("eth_blockNumber", nil, &headHex); err != nil {
			continue
		}
		head, _ := hexUint(headHex)
		if syncing != false {
			status(fmt.Sprintf("syncing (local head %d, %d peers)", head, peers))
			continue
		}
		if p.ref != nil {
			var refHex string
			if err := p.ref.call("eth_blockNumber", nil, &refHex); err != nil {
				status("reference RPC unreachable, waiting: " + err.Error())
				continue
			}
			ref, _ := hexUint(refHex)
			if head+p.cfg.maxLag < ref || head == 0 {
				status(fmt.Sprintf("catching up: local head %d, network head %d", head, ref))
				continue
			}
			if p.cfg.maxAhead > 0 && head > ref+p.cfg.maxAhead {
				// Our blocks do not reach the network (rejected or not propagated): stop
				// extending what would become a private fork until the network catches up.
				p.setPaused(true, fmt.Sprintf("local head %d is ahead of the network head %d (blocks not propagating)", head, ref))
				status(fmt.Sprintf("ahead of the network: local head %d, network head %d", head, ref))
				continue
			}
		} else if head == 0 {
			status("local head is 0 (not synced)")
			continue
		}
		var mining bool
		if err := p.node.call("eth_mining", nil, &mining); err == nil && !mining {
			// threads=0 means "no CPU threads" (getwork only); a bare miner_start() would use all CPU cores.
			if err := p.node.call("miner_start", []interface{}{0}, nil); err != nil {
				status("miner_start failed (enable the miner API on the local HTTP RPC): " + err.Error())
				continue
			}
			log.Printf("node synced (head %d, %d peers): miner_start OK, rewards go to the node's --miner.etherbase", head, peers)
		}
		status(fmt.Sprintf("synced, head %d, %d peers", head, peers))
		p.setPaused(false, "node synced")
	}
}

// ---------------------------------------------------------------- sessions

type request struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
	Worker string          `json:"worker"`
}

const (
	protoUnknown = iota
	protoEthProxy
	protoEthStratum
)

type session struct {
	p      *proxy
	conn   net.Conn
	ip     string
	wmu    sync.Mutex
	proto  int
	login  string
	worker string
	authed bool

	diff        float64  // requested share difficulty (ethash units)
	sentNHDiff  float64  // EthereumStratum: last difficulty sent to the miner
	shareTarget *big.Int // target the miner currently uses
	tmu         sync.Mutex
	extranonce  string

	ok, bad  int64
	diffSum  float64
	since    time.Time
	lastSubm time.Time
	burst    int
}

func (s *session) name() string {
	n := s.login
	if s.worker != "" {
		n += "/" + s.worker
	}
	if n == "" {
		n = "?"
	}
	return n + "@" + s.ip
}

func (s *session) send(v interface{}) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	s.wmu.Lock()
	defer s.wmu.Unlock()
	s.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err = s.conn.Write(b)
	if err != nil {
		s.conn.Close()
	}
	return err
}

func rawID(id json.RawMessage) json.RawMessage {
	if len(id) == 0 {
		return json.RawMessage("null")
	}
	return id
}

func (s *session) result(id json.RawMessage, v interface{}) error {
	return s.send(map[string]interface{}{"id": rawID(id), "jsonrpc": "2.0", "result": v, "error": nil})
}

func (s *session) fail(id json.RawMessage, code int, msg string) error {
	if s.proto == protoEthStratum {
		return s.send(map[string]interface{}{"id": rawID(id), "result": nil, "error": []interface{}{code, msg, nil}})
	}
	return s.send(map[string]interface{}{"id": rawID(id), "jsonrpc": "2.0", "result": nil, "error": map[string]interface{}{"code": code, "message": msg}})
}

// effectiveDiff returns the share difficulty for work w: never above the block difficulty,
// otherwise the miner would discard block solutions.
func (s *session) effectiveDiff(w *work) float64 {
	d := s.diff
	bd, _ := new(big.Float).SetInt(w.blockDiff).Float64()
	if bd < d {
		d = bd
	}
	if d < 1 {
		d = 1
	}
	return d
}

func ethTarget(diff float64) *big.Int {
	d := new(big.Float).SetFloat64(diff)
	t, _ := new(big.Float).Quo(new(big.Float).SetInt(two256), d).Int(nil)
	if t.Cmp(two256) >= 0 {
		t.Sub(two256, big.NewInt(1))
	}
	return t
}

func nhTarget(nhdiff float64) *big.Int {
	t, _ := new(big.Float).Quo(new(big.Float).SetInt(nhDiff1), new(big.Float).SetFloat64(nhdiff)).Int(nil)
	if t.Cmp(two256) >= 0 {
		t.Sub(two256, big.NewInt(1))
	}
	return t
}

func target32(t *big.Int) string {
	b := make([]byte, 32)
	t.FillBytes(b)
	return "0x" + hex.EncodeToString(b)
}

func (s *session) pushWork(w *work, clean bool) {
	if !s.authed || w == nil {
		return
	}
	switch s.proto {
	case protoEthProxy:
		t := ethTarget(s.effectiveDiff(w))
		s.tmu.Lock()
		s.shareTarget = t
		s.tmu.Unlock()
		s.send(map[string]interface{}{"id": 0, "jsonrpc": "2.0", "result": []string{w.headerHex(), w.seedHex(), target32(t), fmt.Sprintf("0x%x", w.number)}})
	case protoEthStratum:
		nh, _ := strconv.ParseFloat(strconv.FormatFloat(s.effectiveDiff(w)/4295032833.0, 'g', 8, 64), 64)
		s.tmu.Lock()
		changed := nh != s.sentNHDiff
		if changed {
			s.sentNHDiff = nh
			s.shareTarget = nhTarget(nh)
		}
		s.tmu.Unlock()
		if changed {
			s.send(map[string]interface{}{"id": nil, "method": "mining.set_difficulty", "params": []float64{nh}})
		}
		s.send(map[string]interface{}{"id": nil, "method": "mining.notify", "params": []interface{}{
			w.jobID, hex.EncodeToString(w.seed[:]), hex.EncodeToString(w.header[:]), clean || changed}})
	}
}

func parseParams(raw json.RawMessage) []string {
	var arr []interface{}
	if err := json.Unmarshal(raw, &arr); err != nil {
		return nil
	}
	out := make([]string, len(arr))
	for i, v := range arr {
		switch x := v.(type) {
		case string:
			out[i] = x
		case float64:
			out[i] = strconv.FormatFloat(x, 'f', -1, 64)
		case nil:
		default:
			b, _ := json.Marshal(x)
			out[i] = string(b)
		}
	}
	return out
}

// parseLogin handles "0xaddr.worker" and passwords like "x", "d=5000000" or "d=5000000,x".
func (s *session) parseLogin(user, pass, worker string) {
	s.login = user
	if i := strings.IndexAny(user, "./"); i > 0 {
		s.login, s.worker = user[:i], user[i+1:]
	}
	if worker != "" {
		s.worker = worker
	}
	if len(s.login) > 64 {
		s.login = s.login[:64]
	}
	if len(s.worker) > 32 {
		s.worker = s.worker[:32]
	}
	for _, part := range strings.FieldsFunc(pass, func(r rune) bool { return r == ',' || r == ';' || r == ' ' }) {
		if strings.HasPrefix(part, "d=") {
			if d, err := strconv.ParseFloat(part[2:], 64); err == nil && d >= s.p.cfg.minClientDiff && d < 1e18 {
				s.diff = d
			}
		}
	}
}

func (s *session) rateLimited() bool {
	now := time.Now()
	if now.Sub(s.lastSubm) > time.Second {
		s.lastSubm, s.burst = now, 0
	}
	s.burst++
	return s.burst > s.p.cfg.maxSubmits
}

func (s *session) handle(req *request) error {
	p := s.p
	if s.proto == protoUnknown {
		switch {
		case strings.HasPrefix(req.Method, "mining."):
			s.proto = protoEthStratum
		case strings.HasPrefix(req.Method, "eth_"):
			s.proto = protoEthProxy
		}
	}
	params := parseParams(req.Params)
	switch req.Method {
	// ---- ETHPROXY
	case "eth_submitLogin":
		user, pass := "", ""
		if len(params) > 0 {
			user = params[0]
		}
		if len(params) > 1 {
			pass = params[1]
		}
		s.parseLogin(user, pass, req.Worker)
		s.authed = true
		log.Printf("miner connected (ethproxy): %s share-diff %.0f", s.name(), s.diff)
		return s.result(req.ID, true)
	case "eth_getWork":
		if !s.authed {
			return s.fail(req.ID, 25, "Not subscribed / logged in")
		}
		w := p.getCurrent()
		if w == nil {
			return s.fail(req.ID, 0, "Work not ready")
		}
		t := ethTarget(s.effectiveDiff(w))
		s.tmu.Lock()
		s.shareTarget = t
		s.tmu.Unlock()
		return s.result(req.ID, []string{w.headerHex(), w.seedHex(), target32(t), fmt.Sprintf("0x%x", w.number)})
	case "eth_submitWork":
		if !s.authed {
			return s.fail(req.ID, 25, "Not logged in")
		}
		if s.rateLimited() {
			return s.fail(req.ID, 24, "Too many submissions")
		}
		if len(params) < 3 {
			return s.fail(req.ID, 20, "Invalid params")
		}
		nonce, err := hexUint(params[0])
		if err != nil {
			return s.fail(req.ID, 20, "Invalid nonce")
		}
		h, err := parse32(params[1])
		if err != nil {
			return s.fail(req.ID, 20, "Invalid header")
		}
		m, err := parse32(params[2])
		if err != nil {
			return s.fail(req.ID, 20, "Invalid mix digest")
		}
		p.mu.RLock()
		w := p.byHeader[h]
		p.mu.RUnlock()
		var t *big.Int
		if w != nil {
			t = ethTarget(s.effectiveDiff(w))
		}
		r := p.checkShare(w, nonce, m[:], t, s.name())
		s.account(r, w)
		if r == shareDup {
			return s.fail(req.ID, 22, "Duplicate share")
		}
		return s.result(req.ID, r == shareOK)
	case "eth_submitHashrate", "mining.hashrate":
		return s.result(req.ID, true)

	// ---- EthereumStratum/1.0.0
	case "mining.subscribe":
		p.sessMu.Lock()
		p.nextEN = (p.nextEN + 1) & 0xffff
		s.extranonce = fmt.Sprintf("%04x", p.nextEN)
		p.sessMu.Unlock()
		return s.result(req.ID, []interface{}{[]string{"mining.notify", fmt.Sprintf("%016x", time.Now().UnixNano()), "EthereumStratum/1.0.0"}, s.extranonce})
	case "mining.extranonce.subscribe":
		return s.result(req.ID, true)
	case "mining.authorize":
		if s.extranonce == "" {
			return s.fail(req.ID, 25, "Not subscribed")
		}
		user, pass := "", ""
		if len(params) > 0 {
			user = params[0]
		}
		if len(params) > 1 {
			pass = params[1]
		}
		s.parseLogin(user, pass, req.Worker)
		s.authed = true
		log.Printf("miner connected (EthereumStratum/1.0.0): %s share-diff %.0f extranonce %s", s.name(), s.diff, s.extranonce)
		if err := s.result(req.ID, true); err != nil {
			return err
		}
		s.pushWork(p.getCurrent(), true)
		return nil
	case "mining.submit":
		if !s.authed {
			return s.fail(req.ID, 24, "Unauthorized worker")
		}
		if s.rateLimited() {
			return s.fail(req.ID, 24, "Too many submissions")
		}
		if len(params) < 3 {
			return s.fail(req.ID, 20, "Invalid params")
		}
		p.mu.RLock()
		w := p.byJob[params[1]]
		p.mu.RUnlock()
		ns := strings.TrimPrefix(strings.ToLower(params[2]), "0x")
		if len(ns) < 16 {
			ns = s.extranonce + ns
		}
		nonce, err := hexUint(ns)
		if err != nil || len(ns) != 16 {
			return s.fail(req.ID, 20, "Invalid nonce")
		}
		s.tmu.Lock()
		t := s.shareTarget
		s.tmu.Unlock()
		if t == nil && w != nil {
			t = nhTarget(s.effectiveDiff(w) / 4295032833.0)
		}
		r := p.checkShare(w, nonce, nil, t, s.name())
		s.account(r, w)
		switch r {
		case shareOK:
			return s.result(req.ID, true)
		case shareStale:
			return s.fail(req.ID, 21, "Job not found")
		case shareDup:
			return s.fail(req.ID, 22, "Duplicate share")
		case shareLowDiff:
			return s.fail(req.ID, 23, "Low difficulty share")
		default:
			return s.fail(req.ID, 20, r.String())
		}
	}
	if len(req.ID) == 0 || string(req.ID) == "null" { // unknown notification: ignore
		return nil
	}
	return s.fail(req.ID, 20, "Unsupported method: "+req.Method)
}

func (s *session) account(r shareResult, w *work) {
	s.tmu.Lock()
	defer s.tmu.Unlock()
	if r == shareOK {
		s.ok++
		s.p.sharesOK.Add(1)
		if w != nil {
			s.diffSum += s.effectiveDiff(w)
		}
		if s.p.cfg.verbose {
			log.Printf("share accepted from %s (block %d)", s.name(), w.number)
		}
	} else {
		s.bad++
		s.p.sharesBad.Add(1)
		log.Printf("share rejected from %s: %s", s.name(), r)
	}
}

func (p *proxy) serve(c net.Conn) {
	ip, _, _ := net.SplitHostPort(c.RemoteAddr().String())
	p.sessMu.Lock()
	if len(p.sessions) >= p.cfg.maxConns || p.perIP[ip] >= p.cfg.maxConnsPerIP {
		p.sessMu.Unlock()
		c.Close()
		return
	}
	s := &session{p: p, conn: c, ip: ip, diff: p.cfg.shareDiff, since: time.Now()}
	p.sessions[s] = struct{}{}
	p.perIP[ip]++
	p.sessMu.Unlock()
	defer func() {
		c.Close()
		p.sessMu.Lock()
		delete(p.sessions, s)
		if p.perIP[ip]--; p.perIP[ip] <= 0 {
			delete(p.perIP, ip)
		}
		p.sessMu.Unlock()
		if s.authed {
			log.Printf("miner disconnected: %s (accepted %d, rejected %d)", s.name(), s.ok, s.bad)
		}
	}()
	if tc, ok := c.(*net.TCPConn); ok {
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(60 * time.Second)
	}
	r := bufio.NewReaderSize(c, 4096)
	for {
		c.SetReadDeadline(time.Now().Add(10 * time.Minute))
		line, err := r.ReadSlice('\n')
		if err != nil {
			if errors.Is(err, bufio.ErrBufferFull) {
				log.Printf("closing %s: request line too long", ip)
			}
			return
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var req request
		if err := json.Unmarshal(line, &req); err != nil {
			log.Printf("closing %s: malformed JSON", ip)
			return
		}
		if err := s.handle(&req); err != nil {
			return
		}
	}
}

func (p *proxy) stats() {
	for range time.Tick(p.cfg.statsEvery) {
		p.sessMu.Lock()
		var lines []string
		total := 0.0
		for s := range p.sessions {
			if !s.authed {
				continue
			}
			s.tmu.Lock()
			hr := s.diffSum / time.Since(s.since).Seconds()
			ok, bad := s.ok, s.bad
			s.tmu.Unlock()
			total += hr
			lines = append(lines, fmt.Sprintf("%s ~%.2f MH/s (%d ok/%d bad)", s.name(), hr/1e6, ok, bad))
		}
		n := len(p.sessions)
		p.sessMu.Unlock()
		w := p.getCurrent()
		h := uint64(0)
		if w != nil {
			h = w.number
		}
		log.Printf("stats: %d conns, est. %.2f MH/s, shares %d ok / %d bad, block solutions accepted by node %d of %d sent (%d held by the 1-block-per-second timestamp gate), working on %d%s",
			n, total/1e6, p.sharesOK.Load(), p.sharesBad.Load(), p.blocksOK.Load(), p.blocksSent.Load(), p.blocksHeld.Load(), h,
			map[bool]string{true: " (PAUSED: " + fmt.Sprint(p.pauseMsg.Load()) + ")", false: ""}[p.paused.Load()])
		for _, l := range lines {
			log.Printf("  %s", l)
		}
	}
}

func main() {
	var cfg config
	flag.StringVar(&cfg.rpcURL, "rpc", "http://127.0.0.1:8545", "node HTTP JSON-RPC with the eth API (getwork)")
	flag.StringVar(&cfg.listen, "listen", "127.0.0.1:3333", "stratum listen address")
	flag.Float64Var(&cfg.shareDiff, "diff", 100e6, "share difficulty in hashes (capped at the block difficulty); miners may request another with password d=<n>")
	flag.Float64Var(&cfg.minClientDiff, "min-client-diff", 1000, "lowest share difficulty a miner may request via d=<n>")
	flag.DurationVar(&cfg.poll, "poll", 250*time.Millisecond, "eth_getWork poll interval")
	flag.Uint64Var(&cfg.epochLength, "epoch-length", 30000, "ethash epoch length (30000 = plain Ethash)")
	flag.IntVar(&cfg.maxConns, "max-conns", 512, "max concurrent miner connections")
	flag.IntVar(&cfg.maxConnsPerIP, "max-conns-per-ip", 64, "max concurrent connections per IP")
	flag.BoolVar(&cfg.autostart, "autostart", false, "local node mode: miner_start once synced (needs miner API on -rpc), pause without peers")
	flag.StringVar(&cfg.refRPC, "ref-rpc", "", "reference RPC for the network head (with -autostart), e.g. https://scdoscan.io/rpc/0")
	flag.Uint64Var(&cfg.maxLag, "max-lag", 3, "with -ref-rpc: start mining only when the local head is at most this many blocks behind")
	flag.BoolVar(&cfg.requirePeers, "require-peers", false, "stop serving work when the node has 0 peers for 30 s (implied by -autostart)")
	flag.DurationVar(&cfg.statsEvery, "stats", time.Minute, "stats log interval")
	flag.BoolVar(&cfg.verbose, "v", false, "log every share and work update")
	flag.IntVar(&cfg.verifyThreads, "verify-threads", max(1, runtime.NumCPU()/2), "max concurrent share verifications (bounds CPU use)")
	flag.IntVar(&cfg.maxSubmits, "max-submits", 200, "max share submissions per second per connection")
	flag.Uint64Var(&cfg.maxAhead, "max-ahead", 30, "with -ref-rpc and -autostart: pause when the local head is more than this many blocks ahead of the network (0 = off)")
	flag.StringVar(&cfg.logFile, "log", "", "also append the log to this file")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	log.SetFlags(log.LstdFlags)
	log.SetOutput(os.Stdout)
	if cfg.logFile != "" {
		f, err := os.OpenFile(cfg.logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			log.Fatalf("log file %s: %v", cfg.logFile, err)
		}
		log.SetOutput(io.MultiWriter(os.Stdout, f))
	}
	p := newProxy(cfg)
	ln, err := net.Listen("tcp", cfg.listen)
	if err != nil {
		log.Fatalf("listen %s: %v", cfg.listen, err)
	}
	log.Printf("%s listening on %s (stratum: ethproxy + EthereumStratum/1.0.0), node %s, share diff %.0f", version, cfg.listen, cfg.rpcURL, cfg.shareDiff)
	go p.watchNode()
	go p.pollWork()
	go p.stats()
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go p.serve(c)
	}
}
