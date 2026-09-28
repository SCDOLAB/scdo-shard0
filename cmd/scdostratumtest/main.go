// scdostratumtest: CPU test client for scdostratum (ethproxy or EthereumStratum/1.0.0).
// It mines real Ethash shares on the CPU with the light cache (slow, test only) and can
// also send deliberately bad submissions to check that the proxy rejects them.
package main

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/consensus/ethash"
)

var nhDiff1 = new(big.Int).Lsh(big.NewInt(0xffff), 208)

type job struct {
	id     string
	header []byte
	seed   []byte
	target *big.Int
	number uint64
}

type client struct {
	conn    net.Conn
	wmu     sync.Mutex
	proto   string
	nextID  atomic.Int64
	pending sync.Map // id -> label
	en      string   // extranonce (ethstratum)

	jmu    sync.Mutex
	cur    *job
	nhDiff float64
	gen    atomic.Int64

	ok, bad, blocks atomic.Int64
	rejects         sync.Map
}

func (c *client) send(label, method string, params interface{}, extra map[string]interface{}) int64 {
	id := c.nextID.Add(1)
	m := map[string]interface{}{"id": id, "method": method, "params": params}
	if c.proto == "ethproxy" {
		m["jsonrpc"] = "2.0"
	}
	for k, v := range extra {
		m[k] = v
	}
	b, _ := json.Marshal(m)
	c.pending.Store(id, label)
	c.wmu.Lock()
	c.conn.Write(append(b, '\n'))
	c.wmu.Unlock()
	return id
}

func trim0x(s string) string { return strings.TrimPrefix(s, "0x") }

func (c *client) setJob(id, header, seed string, target *big.Int, num uint64) {
	h, _ := hex.DecodeString(trim0x(header))
	sd, _ := hex.DecodeString(trim0x(seed))
	c.jmu.Lock()
	if c.cur == nil || !strings.EqualFold(hex.EncodeToString(c.cur.header), hex.EncodeToString(h)) || c.cur.target.Cmp(target) != 0 {
		c.cur = &job{id: id, header: h, seed: sd, target: target, number: num}
		c.gen.Add(1)
	}
	c.jmu.Unlock()
}

func (c *client) reader() {
	r := bufio.NewReader(c.conn)
	for {
		line, err := r.ReadBytes('\n')
		if err != nil {
			log.Fatalf("connection closed: %v", err)
		}
		var m struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
			Result json.RawMessage `json:"result"`
			Error  json.RawMessage `json:"error"`
		}
		if err := json.Unmarshal(line, &m); err != nil {
			log.Printf("bad line: %s", line)
			continue
		}
		switch {
		case m.Method == "mining.set_difficulty":
			var p []float64
			json.Unmarshal(m.Params, &p)
			c.jmu.Lock()
			c.nhDiff = p[0]
			c.jmu.Unlock()
			log.Printf("<- set_difficulty %g", p[0])
		case m.Method == "mining.notify":
			var p []interface{}
			json.Unmarshal(m.Params, &p)
			c.jmu.Lock()
			d := c.nhDiff
			c.jmu.Unlock()
			t, _ := new(big.Float).Quo(new(big.Float).SetInt(nhDiff1), big.NewFloat(d)).Int(nil)
			c.setJob(p[0].(string), p[2].(string), p[1].(string), t, 0)
		case string(m.ID) == "0" && m.Result != nil: // ethproxy push
			var p []string
			json.Unmarshal(m.Result, &p)
			c.handleWork(p)
		default:
			var id int64
			json.Unmarshal(m.ID, &id)
			lv, _ := c.pending.LoadAndDelete(id)
			label, _ := lv.(string)
			if label == "subscribe" {
				var r []json.RawMessage
				if json.Unmarshal(m.Result, &r) == nil && len(r) >= 2 {
					var en string
					json.Unmarshal(r[1], &en)
					c.jmu.Lock()
					c.en = en
					c.jmu.Unlock()
				}
				log.Printf("<- subscribe: %s", strings.TrimSpace(string(line)))
				continue
			}
			if label == "getwork" {
				var p []string
				if json.Unmarshal(m.Result, &p) == nil {
					c.handleWork(p)
				} else {
					log.Printf("getwork: %s", line)
				}
				continue
			}
			okRes := string(m.Result) == "true"
			if strings.HasPrefix(label, "share") {
				if okRes {
					c.ok.Add(1)
				} else {
					c.bad.Add(1)
				}
			}
			if strings.HasPrefix(label, "block") && okRes {
				c.blocks.Add(1)
			}
			if strings.HasPrefix(label, "neg:") {
				c.rejects.Store(label, strings.TrimSpace(string(line)))
			}
			log.Printf("<- %s: %s", label, strings.TrimSpace(string(line)))
		}
	}
}

func (c *client) handleWork(p []string) {
	if len(p) < 3 {
		return
	}
	t, _ := new(big.Int).SetString(trim0x(p[2]), 16)
	var num uint64
	if len(p) > 3 {
		fmt.Sscanf(trim0x(p[3]), "%x", &num)
	}
	c.setJob("", p[0], p[1], t, num)
}

func main() {
	addr := flag.String("addr", "127.0.0.1:3333", "proxy address")
	proto := flag.String("proto", "ethproxy", "ethproxy | ethstratum")
	user := flag.String("user", "0x0000000000000000000000000000000000000000.cputest", "login")
	pass := flag.String("pass", "x", "password (d=<n> requests share difficulty)")
	threads := flag.Int("threads", 4, "CPU threads")
	dur := flag.Duration("duration", 2*time.Minute, "run time")
	wantShares := flag.Int64("shares", 0, "stop after this many accepted shares (0 = run for -duration)")
	wantBlocks := flag.Int64("blocks", 0, "stop after this many shares that met the block target (0 = ignore)")
	epochLen := flag.Uint64("epoch-length", 30000, "epoch length")
	negative := flag.Bool("negative", false, "also send invalid/duplicate/stale/bad-mix submissions")
	full := flag.Bool("full", false, "generate the full ~1 GB DAG for much faster CPU hashing")
	flag.Parse()
	log.SetOutput(os.Stdout)

	conn, err := net.Dial("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	c := &client{conn: conn, proto: *proto}
	go c.reader()
	if *proto == "ethproxy" {
		c.send("login", "eth_submitLogin", []string{*user, *pass}, map[string]interface{}{"worker": "cpu"})
		c.send("getwork", "eth_getWork", []string{}, nil)
	} else {
		c.send("subscribe", "mining.subscribe", []string{"scdostratumtest/1.0", "EthereumStratum/1.0.0"}, nil)
		for i := 0; ; i++ {
			c.jmu.Lock()
			en := c.en
			c.jmu.Unlock()
			if en != "" {
				break
			}
			if i > 100 {
				log.Fatal("no extranonce from mining.subscribe")
			}
			time.Sleep(100 * time.Millisecond)
		}
		c.send("authorize", "mining.authorize", []string{*user, *pass}, nil)
	}
	// wait for a job
	deadline := time.Now().Add(60 * time.Second)
	for {
		c.jmu.Lock()
		j := c.cur
		c.jmu.Unlock()
		if j != nil {
			break
		}
		if time.Now().After(deadline) {
			log.Fatal("no job received within 60 s")
		}
		if *proto == "ethproxy" {
			c.send("getwork", "eth_getWork", []string{}, nil)
		}
		time.Sleep(time.Second)
	}

	type hasher interface {
		Hashimoto(h []byte, n uint64) ([]byte, []byte)
	}
	fulls := map[uint64]hasher{}
	caches := map[uint64]*ethash.LightCache{}
	var cmu sync.Mutex
	cacheFor := func(j *job) *ethash.LightCache {
		cmu.Lock()
		defer cmu.Unlock()
		epoch := j.number / *epochLen
		if j.number == 0 { // ethstratum: derive epoch from seed
			for e := uint64(0); e < 2048; e++ {
				if hex.EncodeToString(ethash.SeedHashFor(e, *epochLen)) == hex.EncodeToString(j.seed) {
					epoch = e
					break
				}
			}
		}
		if cc, ok := caches[epoch]; ok {
			return cc
		}
		log.Printf("generating light cache for epoch %d", epoch)
		cc := ethash.NewLightCache(epoch, *epochLen)
		caches[epoch] = cc
		return cc
	}

	var fmu sync.Mutex
	hasherFor := func(j *job) hasher {
		lc := cacheFor(j)
		if !*full {
			return lc
		}
		fmu.Lock()
		defer fmu.Unlock()
		if f, ok := fulls[lc.Epoch]; ok {
			return f
		}
		log.Printf("generating full DAG for epoch %d (slow)", lc.Epoch)
		t0 := time.Now()
		f := lc.NewFullDataset()
		log.Printf("full DAG ready in %s", time.Since(t0).Round(time.Second))
		fulls[lc.Epoch] = f
		return f
	}

	submit := func(label string, j *job, nonce uint64, mix []byte) {
		if *proto == "ethproxy" {
			c.send(label, "eth_submitWork", []string{fmt.Sprintf("0x%016x", nonce), "0x" + hex.EncodeToString(j.header), "0x" + hex.EncodeToString(mix)}, map[string]interface{}{"worker": "cpu"})
		} else {
			full := fmt.Sprintf("%016x", nonce)
			c.send(label, "mining.submit", []string{*user, j.id, full[len(c.en):]}, nil)
		}
	}

	var hashes atomic.Int64
	start := time.Now()
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var enPrefix uint64
	var enBits uint
	if *proto == "ethstratum" {
		// extranonce is set by the subscribe reply; learn it from the pending map fallback
		enBits = uint(len(c.en) * 4)
		if c.en != "" {
			fmt.Sscanf(c.en, "%x", &enPrefix)
		}
	}
	for t := 0; t < *threads; t++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var rb [8]byte
			rand.Read(rb[:])
			nonce := binary.BigEndian.Uint64(rb[:])
			if enBits > 0 {
				nonce = enPrefix<<(64-enBits) | nonce>>enBits
			}
			for {
				select {
				case <-stop:
					return
				default:
				}
				c.jmu.Lock()
				j := c.cur
				c.jmu.Unlock()
				cache := hasherFor(j)
				g := c.gen.Load()
				for i := 0; i < 2000 && c.gen.Load() == g; i++ {
					nonce++
					mix, res := cache.Hashimoto(j.header, nonce)
					hashes.Add(1)
					if new(big.Int).SetBytes(res).Cmp(j.target) <= 0 {
						log.Printf("-> share nonce 0x%016x job %s (header %x…)", nonce, j.id, j.header[:6])
						submit("share", j, nonce, mix)
					}
				}
			}
		}()
	}
	if *negative {
		go func() {
			time.Sleep(3 * time.Second)
			c.jmu.Lock()
			j := c.cur
			c.jmu.Unlock()
			cache := cacheFor(j)
			// 1. random nonce: almost surely above the share target
			submit("neg:lowdiff", j, 0x1234567812345678, make([]byte, 32))
			// 2. unknown job / header
			bogus := &job{id: "deadbeefdeadbeef", header: make([]byte, 32), target: j.target, number: j.number}
			submit("neg:stale", bogus, 42, make([]byte, 32))
			// 3. bad mix digest (ethproxy only) for a nonce that we have not submitted
			if *proto == "ethproxy" {
				submit("neg:badmix", j, 0x0badbadbadbad0, []byte(strings.Repeat("\x01", 32)))
			}
			// 4. find one real share and submit it twice (duplicate)
			for n := uint64(0x7700000000000000); ; n++ {
				if *proto == "ethstratum" {
					n = enPrefix<<(64-enBits) | (n & (1<<(64-enBits) - 1))
				}
				mix, res := cache.Hashimoto(j.header, n)
				if new(big.Int).SetBytes(res).Cmp(j.target) <= 0 {
					submit("share(dup-1)", j, n, mix)
					time.Sleep(500 * time.Millisecond)
					submit("neg:duplicate", j, n, mix)
					return
				}
			}
		}()
	}
	tick := time.NewTicker(10 * time.Second)
	end := time.After(*dur)
loop:
	for {
		select {
		case <-tick.C:
			log.Printf("hashrate %.1f kH/s, shares ok %d bad %d", float64(hashes.Load())/time.Since(start).Seconds()/1e3, c.ok.Load(), c.bad.Load())
			if *wantShares > 0 && c.ok.Load() >= *wantShares {
				break loop
			}
		case <-end:
			break loop
		}
	}
	close(stop)
	wg.Wait()
	time.Sleep(time.Second)
	fmt.Printf("RESULT proto=%s accepted=%d rejected=%d hashes=%d elapsed=%s\n", *proto, c.ok.Load(), c.bad.Load(), hashes.Load(), time.Since(start).Round(time.Second))
	c.rejects.Range(func(k, v interface{}) bool { fmt.Printf("NEG %s => %s\n", k, v); return true })
	_ = wantBlocks
}
