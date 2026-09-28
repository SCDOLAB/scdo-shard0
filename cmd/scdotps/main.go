// scdotps: stepped native-transfer load generator for SCDO shard0 (test use only).
// Reads a hex private key from -key (never printed), sends 1-wei self-transfers at rising rates
// via eth_sendRawTransaction to -rpc, logs per-step send stats as JSON lines.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

var rpcURL string
var client = &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{MaxIdleConnsPerHost: 64}}

func call(method string, params ...interface{}) (json.RawMessage, error) {
	b, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	r, err := client.Post(rpcURL, "application/json", bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	var out struct {
		Result json.RawMessage
		Error  *struct{ Message string }
	}
	if err := json.NewDecoder(r.Body).Decode(&out); err != nil {
		return nil, err
	}
	if out.Error != nil {
		return nil, fmt.Errorf("%s", out.Error.Message)
	}
	return out.Result, nil
}

func hexU(method string, params ...interface{}) uint64 {
	r, err := call(method, params...)
	if err != nil {
		panic(err)
	}
	var s string
	json.Unmarshal(r, &s)
	v, _ := hexutil.DecodeUint64(s)
	return v
}

func logj(m map[string]interface{}) {
	m["t"] = time.Now().Unix()
	b, _ := json.Marshal(m)
	fmt.Println(string(b))
}

func main() {
	keyf := flag.String("key", "", "hex private key file")
	flag.StringVar(&rpcURL, "rpc", "http://127.0.0.1:8050", "rpc")
	steps := flag.String("steps", "10:60,50:60,100:60,200:30", "rate:seconds,...")
	tipGwei := flag.Float64("tip", 0.01, "priority fee gwei")
	maxErr := flag.Float64("maxerr", 0.2, "abort if step error ratio exceeds")
	maxBacklog := flag.Uint64("maxbacklog", 4000, "abort if sent-but-unmined exceeds")
	workers := flag.Int("workers", 32, "concurrent senders")
	flag.Parse()
	kb, err := os.ReadFile(*keyf)
	if err != nil {
		panic(err)
	}
	key, err := crypto.HexToECDSA(strings.TrimPrefix(strings.TrimSpace(string(kb)), "0x"))
	if err != nil {
		panic("bad key")
	}
	from := crypto.PubkeyToAddress(key.PublicKey)
	chainID := new(big.Int).SetUint64(hexU("eth_chainId"))
	signer := types.LatestSignerForChainID(chainID)
	nonce := hexU("eth_getTransactionCount", from.Hex(), "pending")
	startNonce := nonce
	tip := new(big.Int).SetUint64(uint64(*tipGwei * 1e9))
	maxFee := new(big.Int).SetUint64(2e9) // 2 gwei cap
	logj(map[string]interface{}{"ev": "start", "from": from.Hex(), "chainId": chainID, "nonce": nonce, "head": hexU("eth_blockNumber")})

	type job struct{ raw string }
	jobs := make(chan job, 100000)
	var sent, errs, lat int64
	var lastErr atomic.Value
	var wg sync.WaitGroup
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				t0 := time.Now()
				_, err := call("eth_sendRawTransaction", j.raw)
				atomic.AddInt64(&lat, int64(time.Since(t0)/time.Microsecond))
				if err != nil {
					atomic.AddInt64(&errs, 1)
					lastErr.Store(err.Error())
				} else {
					atomic.AddInt64(&sent, 1)
				}
			}
		}()
	}
	aborted := ""
	for _, st := range strings.Split(*steps, ",") {
		p := strings.Split(st, ":")
		rate, _ := strconv.Atoi(p[0])
		secs, _ := strconv.Atoi(p[1])
		s0, e0, l0 := atomic.LoadInt64(&sent), atomic.LoadInt64(&errs), atomic.LoadInt64(&lat)
		head0 := hexU("eth_blockNumber")
		logj(map[string]interface{}{"ev": "step_start", "rate": rate, "secs": secs, "head": head0, "nonce": nonce})
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(secs)*time.Second)
		tick := time.NewTicker(time.Second / time.Duration(rate))
		gen := 0
	loop:
		for {
			select {
			case <-ctx.Done():
				break loop
			case <-tick.C:
				tx := types.NewTx(&types.DynamicFeeTx{ChainID: chainID, Nonce: nonce, GasTipCap: tip, GasFeeCap: maxFee, Gas: 21000, To: &from, Value: big.NewInt(1)})
				stx, err := types.SignTx(tx, signer, key)
				if err != nil {
					panic(err)
				}
				b, _ := stx.MarshalBinary()
				jobs <- job{hexutil.Encode(b)}
				nonce++
				gen++
				if gen%rate == 0 { // once per second: health checks
					se, ee := atomic.LoadInt64(&sent)-s0, atomic.LoadInt64(&errs)-e0
					if se+ee > 20 && float64(ee)/float64(se+ee) > *maxErr {
						aborted = fmt.Sprintf("error ratio %d/%d at rate %d: %v", ee, se+ee, rate, lastErr.Load())
						break loop
					}
					mined := hexU("eth_getTransactionCount", from.Hex(), "latest")
					if nonce-mined > *maxBacklog {
						aborted = fmt.Sprintf("backlog %d > %d at rate %d", nonce-mined, *maxBacklog, rate)
						break loop
					}
				}
			}
		}
		tick.Stop()
		cancel()
		for len(jobs) > 0 {
			time.Sleep(50 * time.Millisecond)
		}
		time.Sleep(300 * time.Millisecond)
		se, ee, le := atomic.LoadInt64(&sent)-s0, atomic.LoadInt64(&errs)-e0, atomic.LoadInt64(&lat)-l0
		avg := 0.0
		if se+ee > 0 {
			avg = float64(le) / float64(se+ee) / 1000
		}
		logj(map[string]interface{}{"ev": "step_end", "rate": rate, "generated": gen, "accepted": se, "errors": ee, "avg_rpc_ms": avg, "last_err": lastErr.Load(), "head": hexU("eth_blockNumber"), "nonce": nonce, "mined_nonce": hexU("eth_getTransactionCount", from.Hex(), "latest")})
		if aborted != "" {
			break
		}
	}
	close(jobs)
	wg.Wait()
	if aborted != "" {
		logj(map[string]interface{}{"ev": "aborted", "why": aborted})
	}
	// drain: wait until everything accepted is mined (or 6 min)
	deadline := time.Now().Add(6 * time.Minute)
	for time.Now().Before(deadline) {
		mined := hexU("eth_getTransactionCount", from.Hex(), "latest")
		pend := hexU("eth_getTransactionCount", from.Hex(), "pending")
		if mined >= pend {
			break
		}
		time.Sleep(3 * time.Second)
	}
	logj(map[string]interface{}{"ev": "done", "startNonce": startNonce, "endNonce": nonce, "mined_nonce": hexU("eth_getTransactionCount", from.Hex(), "latest"), "pending_nonce": hexU("eth_getTransactionCount", from.Hex(), "pending"), "head": hexU("eth_blockNumber")})
}
