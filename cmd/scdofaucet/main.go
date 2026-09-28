// scdo-faucet: shard0 faucet for SCDO core-geth chain (chainId read from node, 5680).
// GET /faucet?addr=0x... -> sends a real signed 0.01 SCDO legacy tx from the faucet key.
// Rate limit: 1 claim per address per 24h, 1 per client IP per hour (same as old parallel-node faucet).
package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

var (
	faucetWei = big.NewInt(1e16) // 0.01 SCDO
	gasPrice  = big.NewInt(10e9) // 10 gwei, same as wallet
)

const (
	addrWindow = 24 * time.Hour
	ipWindow   = time.Hour
)

type limits struct {
	mu   sync.Mutex
	path string
	Addr map[string]int64 `json:"addr"`
	IP   map[string]int64 `json:"ip"`
}

func loadLimits(p string) *limits {
	l := &limits{path: p, Addr: map[string]int64{}, IP: map[string]int64{}}
	if b, err := os.ReadFile(p); err == nil {
		json.Unmarshal(b, l)
	}
	if l.Addr == nil {
		l.Addr = map[string]int64{}
	}
	if l.IP == nil {
		l.IP = map[string]int64{}
	}
	return l
}

func (l *limits) check(a, ip string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	var w time.Duration
	if t, ok := l.Addr[a]; ok {
		if d := time.Unix(t, 0).Add(addrWindow).Sub(now); d > w {
			w = d
		}
	}
	if t, ok := l.IP[ip]; ok {
		if d := time.Unix(t, 0).Add(ipWindow).Sub(now); d > w {
			w = d
		}
	}
	return w
}

func (l *limits) record(a, ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.Addr[a], l.IP[ip] = now.Unix(), now.Unix()
	for k, t := range l.Addr {
		if now.Sub(time.Unix(t, 0)) > addrWindow {
			delete(l.Addr, k)
		}
	}
	for k, t := range l.IP {
		if now.Sub(time.Unix(t, 0)) > ipWindow {
			delete(l.IP, k)
		}
	}
	if b, err := json.Marshal(l); err == nil {
		os.WriteFile(l.path+".tmp", b, 0600)
		os.Rename(l.path+".tmp", l.path)
	}
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		if x := strings.TrimSpace(r.Header.Get("X-Real-IP")); x != "" {
			return x
		}
		if x := r.Header.Get("X-Forwarded-For"); x != "" {
			return strings.TrimSpace(strings.Split(x, ",")[0])
		}
	}
	return host
}

func reply(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func main() {
	keyPath := flag.String("key", "/opt/scdo-faucet/key", "hex private key file (0600)")
	rpc := flag.String("rpc", "http://127.0.0.1:8050", "geth RPC")
	listen := flag.String("listen", "127.0.0.1:8051", "listen addr")
	limPath := flag.String("limits", "/opt/scdo-faucet/limits.json", "rate-limit state")
	genkey := flag.Bool("genkey", false, "generate a new key at -key (refuses to overwrite) and print its address")
	flag.Parse()

	if *genkey {
		if _, err := os.Stat(*keyPath); err == nil {
			log.Fatal("key file exists, refusing to overwrite")
		}
		k, _ := crypto.GenerateKey()
		if err := crypto.SaveECDSA(*keyPath, k); err != nil {
			log.Fatal(err)
		}
		os.Chmod(*keyPath, 0600)
		fmt.Println(crypto.PubkeyToAddress(k.PublicKey).Hex())
		return
	}
	var key *ecdsa.PrivateKey
	key, err := crypto.LoadECDSA(*keyPath)
	if err != nil {
		log.Fatal("load key: ", err)
	}
	from := crypto.PubkeyToAddress(key.PublicKey)
	cl, err := ethclient.Dial(*rpc)
	if err != nil {
		log.Fatal(err)
	}
	lim := loadLimits(*limPath)
	var chainID *big.Int
	for {
		ctx, c := context.WithTimeout(context.Background(), 10*time.Second)
		chainID, err = cl.ChainID(ctx)
		c()
		if err == nil {
			break
		}
		log.Printf("waiting for node: %v", err)
		time.Sleep(5 * time.Second)
	}
	signer := types.NewEIP155Signer(chainID)
	var sendMu sync.Mutex

	h := func(w http.ResponseWriter, r *http.Request) {
		a := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("addr")))
		if len(a) != 42 || !strings.HasPrefix(a, "0x") || !common.IsHexAddress(a) {
			reply(w, 400, map[string]string{"error": "invalid addr (expected 0x + 40 hex chars)"})
			return
		}
		ip := clientIP(r)
		if wait := lim.check(a, ip); wait > 0 {
			reply(w, 429, map[string]interface{}{"error": "rate limited: faucet allows 1 claim per address per 24h and per IP per hour", "retryAfterSec": int(wait.Seconds())})
			return
		}
		to := common.HexToAddress(a)
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		sendMu.Lock()
		nonce, err := cl.PendingNonceAt(ctx, from)
		if err != nil {
			sendMu.Unlock()
			reply(w, 503, map[string]string{"error": "faucet node unavailable"})
			return
		}
		tx, _ := types.SignTx(types.NewTransaction(nonce, to, faucetWei, 21000, gasPrice, nil), signer, key)
		err = cl.SendTransaction(ctx, tx)
		sendMu.Unlock()
		if err != nil {
			log.Printf("send to %s failed: %v", a, err)
			reply(w, 503, map[string]string{"error": "faucet send failed: " + err.Error()})
			return
		}
		lim.record(a, ip)
		bal, _ := cl.BalanceAt(ctx, to, nil)
		if bal == nil {
			bal = new(big.Int)
		}
		exp := new(big.Int).Add(bal, faucetWei) // balance once the tx is mined
		log.Printf("sent %s -> %s tx %s", faucetWei, a, tx.Hash().Hex())
		reply(w, 200, map[string]interface{}{"status": "ok", "addr": a, "native": exp.String(), "nativeAdded": faucetWei.String(),
			"decimals": 18, "erc20": "0", "txHash": tx.Hash().Hex(), "pending": true,
			"explorer": "https://scdoscan.io/#/tx?txhash=" + tx.Hash().Hex()})
	}
	http.HandleFunc("/faucet", h)
	http.HandleFunc("/", h)
	log.Printf("scdo-faucet %s on %s (rpc %s, chainId %s)", from.Hex(), *listen, *rpc, chainID)
	log.Fatal(http.ListenAndServe(*listen, nil))
}
