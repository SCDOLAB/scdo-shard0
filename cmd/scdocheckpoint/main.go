// scdocheckpoint: SCDO shard0 checkpoint signer / verifier (9Y9 PTY LTD).
//
//	scdocheckpoint genkey -out signer.key                 (throwaway/test key, prints address)
//	scdocheckpoint sign   -key signer.key -rpc URL[,URL] -every 100 -depth 12 -out cp.json [-push URL,...] [-loop 5s]
//	scdocheckpoint signraw -key k -chainid N -number N -hash 0x.. -out cp.json   (tests: forge/tamper)
//	scdocheckpoint verify -file cp.json -signers 0x..,0x.. -threshold 1 -chainid 5680
//
// "sign" only signs a block that every -rpc node reports with the same hash at
// (head - depth) rounded down to a multiple of -every.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/crypto"
)

func die(f string, a ...interface{}) { fmt.Fprintf(os.Stderr, f+"\n", a...); os.Exit(1) }

func rpc(url, method string, params []interface{}, out interface{}) error {
	if params == nil {
		params = []interface{}{}
	}
	body, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var r struct {
		Result json.RawMessage           `json:"result"`
		Error  *struct{ Message string } `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return err
	}
	if r.Error != nil {
		return fmt.Errorf("%s", r.Error.Message)
	}
	return json.Unmarshal(r.Result, out)
}

func writeAtomic(path string, v interface{}) {
	b, _ := json.MarshalIndent(v, "", "  ")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		die("write: %v", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		die("rename: %v", err)
	}
}

func signCP(keyfile string, cp *core.SCDOCheckpoint) {
	key, err := crypto.LoadECDSA(keyfile)
	if err != nil {
		die("load key: %v", err)
	}
	cp.Version = 1
	cp.Timestamp = uint64(time.Now().Unix())
	cp.Message = cp.SigningMessage()
	if err := core.SignSCDOCheckpoint(cp, func(h []byte) ([]byte, error) { return crypto.Sign(h, key) }); err != nil {
		die("sign: %v", err)
	}
	cp.Signers = []common.Address{crypto.PubkeyToAddress(key.PublicKey)}
}

func main() {
	if len(os.Args) < 2 {
		die("usage: scdocheckpoint genkey|sign|signraw|verify ...")
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	out := fs.String("out", "", "output file")
	keyf := fs.String("key", "", "signer key file (hex)")
	rpcs := fs.String("rpc", "http://127.0.0.1:8545", "comma-separated trusted node RPC URLs (all must agree)")
	every := fs.Uint64("every", 100, "checkpoint interval (blocks)")
	depth := fs.Uint64("depth", 12, "confirmation depth before signing")
	push := fs.String("push", "", "comma-separated node RPC URLs to push scdo_submitCheckpoint to")
	loop := fs.Duration("loop", 0, "repeat every interval (0 = once)")
	chainid := fs.Uint64("chainid", 0, "chain id")
	number := fs.Uint64("number", 0, "block number")
	hash := fs.String("hash", "", "block hash")
	file := fs.String("file", "", "checkpoint file")
	signers := fs.String("signers", "", "authorised signer addresses")
	threshold := fs.Int("threshold", 1, "signature threshold")
	serve := fs.String("serve", "", "sign: also serve the -out directory read-only over HTTP on this address (e.g. 0.0.0.0:18590)")
	fs.Parse(os.Args[2:])

	switch os.Args[1] {
	case "genkey":
		key, _ := crypto.GenerateKey()
		if *out == "" {
			die("-out required")
		}
		if err := crypto.SaveECDSA(*out, key); err != nil {
			die("save: %v", err)
		}
		os.Chmod(*out, 0o600)
		fmt.Println(crypto.PubkeyToAddress(key.PublicKey).Hex())
	case "signraw":
		cp := &core.SCDOCheckpoint{ChainID: *chainid, Number: *number, Hash: common.HexToHash(*hash)}
		signCP(*keyf, cp)
		writeAtomic(*out, cp)
	case "verify":
		b, err := os.ReadFile(*file)
		if err != nil {
			die("%v", err)
		}
		var cp core.SCDOCheckpoint
		if err := json.Unmarshal(b, &cp); err != nil {
			die("%v", err)
		}
		pol := &core.SCDOCheckpointPolicy{ChainID: *chainid, Threshold: *threshold}
		for _, a := range strings.Split(*signers, ",") {
			pol.Signers = append(pol.Signers, common.HexToAddress(strings.TrimSpace(a)))
		}
		who, err := pol.Verify(&cp)
		if err != nil {
			die("INVALID: %v", err)
		}
		fmt.Printf("VALID number=%d hash=%s signers=%v\n", cp.Number, cp.Hash.Hex(), who)
	case "sign":
		urls := strings.Split(*rpcs, ",")
		if *serve != "" {
			dir := filepath.Dir(*out)
			fsrv := http.FileServer(http.Dir(dir))
			mux := http.NewServeMux()
			mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet && r.Method != http.MethodHead {
					http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
					return
				}
				if !strings.HasSuffix(r.URL.Path, ".json") {
					http.NotFound(w, r)
					return
				}
				w.Header().Set("Cache-Control", "no-cache")
				w.Header().Set("Access-Control-Allow-Origin", "*")
				fsrv.ServeHTTP(w, r)
			})
			srv := &http.Server{Addr: *serve, Handler: mux, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second}
			go func() { die("serve: %v", srv.ListenAndServe()) }()
		}
		var last uint64
		if b, err := os.ReadFile(*out); err == nil {
			var prev core.SCDOCheckpoint
			if json.Unmarshal(b, &prev) == nil {
				last = prev.Number
			}
		}
		for {
			var head hexutil.Uint64
			var cid hexutil.Big
			err := rpc(urls[0], "eth_blockNumber", nil, &head)
			if err == nil {
				err = rpc(urls[0], "eth_chainId", nil, &cid)
			}
			if err != nil {
				fmt.Fprintln(os.Stderr, "rpc:", err)
			} else if uint64(head) > *depth {
				target := (uint64(head) - *depth) / *every * *every
				if target > last && target > 0 {
					var agreed common.Hash
					ok := true
					for _, u := range urls {
						var blk struct{ Hash common.Hash }
						if err := rpc(u, "eth_getBlockByNumber", []interface{}{hexutil.EncodeUint64(target), false}, &blk); err != nil {
							fmt.Fprintln(os.Stderr, "rpc:", u, err)
							ok = false
							break
						}
						if agreed == (common.Hash{}) {
							agreed = blk.Hash
						} else if agreed != blk.Hash {
							fmt.Fprintf(os.Stderr, "nodes disagree at %d: %s vs %s; not signing\n", target, agreed.Hex(), blk.Hash.Hex())
							ok = false
							break
						}
					}
					if ok {
						cp := &core.SCDOCheckpoint{ChainID: (*big.Int)(&cid).Uint64(), Number: target, Hash: agreed}
						signCP(*keyf, cp)
						writeAtomic(*out, cp)
						writeAtomic(filepath.Join(filepath.Dir(*out), fmt.Sprintf("checkpoint-%d.json", target)), cp)
						last = target
						fmt.Printf("%s signed checkpoint number=%d hash=%s\n", time.Now().Format(time.RFC3339), target, agreed.Hex())
						for _, p := range strings.Split(*push, ",") {
							if p = strings.TrimSpace(p); p != "" {
								var res map[string]interface{}
								if err := rpc(p, "scdo_submitCheckpoint", []interface{}{cp}, &res); err != nil {
									fmt.Fprintln(os.Stderr, "push:", p, err)
								}
							}
						}
					}
				}
			}
			if *loop == 0 {
				return
			}
			time.Sleep(*loop)
		}
	default:
		die("unknown command %s", os.Args[1])
	}
}
