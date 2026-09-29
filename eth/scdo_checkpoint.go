// Copyright 2026 9Y9 PTY LTD (SCDO shard0). LGPL-3.0, same as go-ethereum.
//
// Distribution of SCDO signed checkpoints: poll one or more HTTPS/JSON (or
// file://) sources, and accept pushes over RPC (scdo_submitCheckpoint). Every
// checkpoint is verified against the configured signer list, so a source or
// relay never needs to be trusted; any node can mirror the latest checkpoint.

package eth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/log"
)

const scdoCheckpointMaxBody = 64 * 1024

type scdoCheckpointService struct {
	eth      *Ethereum
	urls     []string
	interval time.Duration
	client   *http.Client
	quit     chan struct{}
	wg       sync.WaitGroup

	mu        sync.Mutex
	lastFetch time.Time
	lastError string
	accepted  uint64
	invalid   uint64
}

func newSCDOCheckpointService(eth *Ethereum, urls []string, interval time.Duration) *scdoCheckpointService {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	return &scdoCheckpointService{
		eth: eth, urls: urls, interval: interval,
		client: &http.Client{Timeout: 10 * time.Second},
		quit:   make(chan struct{}),
	}
}

func (s *scdoCheckpointService) start() {
	s.wg.Add(1)
	go s.loop()
}

func (s *scdoCheckpointService) stop() {
	close(s.quit)
	s.wg.Wait()
}

func (s *scdoCheckpointService) loop() {
	defer s.wg.Done()
	heads := make(chan core.ChainHeadEvent, 16)
	sub := s.eth.blockchain.SubscribeChainHeadEvent(heads)
	defer sub.Unsubscribe()
	s.pollAll()
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			s.pollAll()
		case <-heads:
			s.eth.blockchain.SCDOCheckpointMaintain()
		case <-sub.Err():
			return
		case <-s.quit:
			return
		}
	}
}

func (s *scdoCheckpointService) pollAll() {
	for _, u := range s.urls {
		cp, err := s.fetch(u)
		if err == nil {
			_, err = s.submit(cp, u)
		}
		s.mu.Lock()
		s.lastFetch = time.Now()
		if err != nil {
			s.lastError = fmt.Sprintf("%s: %v", u, err)
		} else {
			s.lastError = ""
		}
		s.mu.Unlock()
		if err != nil && !errors.Is(err, core.ErrSCDOCheckpointOld) {
			log.Debug("SCDO checkpoint fetch", "url", u, "err", err)
		}
	}
}

func (s *scdoCheckpointService) fetch(src string) (*core.SCDOCheckpoint, error) {
	var body []byte
	u, err := url.Parse(src)
	if err != nil {
		return nil, err
	}
	switch u.Scheme {
	case "file":
		f, err := os.Open(u.Path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		body, err = io.ReadAll(io.LimitReader(f, scdoCheckpointMaxBody))
		if err != nil {
			return nil, err
		}
	case "http", "https":
		resp, err := s.client.Get(src)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("http status %d", resp.StatusCode)
		}
		body, err = io.ReadAll(io.LimitReader(resp.Body, scdoCheckpointMaxBody))
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported checkpoint URL scheme %q", u.Scheme)
	}
	var cp core.SCDOCheckpoint
	if err := json.Unmarshal(body, &cp); err != nil {
		return nil, err
	}
	return &cp, nil
}

func (s *scdoCheckpointService) submit(cp *core.SCDOCheckpoint, src string) (bool, error) {
	ok, err := s.eth.blockchain.AddSCDOCheckpoint(cp)
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case err == nil && ok:
		s.accepted++
	case err != nil && !errors.Is(err, core.ErrSCDOCheckpointOld):
		s.invalid++
		log.Warn("SCDO checkpoint rejected", "source", src, "number", cp.Number, "hash", cp.Hash, "err", err)
	}
	return ok, err
}

// SCDOCheckpointAPI is the "scdo" RPC namespace.
type SCDOCheckpointAPI struct{ e *Ethereum }

// GetCheckpoint returns the latest accepted signed checkpoint (null if none).
func (api *SCDOCheckpointAPI) GetCheckpoint() *core.SCDOCheckpoint {
	return api.e.blockchain.SCDOCheckpoint()
}

// SubmitResult is returned by scdo_submitCheckpoint.
type SubmitResult struct {
	Accepted bool   `json:"accepted"`
	Error    string `json:"error,omitempty"`
}

// SubmitCheckpoint verifies and adopts a checkpoint. Safe to expose: only
// checkpoints signed by the configured signers are accepted.
func (api *SCDOCheckpointAPI) SubmitCheckpoint(cp core.SCDOCheckpoint) SubmitResult {
	var (
		ok  bool
		err error
	)
	if api.e.scdoCPSvc != nil {
		ok, err = api.e.scdoCPSvc.submit(&cp, "rpc")
	} else {
		ok, err = api.e.blockchain.AddSCDOCheckpoint(&cp)
	}
	if err != nil {
		return SubmitResult{Accepted: false, Error: err.Error()}
	}
	return SubmitResult{Accepted: ok}
}

// Status reports the checkpoint subsystem state.
func (api *SCDOCheckpointAPI) Status() map[string]interface{} {
	bc := api.e.blockchain
	out := map[string]interface{}{"enabled": false}
	pol := bc.SCDOCheckpointPolicy()
	if pol == nil {
		return out
	}
	rejected, conflict := bc.SCDOCheckpointStats()
	out["enabled"] = true
	out["chainId"] = pol.ChainID
	out["signers"] = pol.Signers
	out["threshold"] = pol.Threshold
	out["rejectedBlocksOrReorgs"] = rejected
	out["conflict"] = conflict
	cp := bc.SCDOCheckpoint()
	out["checkpoint"] = cp
	if cp != nil {
		local := bc.GetCanonicalHash(cp.Number)
		out["localHashAtCheckpoint"] = local
		out["onCheckpointedChain"] = local == cp.Hash
	}
	if fin := bc.CurrentFinalBlock(); fin != nil {
		out["finalized"] = fin.Number.Uint64()
	}
	out["head"] = bc.CurrentBlock().Number.Uint64()
	if api.e.handler != nil && api.e.handler.scdoBans != nil {
		out["peerBans"] = api.e.handler.scdoBans.list()
	}
	if s := api.e.scdoCPSvc; s != nil {
		s.mu.Lock()
		out["sources"] = s.urls
		out["pollInterval"] = s.interval.String()
		out["lastFetch"] = s.lastFetch.Unix()
		out["lastError"] = s.lastError
		out["acceptedCount"] = s.accepted
		out["invalidCount"] = s.invalid
		s.mu.Unlock()
	}
	return out
}

// setupSCDOCheckpoints is called from New() when signers are configured.
func (s *Ethereum) setupSCDOCheckpoints(signers []common.Address, threshold int, urls []string, interval time.Duration) error {
	if len(signers) == 0 {
		return nil
	}
	if threshold == 0 {
		threshold = 1
	}
	chainID := s.blockchain.Config().GetChainID()
	if chainID == nil {
		return errors.New("SCDO checkpoints need a chainId")
	}
	pol := &core.SCDOCheckpointPolicy{ChainID: chainID.Uint64(), Signers: signers, Threshold: threshold}
	if err := s.blockchain.EnableSCDOCheckpoints(pol); err != nil {
		return err
	}
	var clean []string
	for _, u := range urls {
		if u = strings.TrimSpace(u); u != "" {
			clean = append(clean, u)
		}
	}
	s.scdoCPSvc = newSCDOCheckpointService(s, clean, interval)
	return nil
}
