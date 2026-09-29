// Copyright 2026 9Y9 PTY LTD (SCDO shard0). LGPL-3.0, same as go-ethereum.
//
// SCDO signed checkpoints ("company finality" overlay for Ethash PoW).
//
// A configured set of checkpoint signer keys signs (chainId, number, hash) of
// blocks that are already buried under the signer node's head (e.g. every 100
// blocks at depth 12). A node that holds a valid signed checkpoint:
//
//   1. refuses to import any block at the checkpoint height with another hash
//      (ValidateBody -> ErrSCDOCheckpointMismatch), so a conflicting fork can
//      never be extended past the checkpoint;
//   2. refuses any reorg that would drop the checkpointed block from the
//      canonical chain (ForkChoice.ReorgNeeded), regardless of total difficulty;
//   3. prefers a chain that contains the checkpoint over one that conflicts with it;
//   4. persists the latest checkpoint in the chain database (survives restarts)
//      and marks the checkpoint block as the "finalized" block (eth_getBlockByNumber("finalized")).
//
// Mining, block validity rules and the p2p protocol are unchanged. If no
// checkpoint arrives (signer offline), the node behaves exactly like upstream.
//
// Signature scheme: EIP-191 personal_sign over the ASCII message
//   "SCDO-CHECKPOINT-v1 chainId=<id> number=<n> hash=<0x..>"
// so any Ethereum wallet / HSM / ethers.verifyMessage can produce and check it.

package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
)

var (
	ErrSCDOCheckpointMismatch   = errors.New("block conflicts with SCDO signed checkpoint")
	ErrSCDOCheckpointVersion    = errors.New("unsupported checkpoint version")
	ErrSCDOCheckpointChainID    = errors.New("checkpoint chainId mismatch")
	ErrSCDOCheckpointNoSig      = errors.New("checkpoint has no signatures")
	ErrSCDOCheckpointBadSig     = errors.New("invalid checkpoint signature")
	ErrSCDOCheckpointSigner     = errors.New("checkpoint signed by unknown signer")
	ErrSCDOCheckpointThreshold  = errors.New("not enough distinct authorised checkpoint signatures")
	ErrSCDOCheckpointOld        = errors.New("checkpoint not newer than the current one")
	ErrSCDOCheckpointDisabled   = errors.New("SCDO checkpoints not enabled on this node")
	ErrSCDOCheckpointZeroHash   = errors.New("checkpoint hash is zero")
	scdoCheckpointDBKey         = []byte("scdo-signed-checkpoint-latest")
	scdoCheckpointMessagePrefix = "SCDO-CHECKPOINT-v1"
)

// SCDOCheckpoint is a signed (number, hash) pair. JSON is the wire/file format.
type SCDOCheckpoint struct {
	Version    int              `json:"version"`
	ChainID    uint64           `json:"chainId"`
	Number     uint64           `json:"number"`
	Hash       common.Hash      `json:"hash"`
	Signatures []hexutil.Bytes  `json:"signatures"`
	Signers    []common.Address `json:"signers,omitempty"`   // informational only, never trusted
	Timestamp  uint64           `json:"timestamp,omitempty"` // informational: unix time of signing
	Message    string           `json:"message,omitempty"`   // informational: the signed text
}

// SigningMessage returns the exact text that is signed (EIP-191 personal_sign).
func (c *SCDOCheckpoint) SigningMessage() string {
	return fmt.Sprintf("%s chainId=%d number=%d hash=%s", scdoCheckpointMessagePrefix, c.ChainID, c.Number, c.Hash.Hex())
}

// SigningHash is keccak256("\x19Ethereum Signed Message:\n" + len(msg) + msg).
func (c *SCDOCheckpoint) SigningHash() []byte {
	msg := c.SigningMessage()
	return crypto.Keccak256([]byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(msg), msg)))
}

// SignSCDOCheckpoint appends a signature made with a raw secp256k1 key (tooling/tests).
func SignSCDOCheckpoint(c *SCDOCheckpoint, sign func(hash []byte) ([]byte, error)) error {
	sig, err := sign(c.SigningHash())
	if err != nil {
		return err
	}
	if len(sig) != 65 {
		return ErrSCDOCheckpointBadSig
	}
	if sig[64] < 27 {
		sig[64] += 27 // personal_sign convention
	}
	c.Signatures = append(c.Signatures, sig)
	return nil
}

// SCDOCheckpointPolicy defines who may sign checkpoints for which chain.
type SCDOCheckpointPolicy struct {
	ChainID   uint64
	Signers   []common.Address
	Threshold int
}

func (p *SCDOCheckpointPolicy) String() string {
	s := make([]string, len(p.Signers))
	for i, a := range p.Signers {
		s[i] = a.Hex()
	}
	return fmt.Sprintf("chainId=%d threshold=%d/%d signers=[%s]", p.ChainID, p.Threshold, len(p.Signers), strings.Join(s, ","))
}

// Verify checks a checkpoint against the policy and returns the distinct authorised signers.
func (p *SCDOCheckpointPolicy) Verify(c *SCDOCheckpoint) ([]common.Address, error) {
	if c == nil {
		return nil, errors.New("nil checkpoint")
	}
	if c.Version != 1 {
		return nil, ErrSCDOCheckpointVersion
	}
	if c.ChainID != p.ChainID {
		return nil, fmt.Errorf("%w: have %d want %d", ErrSCDOCheckpointChainID, c.ChainID, p.ChainID)
	}
	if c.Hash == (common.Hash{}) {
		return nil, ErrSCDOCheckpointZeroHash
	}
	if len(c.Signatures) == 0 {
		return nil, ErrSCDOCheckpointNoSig
	}
	if len(c.Signatures) > 32 {
		return nil, fmt.Errorf("%w: too many signatures", ErrSCDOCheckpointBadSig)
	}
	allowed := make(map[common.Address]bool, len(p.Signers))
	for _, a := range p.Signers {
		allowed[a] = true
	}
	hash := c.SigningHash()
	seen := make(map[common.Address]bool)
	var good []common.Address
	for i, sig := range c.Signatures {
		if len(sig) != 65 {
			return nil, fmt.Errorf("%w: signature %d has length %d", ErrSCDOCheckpointBadSig, i, len(sig))
		}
		s := make([]byte, 65)
		copy(s, sig)
		if s[64] >= 27 {
			s[64] -= 27
		}
		if s[64] > 1 {
			return nil, fmt.Errorf("%w: signature %d bad v", ErrSCDOCheckpointBadSig, i)
		}
		// Reject malleable (high-s) signatures.
		if !crypto.ValidateSignatureValues(s[64], new(big.Int).SetBytes(s[0:32]), new(big.Int).SetBytes(s[32:64]), true) {
			return nil, fmt.Errorf("%w: signature %d invalid values", ErrSCDOCheckpointBadSig, i)
		}
		pub, err := crypto.SigToPub(hash, s)
		if err != nil {
			return nil, fmt.Errorf("%w: signature %d: %v", ErrSCDOCheckpointBadSig, i, err)
		}
		addr := crypto.PubkeyToAddress(*pub)
		if !allowed[addr] {
			return nil, fmt.Errorf("%w: %s", ErrSCDOCheckpointSigner, addr.Hex())
		}
		if !seen[addr] {
			seen[addr] = true
			good = append(good, addr)
		}
	}
	if len(good) < p.Threshold {
		return nil, fmt.Errorf("%w: have %d need %d", ErrSCDOCheckpointThreshold, len(good), p.Threshold)
	}
	sort.Slice(good, func(i, j int) bool { return good[i].Hex() < good[j].Hex() })
	return good, nil
}

// scdoCheckpointer is the per-BlockChain checkpoint state.
type scdoCheckpointer struct {
	mu       sync.Mutex
	policy   *SCDOCheckpointPolicy
	latest   atomic.Pointer[SCDOCheckpoint]
	rejected atomic.Uint64 // blocks/reorgs refused because of a checkpoint
	conflict atomic.Bool   // local canonical chain conflicts with the latest checkpoint
}

// EnableSCDOCheckpoints activates the checkpoint rules with the given policy
// and restores the persisted checkpoint (re-verified against the policy).
func (bc *BlockChain) EnableSCDOCheckpoints(policy *SCDOCheckpointPolicy) error {
	if policy == nil || len(policy.Signers) == 0 {
		return errors.New("SCDO checkpoints: empty signer list")
	}
	if policy.Threshold < 1 || policy.Threshold > len(policy.Signers) {
		return fmt.Errorf("SCDO checkpoints: bad threshold %d for %d signers", policy.Threshold, len(policy.Signers))
	}
	cp := &scdoCheckpointer{policy: policy}
	if blob, err := bc.db.Get(scdoCheckpointDBKey); err == nil && len(blob) > 0 {
		var stored SCDOCheckpoint
		if err := json.Unmarshal(blob, &stored); err != nil {
			log.Warn("SCDO checkpoint: stored checkpoint unreadable, ignoring", "err", err)
		} else if _, err := policy.Verify(&stored); err != nil {
			log.Warn("SCDO checkpoint: stored checkpoint no longer valid for signer policy, ignoring", "number", stored.Number, "err", err)
		} else {
			cp.latest.Store(&stored)
			log.Info("SCDO checkpoint restored from database", "number", stored.Number, "hash", stored.Hash)
		}
	}
	bc.scdoCP.Store(cp)
	log.Info("SCDO signed checkpoints enabled", "policy", policy.String())
	bc.SCDOCheckpointMaintain()
	return nil
}

func (bc *BlockChain) scdo() *scdoCheckpointer { return bc.scdoCP.Load() }

// SCDOCheckpoint returns the latest accepted checkpoint (nil if none / disabled).
func (bc *BlockChain) SCDOCheckpoint() *SCDOCheckpoint {
	if s := bc.scdo(); s != nil {
		return s.latest.Load()
	}
	return nil
}

// SCDOCheckpointPolicy returns the active policy (nil if disabled).
func (bc *BlockChain) SCDOCheckpointPolicy() *SCDOCheckpointPolicy {
	if s := bc.scdo(); s != nil {
		return s.policy
	}
	return nil
}

// SCDOCheckpointStats returns (#rejected blocks/reorgs, local chain conflicts with checkpoint).
func (bc *BlockChain) SCDOCheckpointStats() (uint64, bool) {
	if s := bc.scdo(); s != nil {
		return s.rejected.Load(), s.conflict.Load()
	}
	return 0, false
}

// AddSCDOCheckpoint verifies and, if newer, adopts and persists a checkpoint.
// Returns (true, nil) when adopted, (false, nil) when it equals the current one.
func (bc *BlockChain) AddSCDOCheckpoint(c *SCDOCheckpoint) (bool, error) {
	s := bc.scdo()
	if s == nil {
		return false, ErrSCDOCheckpointDisabled
	}
	signers, err := s.policy.Verify(c)
	if err != nil {
		return false, err
	}
	s.mu.Lock()
	cur := s.latest.Load()
	if cur != nil {
		if c.Number == cur.Number && c.Hash == cur.Hash {
			s.mu.Unlock()
			return false, nil
		}
		if c.Number <= cur.Number {
			s.mu.Unlock()
			if c.Number == cur.Number {
				log.Error("SCDO checkpoint: validly signed checkpoint CONFLICTS with current one (signer key compromise?)", "number", c.Number, "have", cur.Hash, "got", c.Hash)
			}
			return false, fmt.Errorf("%w: have %d got %d", ErrSCDOCheckpointOld, cur.Number, c.Number)
		}
		// A new checkpoint must descend from the previous one when both are known locally.
		if h := bc.GetHeaderByHash(c.Hash); h != nil && h.Number.Uint64() == c.Number {
			if st := bc.scdoChainHas(h, cur); st == scdoCPConflict {
				s.mu.Unlock()
				log.Error("SCDO checkpoint: new checkpoint does not descend from previous checkpoint, refusing", "number", c.Number, "hash", c.Hash, "prev", cur.Number)
				return false, errors.New("checkpoint does not descend from previous checkpoint")
			}
		}
	}
	stored := *c
	stored.Signers = signers
	stored.Message = c.SigningMessage()
	blob, _ := json.Marshal(&stored)
	if err := bc.db.Put(scdoCheckpointDBKey, blob); err != nil {
		s.mu.Unlock()
		return false, err
	}
	s.latest.Store(&stored)
	s.mu.Unlock()
	log.Info("SCDO signed checkpoint accepted", "number", c.Number, "hash", c.Hash, "signers", len(signers))
	bc.SCDOCheckpointMaintain()
	return true, nil
}

// SCDOCheckpointMaintain updates the finalized marker and detects / heals a
// local canonical chain that conflicts with the latest checkpoint.
func (bc *BlockChain) SCDOCheckpointMaintain() {
	s := bc.scdo()
	if s == nil {
		return
	}
	cp := s.latest.Load()
	if cp == nil {
		return
	}
	head := bc.CurrentBlock()
	if head == nil || head.Number.Uint64() < cp.Number {
		s.conflict.Store(false)
		return
	}
	canon := bc.GetCanonicalHash(cp.Number)
	if canon == cp.Hash {
		s.conflict.Store(false)
		if fin := bc.CurrentFinalBlock(); fin == nil || fin.Hash() != cp.Hash {
			if h := bc.GetHeaderByHash(cp.Hash); h != nil {
				bc.SetFinalized(h)
			}
		}
		return
	}
	// Canonical chain conflicts with a validly signed checkpoint.
	s.conflict.Store(true)
	block := bc.GetBlockByHash(cp.Hash)
	if block == nil || !bc.HasState(block.Root()) {
		log.Error("SCDO checkpoint: local chain CONFLICTS with signed checkpoint and checkpoint block is unknown; waiting for peers on the checkpointed chain", "number", cp.Number, "checkpoint", cp.Hash, "local", canon)
		return
	}
	log.Error("SCDO checkpoint: local chain CONFLICTS with signed checkpoint, rewinding to checkpoint block", "number", cp.Number, "checkpoint", cp.Hash, "local", canon)
	go func() {
		if _, err := bc.SetCanonical(block); err != nil {
			log.Error("SCDO checkpoint: failed to switch to checkpointed chain", "err", err)
			return
		}
		s.conflict.Store(false)
		bc.SetFinalized(block.Header())
	}()
}

type scdoCPState int

const (
	scdoCPUnknown  scdoCPState = iota // chain tip below checkpoint height
	scdoCPContains                    // chain contains the checkpoint block
	scdoCPConflict                    // chain has another block at checkpoint height
)

// scdoChainHas reports whether the chain ending at tip contains cp. Cost is
// O(distance from tip to the canonical chain), normally 0 or 1 lookups.
func (bc *BlockChain) scdoChainHas(tip *types.Header, cp *SCDOCheckpoint) scdoCPState {
	if tip == nil || tip.Number.Uint64() < cp.Number {
		return scdoCPUnknown
	}
	h := tip
	for h != nil && h.Number.Uint64() > cp.Number {
		if bc.GetCanonicalHash(h.Number.Uint64()) == h.Hash() {
			if bc.GetCanonicalHash(cp.Number) == cp.Hash {
				return scdoCPContains
			}
			return scdoCPConflict
		}
		h = bc.GetHeader(h.ParentHash, h.Number.Uint64()-1)
	}
	if h == nil {
		return scdoCPUnknown
	}
	if h.Hash() == cp.Hash {
		return scdoCPContains
	}
	return scdoCPConflict
}

// scdoForkChoice returns (decided, reorg). decided=false means "no opinion, use TD rules".
func (bc *BlockChain) scdoForkChoice(current, extern *types.Header) (bool, bool) {
	s := bc.scdo()
	if s == nil {
		return false, false
	}
	cp := s.latest.Load()
	if cp == nil {
		return false, false
	}
	cur := bc.scdoChainHas(current, cp)
	var ext scdoCPState
	if extern.ParentHash == current.Hash() && extern.Number.Uint64() > cp.Number {
		ext = cur // plain extension of the current head
	} else {
		ext = bc.scdoChainHas(extern, cp)
	}
	switch {
	case cur == scdoCPContains && ext != scdoCPContains:
		s.rejected.Add(1)
		log.Warn("Reorg disallowed by SCDO signed checkpoint 🔒", "checkpoint.bno", cp.Number, "checkpoint.hash", cp.Hash,
			"current.bno", current.Number, "current.hash", current.Hash(), "proposed.bno", extern.Number, "proposed.hash", extern.Hash())
		return true, false
	case cur == scdoCPConflict && ext == scdoCPContains:
		log.Warn("Switching to chain containing SCDO signed checkpoint", "checkpoint.bno", cp.Number, "proposed.bno", extern.Number)
		return true, true
	}
	return false, false
}

// scdoCheckBlock rejects a block at a checkpointed height with a different hash.
func (bc *BlockChain) scdoCheckBlock(header *types.Header) error {
	s := bc.scdo()
	if s == nil {
		return nil
	}
	cp := s.latest.Load()
	if cp == nil || header.Number.Uint64() != cp.Number || header.Hash() == cp.Hash {
		return nil
	}
	s.rejected.Add(1)
	log.Warn("Block rejected by SCDO signed checkpoint 🔒", "number", cp.Number, "checkpoint", cp.Hash, "block", header.Hash())
	return fmt.Errorf("%w: number %d have %s checkpoint %s", ErrSCDOCheckpointMismatch, cp.Number, header.Hash().Hex(), cp.Hash.Hex())
}
