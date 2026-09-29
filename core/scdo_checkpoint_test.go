package core

import (
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func scdoTestCP(t testing.TB) (*SCDOCheckpoint, *SCDOCheckpointPolicy) {
	key, _ := crypto.GenerateKey()
	cp := &SCDOCheckpoint{Version: 1, ChainID: 5680, Number: 1200, Hash: common.HexToHash("0x1234")}
	if err := SignSCDOCheckpoint(cp, func(h []byte) ([]byte, error) { return crypto.Sign(h, key) }); err != nil {
		t.Fatal(err)
	}
	return cp, &SCDOCheckpointPolicy{ChainID: 5680, Signers: []common.Address{crypto.PubkeyToAddress(key.PublicKey)}, Threshold: 1}
}

func TestSCDOCheckpointVerify(t *testing.T) {
	cp, pol := scdoTestCP(t)
	if _, err := pol.Verify(cp); err != nil {
		t.Fatalf("valid checkpoint rejected: %v", err)
	}
	// tampered hash / number / chainId
	for name, mut := range map[string]func(c *SCDOCheckpoint){
		"hash":    func(c *SCDOCheckpoint) { c.Hash = common.HexToHash("0x9999") },
		"number":  func(c *SCDOCheckpoint) { c.Number++ },
		"sigbyte": func(c *SCDOCheckpoint) { c.Signatures[0][5] ^= 1 },
	} {
		cc := &SCDOCheckpoint{Version: 1, ChainID: cp.ChainID, Number: cp.Number, Hash: cp.Hash}
		cc.Signatures = append(cc.Signatures, append([]byte{}, cp.Signatures[0]...))
		mut(cc)
		if _, err := pol.Verify(cc); err == nil {
			t.Fatalf("%s: tampered checkpoint accepted", name)
		}
	}
	c2 := *cp
	c2.ChainID = 1
	if _, err := pol.Verify(&c2); !errors.Is(err, ErrSCDOCheckpointChainID) {
		t.Fatalf("chainId: %v", err)
	}
	// signed by a non-authorised key
	other, _ := scdoTestCP(t)
	if _, err := pol.Verify(other); !errors.Is(err, ErrSCDOCheckpointSigner) {
		t.Fatalf("unknown signer: %v", err)
	}
	// threshold 2 with one signature
	pol2 := *pol
	pol2.Signers = append(pol2.Signers, common.HexToAddress("0x01"))
	pol2.Threshold = 2
	if _, err := pol2.Verify(cp); !errors.Is(err, ErrSCDOCheckpointThreshold) {
		t.Fatalf("threshold: %v", err)
	}
	// duplicate signature does not count twice
	c3 := *cp
	c3.Signatures = append(c3.Signatures, cp.Signatures[0])
	if _, err := pol2.Verify(&c3); !errors.Is(err, ErrSCDOCheckpointThreshold) {
		t.Fatalf("duplicate sig counted twice: %v", err)
	}
	// no signature
	c4 := *cp
	c4.Signatures = nil
	if _, err := pol.Verify(&c4); !errors.Is(err, ErrSCDOCheckpointNoSig) {
		t.Fatalf("nosig: %v", err)
	}
}

func BenchmarkSCDOCheckpointVerify(b *testing.B) {
	cp, pol := scdoTestCP(b)
	for i := 0; i < b.N; i++ {
		if _, err := pol.Verify(cp); err != nil {
			b.Fatal(err)
		}
	}
}
