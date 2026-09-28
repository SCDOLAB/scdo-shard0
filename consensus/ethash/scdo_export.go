// Copyright 2026 SCDO shard0 additions. Licensed under the GNU LGPL v3 like the rest of go-ethereum.

package ethash

// Exported light-verification helpers used by cmd/scdostratum (stratum <-> getwork
// proxy) and its test client. They only wrap the unexported ethash primitives; no
// consensus behaviour is changed.

// LightCache is an in-memory ethash verification cache for one epoch.
type LightCache struct {
	Epoch       uint64
	EpochLength uint64
	cache       []uint32
	dataSize    uint64
}

// NewLightCache generates the verification cache for the given epoch (for plain
// Ethash the epoch length is 30000). Epoch 0 takes ~1-2 s and 16 MB of RAM.
func NewLightCache(epoch, epochLength uint64) *LightCache {
	size := cacheSize(epoch)
	c := make([]uint32, size/4)
	generateCache(c, epoch, epochLength, seedHash(epoch, epochLength))
	return &LightCache{Epoch: epoch, EpochLength: epochLength, cache: c, dataSize: datasetSize(epoch)}
}

// Hashimoto computes (mixDigest, result) for a seal hash and nonce using the light cache.
func (l *LightCache) Hashimoto(sealHash []byte, nonce uint64) (mix []byte, result []byte) {
	return hashimotoLight(l.dataSize, l.cache, sealHash, nonce)
}

// FullDataset is the full ethash mining dataset for one epoch (≈1 GB for epoch 0).
type FullDataset struct {
	Epoch   uint64
	dataset []uint32
}

// NewFullDataset generates the full dataset (uses all CPU cores; minutes of CPU time).
func (l *LightCache) NewFullDataset() *FullDataset {
	d := make([]uint32, l.dataSize/4)
	generateDataset(d, l.Epoch, l.EpochLength, l.cache)
	return &FullDataset{Epoch: l.Epoch, dataset: d}
}

// Hashimoto computes (mixDigest, result) using the full dataset.
func (f *FullDataset) Hashimoto(sealHash []byte, nonce uint64) (mix []byte, result []byte) {
	return hashimotoFull(f.dataset, sealHash, nonce)
}

// SeedHashFor returns the seed hash of an epoch.
func SeedHashFor(epoch, epochLength uint64) []byte { return seedHash(epoch, epochLength) }
