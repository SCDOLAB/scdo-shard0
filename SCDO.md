# SCDO shard 0 (core-geth fork)

This branch (`scdo`) is the source of the node software that runs **SCDO shard 0**.
It is [etclabscore/core-geth](https://github.com/etclabscore/core-geth) **v1.12.23**
(itself a downstream of [go-ethereum](https://github.com/ethereum/go-ethereum)) with a
few small SCDO additions on top. All upstream history, authorship and licences are kept.

| | |
|---|---|
| Chain ID / network ID | **5680** (`0x1630`) |
| Consensus | Ethash proof of work (plain Ethash, 30,000-block epochs) |
| EVM | full EVM, EIP-155 and EIP-1559 (London) from genesis |
| Genesis | [`scdo/scdo-shard0-genesis.json`](scdo/scdo-shard0-genesis.json) (same file as https://scdoscan.io/downloads/shard0/scdo-shard0-genesis.json) |
| Public RPC | https://scdoscan.io/rpc/0 |
| Explorer | https://scdoscan.io |
| Bootnode | `enode://1d2c370db7c419349e2313f20023f6b379f946990042b9b42df45cb56e4c3487df0d36c52cd81308fcdf312450f758a6213fcac21213e94a71af4a3c9392601f@82.223.19.88:30368` |

The chain ID comes from the genesis file. There are no consensus changes to core-geth.

## What was added

| Path | What it is |
|---|---|
| `cmd/scdostratum` | `scdo-stratum`: solo stratum-to-getwork proxy for one node (ethproxy and EthereumStratum/1.0.0 on one port, light-cache share checks, sync/peer gating). Used by the GPU mining package. |
| `cmd/scdostratumtest` | CPU test client for `scdostratum` (real Ethash shares, plus deliberately bad submissions). Test use only. |
| `cmd/scdofaucet` | The shard 0 faucet service. It reads its key from a file given with `-key` (no key in this repo). |
| `cmd/scdotps` | Load generator for tests. It reads its key from a file given with `-key` (no key in this repo). |
| `consensus/ethash/scdo_export.go` | Exported wrappers around the ethash light cache / hashimoto, used by the proxy. No consensus change. |
| `consensus/ethash/ethash.go` | Bug fix: a uint64 underflow in the old-cache/DAG cleanup deleted the live epoch 0/1 DAG file. |
| `scdo/scdo-shard0-genesis.json` | Shard 0 genesis (chainId 5680). |

## Build

Go 1.21 or newer. With Go 1.23+ add `-ldflags=-checklinkname=0` (an old upstream dependency,
`fjl/memsize`, otherwise fails to link). The published binaries were built with Go 1.24:

```bash
go build -ldflags '-checklinkname=0 -extldflags -static' -tags osusergo,netgo,static_build -o build/geth ./cmd/geth
go build -o build/scdo-stratum ./cmd/scdostratum
```

`geth init` with the genesis above must print genesis hash `0xbbb083…70cb12`.

## Run a node

```bash
./build/geth --datadir ./scdo0 init scdo/scdo-shard0-genesis.json
./build/geth --datadir ./scdo0 --networkid 5680 --port 30368 --syncmode full \
  --bootnodes enode://1d2c370db7c419349e2313f20023f6b379f946990042b9b42df45cb56e4c3487df0d36c52cd81308fcdf312450f758a6213fcac21213e94a71af4a3c9392601f@82.223.19.88:30368 \
  --http --http.addr 127.0.0.1 --http.port 8545 --http.api eth,net,web3
```

For GPU mining, use the ready-made package from https://scdoscan.io/downloads/shard0/
(scripts in [SCDOLAB/scdo-gpu-miner](https://github.com/SCDOLAB/scdo-gpu-miner)). It runs
this node plus `scdo-stratum` locally, so blocks pay your own address.

## Licence

Same as upstream: the library code (everything outside `cmd/`) is under the
GNU LGPL v3 ([COPYING.LESSER](COPYING.LESSER)), and the programs in `cmd/` are under the
GNU GPL v3 ([COPYING](COPYING)). The SCDO additions use the same licences:
`consensus/ethash/scdo_export.go` is LGPL v3, and `cmd/scdostratum`, `cmd/scdostratumtest`,
`cmd/scdofaucet` and `cmd/scdotps` are GPL v3. Copyright of upstream code stays with the
go-ethereum and core-geth authors (see [AUTHORS](AUTHORS)).
