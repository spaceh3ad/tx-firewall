# tx-firewall

A JSON-RPC proxy that screens Ethereum transactions before they reach the node, blocking ones that fail security or compliance checks. Inspired by sequencer-level transaction screening on rollups.

## Status

- [x] JSON-RPC passthrough proxy (single and batch requests)
- [x] Docker Compose setup with a local Anvil node
- [x] Intercept and decode `eth_sendRawTransaction`
- [x] Risk scoring and blocking (`-32003 transaction rejected`, fail-closed)
- [x] Sanctions screening of every address in the trace (OFAC list, optional Chainalysis oracle)
- [x] Transaction simulation (`debug_traceCall` with the call tracer)
- [x] Privilege-change rule
- [ ] Remaining trace-based rules (see [Rules](#rules))

## Requirements
- docker

## Running

The project is designed to run with Docker Compose, which starts both the firewall and a local Anvil node.

```sh
cp .env.example .env   # optional, defaults work out of the box
docker compose up --build
```

Test it:

```sh
curl -X POST localhost:8546 -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}'
```

Expected response: `{"jsonrpc":"2.0","id":1,"result":"0x7a69"}`

## Configuration

| Variable               | Default                  | Description                                                                 |
|------------------------|--------------------------|-----------------------------------------------------------------------------|
| `SANCTIONS_LIST`       | `./config/sanctions.txt` | Host path of the sanctions list mounted into the firewall container         |
| `SANCTIONS_ORACLE_RPC` | empty (disabled)         | Mainnet RPC URL used to query the Chainalysis sanctions oracle              |
| `RISK_THRESHOLD`       | `50`                     | A transaction is blocked when the summed weights of its findings reach this |

The sanctions list has one address per line; blank lines and anything after `#` are ignored. The firewall refuses to start if the list is missing or has a malformed line. `config/sanctions.txt` is a snapshot of the [OFAC Ethereum address list](https://github.com/0xB10C/ofac-sanctioned-digital-currency-addresses); replace its addresses with the latest version of that file to refresh it.

When `SANCTIONS_ORACLE_RPC` is set, addresses that pass the list are also checked against the [Chainalysis sanctions oracle](https://go.chainalysis.com/chainalysis-oracle-docs.html) (`0x40C57923924B5c5c5455c48D93317139ADDaC8fb`). The oracle is not deployed on local Anvil, so this needs a mainnet RPC. The firewall checks the contract exists at startup, and caches answers for 10 minutes. If the oracle can't be reached, the transaction is rejected rather than let through.

## How screening works

Every `eth_sendRawTransaction` is decoded and simulated on the upstream node with `debug_traceCall`, so **the upstream node must expose the debug API** (Anvil does; for Geth enable the `debug` namespace). The firewall checks this at startup. Effects of frames that revert are ignored, since they are rolled back on-chain.

The rules then inspect the result. A hard-block finding blocks the transaction; otherwise the weights of the findings are summed (high = 40, medium = 20) and the transaction is blocked when the score reaches `RISK_THRESHOLD`. With the default of 50, a single high-weight finding is logged as `flagged transaction` and forwarded, and it takes a second signal to block.

When a transaction is blocked, or cannot be screened, the whole request (including the rest of a batch) is rejected before reaching the node:

```json
{"jsonrpc":"2.0","id":1,"error":{"code":-32003,"message":"transaction rejected: sanctioned address 0x..."}}
```

A transaction the node refuses to execute (for example, the sender can't pay for it) is rejected with the node's reason: `transaction rejected: simulation failed: Insufficient funds ...`.

### Rules

| Rule                                 | What it checks                                                                                                                 | Type          | Status                      |
|--------------------------------------|--------------------------------------------------------------------------------------------------------------------------------|---------------|-----------------------------|
| Sanctioned address                   | An address from the OFAC list (or the Chainalysis oracle) anywhere in the trace: sender, called contracts, Transfer recipients | Hard block    | Done                        |
| Large outflow                        | More than X% of a contract's token balance leaves in a single transaction                                                      | High weight   | Planned                     |
| Privilege change                     | OwnershipTransferred, Upgraded, AdminChanged, RoleGranted events                                                               | High weight   | Done                        |
| Flash loan + outflow                 | A loan borrowed and repaid in the same transaction, combined with a large outflow elsewhere                                    | High weight   | Planned                     |
| Unlimited approval to fresh contract | Approval with the max amount to a recently deployed contract                                                                   | Medium weight | Planned                     |
| NFT drainer                          | ApprovalForAll to a fresh contract or EOA                                                                                      | Medium weight | Planned                     |
| Deploy-and-call                      | The transaction creates a contract and immediately calls it                                                                    | Medium weight | Planned                     |
| Delegatecall to fresh code           | DELEGATECALL into a contract with no history                                                                                   | Medium weight | Planned                     |

The sanctioned-address rule checks the sender, the recipient, every contract called or created by a frame that doesn't revert (including delegatecall targets), and the recipient of every ERC-20 and ERC-721 `Transfer`.

Privilege-change events from contracts deployed in the same transaction are ignored: constructors emit them when setting the initial owner, implementation or roles.
