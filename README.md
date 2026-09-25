# tx-firewall

A JSON-RPC proxy that screens Ethereum transactions before they reach the node, blocking ones that fail security or compliance checks. Inspired by sequencer-level transaction screening on rollups.

## Status

- [x] JSON-RPC passthrough proxy (single and batch requests)
- [x] Docker Compose setup with a local Anvil node
- [x] Intercept and decode `eth_sendRawTransaction`
- [x] Risk scoring and blocking (`-32003 transaction rejected`, fail-closed)
- [x] Sanctions screening of sender and recipient (OFAC list)
- [ ] Transaction simulation and trace-based rules
- [ ] Sanctions screening of every address in the trace

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

| Variable         | Default                  | Description                                                                 |
|------------------|--------------------------|-----------------------------------------------------------------------------|
| `SANCTIONS_LIST` | `./config/sanctions.txt` | Host path of the sanctions list mounted into the firewall container         |
| `RISK_THRESHOLD` | `50`                     | A transaction is blocked when the summed weights of its findings reach this |

The sanctions list has one address per line; blank lines and anything after `#` are ignored. The firewall refuses to start if the list is missing or has a malformed line. `config/sanctions.txt` is a snapshot of the [OFAC Ethereum address list](https://github.com/0xB10C/ofac-sanctioned-digital-currency-addresses); replace its addresses with the latest version of that file to refresh it.

When a transaction is blocked, or cannot be screened, the whole request (including the rest of a batch) is rejected before reaching the node:

```json
{"jsonrpc":"2.0","id":1,"error":{"code":-32003,"message":"transaction rejected: sanctioned address 0x..."}}
```

### Rules

| Rule                                 | What it checks                                                                                                                 | Type          |
|--------------------------------------|--------------------------------------------------------------------------------------------------------------------------------|---------------|
| Sanctioned address                   | An address from the OFAC list (or the Chainalysis oracle) anywhere in the trace: sender, called contracts, Transfer recipients | Hard block    |
| Large outflow                        | More than X% of a contract's token balance leaves in a single transaction                                                      | High weight   |
| Privilege change                     | OwnershipTransferred, Upgraded, AdminChanged, RoleGranted events                                                               | High weight   |
| Flash loan + outflow                 | A loan borrowed and repaid in the same transaction, combined with a large outflow elsewhere                                    | High weight   |
| Unlimited approval to fresh contract | Approval with the max amount to a recently deployed contract                                                                   | Medium weight |
| NFT drainer                          | ApprovalForAll to a fresh contract or EOA                                                                                      | Medium weight |
| Deploy-and-call                      | The transaction creates a contract and immediately calls it                                                                    | Medium weight |
| Delegatecall to fresh code           | DELEGATECALL into a contract with no history                                                                                   | Medium weight |
