# tx-firewall

A JSON-RPC proxy that screens Ethereum transactions before they reach the node, blocking ones that fail security or compliance checks. Inspired by sequencer-level transaction screening on rollups.

## Status

- [x] JSON-RPC passthrough proxy (single and batch requests)
- [x] Docker Compose setup with a local Anvil node
- [ ] Intercept and decode `eth_sendRawTransaction`
- [ ] Sanctions screening (OFAC list)
- [ ] Transaction simulation and trace-based rules
- [ ] Risk scoring and blocking

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
