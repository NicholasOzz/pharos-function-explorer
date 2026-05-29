# Pharos Function Explorer

An [Agent Skill](https://agentskills.io) that reveals what any contract on the [Pharos Network](https://www.pharos.xyz) can do — **even when the contract is unverified.** Built for the **Pharos Agent Center Skill Builder Campaign**.

Block explorers can only show a contract's functions if its source code is verified. This skill works regardless: it reads the raw bytecode, extracts the function selectors directly, resolves them to human-readable signatures, and flags security-sensitive functions.

## Why this is different

Every other inspection skill depends on verified source code or a known ABI. This one reverse-engineers the contract from its bytecode, so it works on the ~majority of contracts that haven't been verified yet. It's a contract autopsy and security-audit tool.

It answers questions like:
- "What functions does this unverified contract have?"
- "Does this contract have a hidden owner backdoor?"
- "Can the deployer mint, pause, or blacklist?"
- "Is there a self-destruct or upgrade function?"

## How it works

1. **Fetch bytecode** via `eth_getCode`
2. **Disassemble** the bytecode with a proper EVM opcode walker that correctly skips the inline data of every `PUSH1`–`PUSH32` instruction, capturing each `PUSH4` constant — these are the function selectors the contract's dispatcher checks
3. **Resolve** the selectors against the public OpenChain 4-byte signature database (free, no API key), batched for efficiency
4. **Categorize** resolved names, flagging security-sensitive functions across 8 categories
5. **Report** sensitive functions first, then standard functions, then unresolved selectors

### Why bytecode scanning works

EVM contracts route calls through a dispatcher that compares the first 4 bytes of calldata (the selector) against each function's selector. Solidity embeds these selectors in the bytecode as `PUSH4` constants. A correct opcode walker extracts them with no source code required.

## Security categories flagged

| Category | Examples |
|---|---|
| ownership | transferOwnership, renounceOwnership, setAdmin |
| minting | mint, burn |
| pausing | pause, unpause, freeze |
| fees | setFee, setTax, setTreasury |
| blacklist | blacklist, ban, block |
| upgradeability | upgradeTo, setImplementation |
| withdrawal | withdraw, sweep, rescue, drain |
| destruction | selfdestruct, destroy, kill |

## Installation

```bash
git clone https://github.com/<your-username>/pharos-function-explorer.git
cd pharos-function-explorer
npm install
```

Requires Node.js 18+.

## Usage

```bash
node scripts/explore_functions.js <address> [mainnet|testnet]
```

### Example output

```
Contract:        0xabc...
Network:         Pharos Pacific Ocean Mainnet
Bytecode size:   4,521 bytes
Selectors found: 23 (19 resolved, 4 unknown)

Security-sensitive functions (5):
  [minting]       mint(address,uint256)
  [ownership]     renounceOwnership()
  [ownership]     transferOwnership(address)
  [pausing]       pause()
  [withdrawal]    withdraw(uint256)

Standard / other functions (14):
  approve(address,uint256)
  balanceOf(address)
  totalSupply()
  transfer(address,uint256)
  ...

Unknown selectors (4):
  0x1a2b3c4d
  (not found in OpenChain — may be custom functions)

Explorer:        https://pharosscan.xyz/address/0xabc...
```

## Using as an Agent Skill

This repo follows the [open Agent Skills format](https://agentskills.io/specification):

```
pharos-function-explorer/
├── SKILL.md
├── scripts/
│   └── explore_functions.js
├── package.json
└── README.md
```

Agents compatible with Pharos Agent Center (Claude Code, Codex, OpenClaw, etc.) load `SKILL.md` and trigger this skill on prompts like:
- "What functions does contract 0x... have?"
- "Audit this Pharos contract for backdoors"
- "Does this contract have owner-only functions?"

## Notes

- **Proxy contracts**: the skill shows the proxy's own selectors. To explore the implementation's functions, find the implementation address (e.g. via the Pharos Contract Inspector skill) and run this against that address.
- **False positives**: random `PUSH4` data that isn't a real selector simply won't resolve, landing harmlessly in the "unknown" list.

## Network details

| Network | Chain ID | RPC | Explorer |
|---|---|---|---|
| Mainnet | 1672 | `https://rpc.pharos.xyz` | `https://pharosscan.xyz` |
| Atlantic Testnet | 688689 | `https://atlantic.dplabs-internal.com` | `https://atlantic.pharosscan.xyz` |

## Data sources

- **Pharos RPC** for bytecode
- **OpenChain** ([openchain.xyz](https://openchain.xyz)) for the free 4-byte signature database

## License

MIT
