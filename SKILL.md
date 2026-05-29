name: pharos-function-explorer
description: Discover every function a contract exposes on the Pharos Network — even when the contract is unverified. This skill disassembles a contract's on-chain bytecode, extracts all function selectors, resolves them to human-readable signatures via the public OpenChain 4-byte database, and flags security-sensitive functions (ownership, minting, pausing, fee changes, blacklisting, upgradeability, fund withdrawal, self-destruct). Use whenever a user asks "what functions does this contract have", "what can this contract do", "is this contract safe", "does this contract have a backdoor", "what owner functions exist", "explore 0x...", or wants to reverse-engineer or audit an unverified Pharos contract.
license: MIT
Pharos Function Explorer
A security and reverse-engineering Agent Skill that reveals what any Pharos contract can do — even when it has never been verified.
Block explorers can only show you a contract's functions if its source code is verified. This skill works regardless: it reads the raw bytecode, extracts the function selectors directly, and resolves them against the public OpenChain signature database. The result is a categorized map of everything the contract exposes, with security-sensitive functions flagged.
When to use
Use this skill when the user wants to:
See every function an unverified contract exposes
Audit a contract before interacting with it
Find hidden owner-only or admin functions ("backdoors")
Detect dangerous capabilities (mint, pause, blacklist, self-destruct, upgrade)
Reverse-engineer an unknown contract's interface
Understand what a contract does without its source code
Inputs
Contract address — a 0x-prefixed contract address
Optional:
Network — mainnet (default, chain 1672) or testnet (chain 688689 Atlantic)
How to run it
Bash
Output format
Code
How it works
Fetch bytecode via eth_getCode
Disassemble: walk the bytecode opcode-by-opcode, correctly skipping PUSH data, and capture every PUSH4 constant — these are the function selectors the contract's dispatcher checks against
Resolve: batch-query the selectors against the OpenChain 4-byte database (free, no API key) to get human-readable signatures
Categorize: pattern-match resolved names to flag security-sensitive functions:
ownership: transferOwnership, renounceOwnership, owner, admin
minting: mint, burn
pausing: pause, unpause
fees: setFee, setTax, setTreasury
blacklist: blacklist, ban, block
upgradeability: upgradeTo, setImplementation
withdrawal: withdraw, sweep, rescue, claim
destruction: selfdestruct, destroy, kill
Report: present sensitive functions first, then standard functions, then unresolved selectors
Why bytecode scanning works
EVM contracts route incoming calls through a dispatcher that compares the first 4 bytes of calldata (the selector) against each function's selector. These selectors are embedded in the bytecode as PUSH4 constants. By disassembling the bytecode with a proper opcode walker (one that skips the data bytes of all PUSH1–PUSH32 instructions), we extract those selectors reliably — no source code required.
Edge cases
Not a contract (EOA): empty bytecode → reported as a wallet, no functions to explore
Proxy contracts: shows the proxy's own selectors; the implementation's functions live at the implementation address (use the Contract Inspector skill to find it)
Selector not in OpenChain: listed under "Unknown selectors" — likely a custom function whose signature hasn't been registered
False-positive PUSH4 values: random PUSH4 data that isn't a real selector simply won't resolve, so it lands in the unknown list without polluting the resolved output
Network / OpenChain unreachable: raw selectors are still shown even if name resolution fails
Dependencies
Node.js 18+ (native fetch is used)
viem (installed via npm install)
See README.md for setup.
