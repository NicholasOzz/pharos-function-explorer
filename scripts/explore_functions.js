#!/usr/bin/env node
/**
 * Pharos Function Explorer
 *
 * Discovers every function a contract exposes on Pharos — even when unverified —
 * by disassembling its bytecode, extracting function selectors, resolving them via
 * the OpenChain 4-byte database, and flagging security-sensitive functions.
 *
 * Usage:
 *   node scripts/explore_functions.js <address> [mainnet|testnet]
 */

import {
  createPublicClient,
  http,
  defineChain,
  isAddress,
  getAddress,
} from "viem";

// --- URL constants (grouped for easy paste-audit) ---
const RPC_MAINNET = "https://rpc.pharos.xyz";
const RPC_TESTNET = "https://atlantic.dplabs-internal.com";
const EXPLORER_MAINNET = "https://pharosscan.xyz";
const EXPLORER_TESTNET = "https://atlantic.pharosscan.xyz";
const OPENCHAIN_API = "https://api.openchain.xyz/signature-database/v1/lookup";

// --- Pharos chain definitions ---
const pharosMainnet = defineChain({
  id: 1672,
  name: "Pharos Pacific Ocean Mainnet",
  nativeCurrency: { name: "Pharos", symbol: "PROS", decimals: 18 },
  rpcUrls: { default: { http: [RPC_MAINNET] } },
});

const pharosTestnet = defineChain({
  id: 688689,
  name: "Pharos Atlantic Testnet",
  nativeCurrency: { name: "Pharos", symbol: "PROS", decimals: 18 },
  rpcUrls: { default: { http: [RPC_TESTNET] } },
});

// --- Security-sensitive function name patterns (matched against lowercased name) ---
const SENSITIVE_CATEGORIES = {
  ownership: ["transferownership", "renounceownership", "setowner", "changeowner", "setadmin", "changeadmin", "acceptownership", "pendingowner"],
  minting: ["mint", "burn"],
  pausing: ["pause", "unpause", "setpaused", "freeze", "unfreeze"],
  fees: ["setfee", "settax", "settreasury", "setfeerecipient", "setfees", "updatefee"],
  blacklist: ["blacklist", "unblacklist", "addblacklist", "removeblacklist", "ban", "block", "setblacklist"],
  upgradeability: ["upgradeto", "setimplementation", "upgrade", "_upgrade"],
  withdrawal: ["withdraw", "sweep", "rescue", "emergencywithdraw", "drain", "skim"],
  destruction: ["selfdestruct", "destroy", "kill", "destruct"],
};

// --- Disassemble bytecode and extract PUSH4 selectors (EVM-aware opcode walker) ---
function extractSelectors(bytecode) {
  const hex = bytecode.startsWith("0x") ? bytecode.slice(2) : bytecode;
  const bytes = [];
  for (let i = 0; i < hex.length; i += 2) {
    bytes.push(parseInt(hex.slice(i, i + 2), 16));
  }

  const selectors = new Set();
  let i = 0;
  while (i < bytes.length) {
    const op = bytes[i];
    // PUSH1 (0x60) through PUSH32 (0x7f) — these have inline data bytes we must skip
    if (op >= 0x60 && op <= 0x7f) {
      const pushSize = op - 0x5f; // PUSH1 => 1 data byte
      // PUSH4 (0x63): the next 4 bytes are a candidate function selector
      if (op === 0x63 && i + 4 < bytes.length) {
        const selBytes = bytes.slice(i + 1, i + 5);
        const selector =
          "0x" + selBytes.map((b) => b.toString(16).padStart(2, "0")).join("");
        selectors.add(selector);
      }
      i += 1 + pushSize;
    } else {
      i += 1;
    }
  }
  return Array.from(selectors);
}

// --- Batch-resolve selectors via OpenChain ---
async function resolveSelectors(selectors) {
  const resolved = {}; // selector -> signature
  const BATCH = 50;
  for (let i = 0; i < selectors.length; i += BATCH) {
    const batch = selectors.slice(i, i + BATCH);
    const query = batch.join(",");
    try {
      const url = `${OPENCHAIN_API}?function=${query}&filter=true`;
      const response = await fetch(url);
      if (!response.ok) continue;
      const data = await response.json();
      const fnMap = data?.result?.function || {};
      for (const sel of batch) {
        const entries = fnMap[sel];
        if (entries && entries.length > 0) {
          resolved[sel] = entries[0].name;
        }
      }
    } catch {
      // Skip this batch on error; selectors stay unresolved
    }
  }
  return resolved;
}

// --- Categorize a resolved function name; returns category key or null ---
function categorize(signature) {
  const name = signature.split("(")[0].toLowerCase();
  for (const [category, keywords] of Object.entries(SENSITIVE_CATEGORIES)) {
    for (const kw of keywords) {
      if (name === kw || name.includes(kw)) {
        return category;
      }
    }
  }
  return null;
}

// --- Main exploration ---
async function explore(rawAddress, networkKey = "mainnet") {
  if (!isAddress(rawAddress)) {
    throw new Error(`Invalid address: ${rawAddress}`);
  }
  const address = getAddress(rawAddress);

  const chain = networkKey === "testnet" ? pharosTestnet : pharosMainnet;
  const explorerUrl = networkKey === "testnet" ? EXPLORER_TESTNET : EXPLORER_MAINNET;
  const client = createPublicClient({ chain, transport: http() });

  const code = await client.getBytecode({ address });
  if (!code || code === "0x") {
    return {
      address,
      networkName: chain.name,
      isContract: false,
      explorer: `${explorerUrl}/address/${address}`,
    };
  }

  const bytecodeSize = (code.length - 2) / 2;
  const selectors = extractSelectors(code);
  const resolved = await resolveSelectors(selectors);

  // Split into sensitive, standard, and unknown
  const sensitive = [];
  const standard = [];
  const unknown = [];

  for (const sel of selectors) {
    const sig = resolved[sel];
    if (!sig) {
      unknown.push(sel);
      continue;
    }
    const category = categorize(sig);
    if (category) {
      sensitive.push({ category, signature: sig });
    } else {
      standard.push(sig);
    }
  }

  // Sort sensitive by category for grouped display
  sensitive.sort((a, b) => a.category.localeCompare(b.category));
  standard.sort();

  return {
    address,
    networkName: chain.name,
    isContract: true,
    bytecodeSize,
    totalSelectors: selectors.length,
    resolvedCount: Object.keys(resolved).length,
    sensitive,
    standard,
    unknown,
    explorer: `${explorerUrl}/address/${address}`,
  };
}

// --- Output formatter ---
function formatReport(r) {
  const lines = [];
  lines.push(`Contract:        ${r.address}`);
  lines.push(`Network:         ${r.networkName}`);

  if (!r.isContract) {
    lines.push(`Type:            Wallet (EOA) — no bytecode, no functions to explore`);
    lines.push("");
    lines.push(`Explorer:        ${r.explorer}`);
    return lines.join("\n");
  }

  lines.push(`Bytecode size:   ${r.bytecodeSize.toLocaleString()} bytes`);
  lines.push(
    `Selectors found: ${r.totalSelectors} (${r.resolvedCount} resolved, ${r.unknown.length} unknown)`,
  );

  // --- Sensitive functions ---
  lines.push("");
  if (r.sensitive.length > 0) {
    lines.push(`Security-sensitive functions (${r.sensitive.length}):`);
    for (const f of r.sensitive) {
      const tag = `[${f.category}]`.padEnd(16);
      lines.push(`  ${tag}${f.signature}`);
    }
  } else {
    lines.push(`Security-sensitive functions: none detected`);
  }

  // --- Standard functions ---
  lines.push("");
  lines.push(`Standard / other functions (${r.standard.length}):`);
  if (r.standard.length === 0) {
    lines.push(`  (none resolved)`);
  } else {
    for (const sig of r.standard) {
      lines.push(`  ${sig}`);
    }
  }

  // --- Unknown selectors ---
  if (r.unknown.length > 0) {
    lines.push("");
    lines.push(`Unknown selectors (${r.unknown.length}):`);
    for (const sel of r.unknown) {
      lines.push(`  ${sel}`);
    }
    lines.push(`  (not found in OpenChain — may be custom functions)`);
  }

  lines.push("");
  lines.push(`Explorer:        ${r.explorer}`);

  return lines.join("\n");
}

// --- CLI entry point ---
async function main() {
  const [address, network] = process.argv.slice(2);
  if (!address) {
    console.error("Usage: node scripts/explore_functions.js <address> [mainnet|testnet]");
    process.exit(1);
  }
  try {
    const result = await explore(address, network);
    console.log(formatReport(result));
  } catch (err) {
    console.error(`Error: ${err.message}`);
    process.exit(1);
  }
}

main();

export { explore, formatReport, extractSelectors };
