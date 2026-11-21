// ClaimGuard attestation hook for the Agent ID red-packet monitor.
//
// STATUS: WIRED IN 2026-11-21, after ClaimGuardRegistry was deployed to
// 0x9B6f33D9aE6B01eb56e44DADA9F7FF2fAB9B0d14 (BSC mainnet). The live monitor
// (~/workspace/redpackets/monitor.mjs) dynamically imports this module from
// its event() emit point for definitive gate outcomes only, gated by
// ~/workspace/redpackets/claimguard.config.json (enabled + registry +
// dryRun). Removing that config file (or setting enabled:false) disables
// attestation completely; claim behaviour is never affected either way.
//
// What it does (once wired): after the monitor's fail-closed gates finish
// evaluating a packet — whether they PASS (grab executed) or REFUSE (a gate
// stopped the claim) — it records the outcome on-chain in ClaimGuardRegistry
// via attestClaim(), through the same preview -> validate -> execute gates
// the monitor itself uses for value-bearing calls:
//   * the preview must target the configured ClaimGuardRegistry address,
//   * the value must be exactly 0,
//   * anything unexpected aborts the attestation (never the claim flow).
//
// Safety defaults:
//   * Disabled unless CLAIMGUARD_ATTEST=1.
//   * Dry-run unless CLAIMGUARD_ATTEST_DRY_RUN=0 (logs calldata, sends nothing).
//   * Registry address comes from CLAIMGUARD_REGISTRY env; empty = disabled.
//   * An attestation failure NEVER throws into the monitor's claim path —
//     attestations are a reporting layer, not a gate.
import { execFile } from 'node:child_process';

export const CLAIMGUARD = {
  // Outcome codes — mirror ClaimGuardRegistry.
  OUTCOME_PASSED: 0,
  OUTCOME_REFUSED: 1,
  // Reason codes — mirror ClaimGuardRegistry.
  REASON_NONE: 0,
  REASON_HELPER_REFUSED: 1,
  REASON_CUSTOM_TOKEN: 2,
  REASON_UNEXPECTED_CALL_SET: 3,
  REASON_PREVIEW_TARGET_MISMATCH: 4,
  REASON_PREVIEW_VALUE_NONZERO: 5,
  REASON_PREVIEW_BLOCKED: 6,
  REASON_CODE_REQUIRED: 7,
  REASON_OTHER: 8,
};

// ---------------------------------------------------------------------------
// Minimal pure-JS Keccak-256 (the monitor's codebase is dependency-free, and
// Node's crypto offers SHA3-256 — a different padding — not Keccak-256).
// Verified against published test vectors in --selftest below.
// ---------------------------------------------------------------------------
const MASK64 = (1n << 64n) - 1n;
const RC = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];
// Rotation offsets r[x + 5*y]
const ROT = [
  0, 1, 62, 28, 27,
  36, 44, 6, 55, 20,
  3, 10, 43, 25, 39,
  41, 45, 15, 21, 8,
  18, 2, 61, 56, 14,
];

function rotl(x, n) {
  if (n === 0) return x & MASK64;
  const b = BigInt(n);
  return ((x << b) | (x >> (64n - b))) & MASK64;
}

function keccakF(state) {
  for (let round = 0; round < 24; round++) {
    // theta
    const c = new Array(5);
    for (let x = 0; x < 5; x++) c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
    for (let x = 0; x < 5; x++) {
      const d = c[(x + 4) % 5] ^ rotl(c[(x + 1) % 5], 1);
      for (let y = 0; y < 5; y++) state[x + 5 * y] = (state[x + 5 * y] ^ d) & MASK64;
    }
    // rho + pi
    const b = new Array(25).fill(0n);
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(state[x + 5 * y], ROT[x + 5 * y]);
      }
    }
    // chi
    for (let y = 0; y < 5; y++) {
      for (let x = 0; x < 5; x++) {
        state[x + 5 * y] = (b[x + 5 * y] ^ (~b[((x + 1) % 5) + 5 * y] & b[((x + 2) % 5) + 5 * y])) & MASK64;
      }
    }
    // iota
    state[0] = (state[0] ^ RC[round]) & MASK64;
  }
}

export function keccak256(bytes) {
  const rate = 136; // bytes, for 256-bit output
  const state = new Array(25).fill(0n);
  const padded = Array.from(bytes);
  padded.push(0x01);
  while (padded.length % rate !== rate - 1) padded.push(0x00);
  padded.push(0x80);
  for (let off = 0; off < padded.length; off += rate) {
    for (let i = 0; i < rate / 8; i++) {
      let lane = 0n;
      for (let j = 7; j >= 0; j--) lane = (lane << 8n) | BigInt(padded[off + i * 8 + j]);
      state[i] = (state[i] ^ lane) & MASK64;
    }
    keccakF(state);
  }
  const out = [];
  for (let i = 0; i < 4; i++) {
    let lane = state[i];
    for (let j = 0; j < 8; j++) { out.push(Number(lane & 0xffn)); lane >>= 8n; }
  }
  return out;
}

export function keccak256Hex(utf8) {
  return '0x' + keccak256(new TextEncoder().encode(utf8)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

export function functionSelector(signature) {
  return keccak256(new TextEncoder().encode(signature)).slice(0, 4)
    .map((b) => b.toString(16).padStart(2, '0')).join('');
}

// ---------------------------------------------------------------------------
// ABI encoding for the two ClaimGuardRegistry calls (all argument types are
// static, so encoding is fixed 32-byte words).
// ---------------------------------------------------------------------------
const word = (hex) => hex.replace(/^0x/, '').padStart(64, '0');

export function encodeAttestClaim({ opportunityId, target, detailHash, outcome, reason }) {
  const sel = functionSelector('attestClaim(bytes32,address,bytes32,uint8,uint8)');
  return '0x' + sel
    + word(opportunityId)
    + word(target)
    + word(detailHash)
    + word(BigInt(outcome).toString(16))
    + word(BigInt(reason).toString(16));
}

export function encodeRegisterAgent({ policyHash }) {
  const sel = functionSelector('registerAgent(bytes32)');
  return '0x' + sel + word(policyHash);
}

// ---------------------------------------------------------------------------
// Monitor outcome mapping: translate the live monitor's gate results into
// (outcome, reason) pairs. Keys match the monitor's event vocabulary.
// ---------------------------------------------------------------------------
export function mapGateResult(kind, detail = '') {
  const C = CLAIMGUARD;
  switch (kind) {
    case 'GRAB_EXECUTED':
    case 'CLAIMED_DIRECT':
      return { outcome: C.OUTCOME_PASSED, reason: C.REASON_NONE };
    case 'GRAB_FAILED':
    case 'CLAIM_FAILED':
      return { outcome: C.OUTCOME_REFUSED, reason: C.REASON_HELPER_REFUSED };
    case 'CUSTOM_TOKEN':
      return { outcome: C.OUTCOME_REFUSED, reason: C.REASON_CUSTOM_TOKEN };
    case 'NEEDS_REVIEW':
      return { outcome: C.OUTCOME_REFUSED, reason: C.REASON_UNEXPECTED_CALL_SET };
    case 'NEEDS_CODE':
      return { outcome: C.OUTCOME_REFUSED, reason: C.REASON_CODE_REQUIRED };
    case 'PREVIEW_BLOCKED':
      if (/to=|target|contract/i.test(detail)) return { outcome: C.OUTCOME_REFUSED, reason: C.REASON_PREVIEW_TARGET_MISMATCH };
      if (/value/i.test(detail)) return { outcome: C.OUTCOME_REFUSED, reason: C.REASON_PREVIEW_VALUE_NONZERO };
      return { outcome: C.OUTCOME_REFUSED, reason: C.REASON_PREVIEW_BLOCKED };
    default:
      return { outcome: C.OUTCOME_REFUSED, reason: C.REASON_OTHER };
  }
}

// ---------------------------------------------------------------------------
// Submission (used only when wired in AND enabled AND not dry-run).
// Mirrors the monitor's preview -> validate -> execute discipline.
// ---------------------------------------------------------------------------
function run(cmd, args, timeoutMs = 90000) {
  return new Promise((resolve) => {
    execFile(cmd, args, { timeout: timeoutMs, maxBuffer: 8 * 1024 * 1024 }, (err, stdout, stderr) => {
      resolve({ code: err ? (err.code ?? 1) : 0, stdout: stdout || '', stderr: stderr || '' });
    });
  });
}
function parseJson(text) { try { return JSON.parse(text); } catch { const m = text.match(/\{[\s\S]*\}/); if (m) { try { return JSON.parse(m[0]); } catch { return null; } } return null; } }

export function claimguardConfig(env = process.env) {
  return {
    enabled: env.CLAIMGUARD_ATTEST === '1',
    dryRun: env.CLAIMGUARD_ATTEST_DRY_RUN !== '0',
    registry: (env.CLAIMGUARD_REGISTRY || '0x9B6f33D9aE6B01eb56e44DADA9F7FF2fAB9B0d14').toLowerCase(), // deployed 2026-11-21, tx 0x1bb3d960b9a0a4bff0dae413ff2876ccac1c2e831df5f1b2276738c8560041f6
    agent: '0x4aD5326c31a11a5766744bD65BFEb8838A6dCfc8', // meevm.ai (Agent ID holder)
    chainId: '56', // BNB Chain mainnet
  };
}

/// Record one gate outcome on-chain. Never throws; returns a status object.
/// In production wiring this is called AFTER the monitor has finished the
/// packet (grab executed or definitively refused), never before a claim.
export async function attestGateOutcome({ packetId, target, kind, detail = '', detailRecord = null }, env = process.env) {
  const cfg = claimguardConfig(env);
  if (!cfg.enabled || !cfg.registry) return { status: 'disabled' };
  const { outcome, reason } = mapGateResult(kind, detail);
  const opportunityId = keccak256Hex(`agentid.im:hongbao:${packetId}`);
  const detailHash = keccak256Hex(JSON.stringify(detailRecord ?? { packetId, kind, detail }));
  const inputData = encodeAttestClaim({ opportunityId, target, detailHash, outcome, reason });
  if (cfg.dryRun) return { status: 'dry-run', to: cfg.registry, inputData };

  const pv = await run('baw', [
    'contract-call', 'preview',
    '--binanceChainId', cfg.chainId,
    '--from', cfg.agent,
    '--to', cfg.registry,
    '--value', '0',
    '--inputData', inputData,
    '--json',
  ]);
  const pj = parseJson(pv.stdout);
  const requestId = pj?.requestId || pj?.data?.requestId || pj?.result?.requestId;
  const pTo = pj?.data?.to || pj?.to || pj?.data?.transaction?.to;
  if (!requestId) return { status: 'abort', why: 'attestation preview returned no requestId' };
  if (pTo && String(pTo).toLowerCase() !== cfg.registry) return { status: 'abort', why: `attestation preview to=${pTo} mismatch` };
  const ex = await run('baw', ['contract-call', 'execute', '--requestId', String(requestId), '--json']);
  const ej = parseJson(ex.stdout);
  if (!ej || ej.success === false) return { status: 'abort', why: 'attestation execute failed' };
  return { status: 'executed', tx: ej.data?.txHash || ej.txHash || 'unknown', inputData };
}

// ---------------------------------------------------------------------------
// Self-test: `node attest.mjs --selftest` — verifies the Keccak-256 vectors
// and prints the function selectors for cross-checking with `cast sig`.
// ---------------------------------------------------------------------------
if (import.meta.url === `file://${process.argv[1]}` && process.argv.includes('--selftest')) {
  const vectors = [
    ['', '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'],
    ['hello', '0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8'],
  ];
  let ok = true;
  for (const [input, expected] of vectors) {
    const got = keccak256Hex(input);
    console.log(`keccak256(${JSON.stringify(input)}) = ${got} ${got === expected ? 'OK' : `MISMATCH, expected ${expected}`}`);
    if (got !== expected) ok = false;
  }
  console.log('attestClaim selector   :', '0x' + functionSelector('attestClaim(bytes32,address,bytes32,uint8,uint8)'));
  console.log('registerAgent selector :', '0x' + functionSelector('registerAgent(bytes32)'));
  console.log('sample attest calldata :', encodeAttestClaim({
    opportunityId: keccak256Hex('agentid.im:hongbao:4'),
    target: '0xA39660B43c3F797d4bBEab8Df0e40D771565b8CE',
    detailHash: keccak256Hex('{"packetId":4}'),
    outcome: 1, reason: 7,
  }));
  process.exit(ok ? 0 : 1);
}
