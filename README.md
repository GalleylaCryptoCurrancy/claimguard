# ClaimGuard

**An Agent ID-gated safe-claim registry for autonomous agents on BNB Chain.**

Autonomous agents claim value-bearing opportunities — red packets, mints, airdrops — on
behalf of their owners. That is exactly where scam contracts and drainer previews strike,
and today an agent's safety decisions leave no public trace.

ClaimGuard fixes the traceability half of that problem:

1. Any **Agent ID** holder registers on-chain, declaring a hash of their agent's published
   safety policy.
2. After every safety-gate evaluation, the agent's tooling writes an **attestation**:
   `PASSED` (all gates green, claim proceeded) or `REFUSED` (a gate stopped the claim),
   with a machine-readable reason code.
3. Anyone can audit the result — registrations, policy hashes, counters, and the full
   `ClaimAttested` event stream are public.

The reference integration is the production red-packet monitor described below: it watches
agentid.im hongbao packets — claimable **only by Agent ID holders** — evaluates each one
through fail-closed gates, and attests every outcome on-chain. The integration is wired
into the live monitor and enabled (since 2026-11-21); it is fail-open by construction, so
an attestation failure can never affect a claim decision.

## Live deployment (BNB Chain mainnet)

| | |
|---|---|
| Contract | [`ClaimGuardRegistry` — 0x9B6f33D9aE6B01eb56e44DADA9F7FF2fAB9B0d14](https://bscscan.com/address/0x9B6f33D9aE6B01eb56e44DADA9F7FF2fAB9B0d14) |
| Deployment tx | [0x1bb3d960b9a0a4bff0dae413ff2876ccac1c2e831df5f1b2276738c8560041f6](https://bscscan.com/tx/0x1bb3d960b9a0a4bff0dae413ff2876ccac1c2e831df5f1b2276738c8560041f6) (2026-11-21) |
| Verified source | [Sourcify — exact (full) match](https://sourcify.dev/#/lookup/0x9B6f33D9aE6B01eb56e44DADA9F7FF2fAB9B0d14) (creation + runtime bytecode). BscScan verification is being completed separately; until it lands, the Sourcify record is the canonical verification. |
| First registered agent | `meevm.ai` — 0x4aD5326c31a11a5766744bD65BFEb8838A6dCfc8, policy hash 0x6ee9a219326b35bf406d52bff00098e07d31d717bd2bfe4a95fbfd00b944bbdb (keccak256 of this README) |
| Counters at publication (read on-chain 2026-11-21) | 1 registered agent · 3 attestations · 0 passed · 3 refused — the three seed attestations are real `CODE_REQUIRED` refusals from the production monitor (packets #3/#4/#5), not synthetic data |

## Register your agent

Registration is open to any Agent ID holder, costs no protocol fee, and takes one
transaction:

1. **Hold an Agent ID** in a BNB Chain wallet (the contract checks
   `balanceOf(yourAddress) > 0` in the official registry
   `0x60B9262456dE011F7d15a54CdD8c48bAaa8B022F`).
2. **Publish your agent's safety policy** anywhere public (a repo README is fine) and
   compute its keccak256 hash — that hash is your `policyHash`.
3. **Call `registerAgent(policyHash)`** on
   `0x9B6f33D9aE6B01eb56e44DADA9F7FF2fAB9B0d14` from the holder wallet — via BscScan's
   *Write Contract*, your wallet's contract-interaction feature, or:
   ```bash
   cast send 0x9B6f33D9aE6B01eb56e44DADA9F7FF2fAB9B0d14 \
     "registerAgent(bytes32)" <YOUR_POLICY_HASH> \
     --rpc-url <BSC_RPC> --private-key <HOLDER_KEY>
   ```
   **Gas cost:** the measured registration transaction used 95,873 gas — about
   **0.000005 BNB (≈ $0.003)** at the 0.05 gwei gas price seen at deployment, and still
   only ≈ 0.0001 BNB (≈ $0.05) at 1 gwei. One record per address; re-registering reverts.
4. **Attest your gate outcomes** with `attestClaim(opportunityId, target, detailHash,
   outcome, reason)` after each safety-gate evaluation — or reuse the reference hook in
   [`monitor-integration/attest.mjs`](monitor-integration/attest.mjs).

## How Agent ID is used

Agent ID is the access key, not decoration:

- `registerAgent()` checks the caller's balance in the **official Agent ID registry**
  (`0x60B9262456dE011F7d15a54CdD8c48bAaa8B022F`, SPACE ID Agent ID) and reverts for
  non-holders.
- Attestations are written by, and indexed under, the registered agent's address, so an
  Agent ID holder's safety record is publicly readable.
- The monitored opportunity class (Agent ID red packets) exists only for Agent ID holders.

## Contract: `ClaimGuardRegistry`

| Function | Behaviour |
|---|---|
| `registerAgent(bytes32 policyHash)` | Agent ID holders only; one record per address; `policyHash` must be non-zero. Emits `AgentRegistered`. |
| `attestClaim(bytes32 opportunityId, address target, bytes32 detailHash, uint8 outcome, uint8 reason)` | Registered agents only. A pass requires reason `NONE`; a refusal requires a non-zero reason. Emits `ClaimAttested`. |
| `isRegisteredAgent(address)` | View. |
| `agentPolicy(address)` / `agentRecord(address)` | Views: declared policy hash and registration record. |
| `agentCount` / `attestationCount` / `passCount` / `refuseCount` | Public counters. |

### Reason codes

| Code | Name | Meaning (from the production monitor) |
|---|---|---|
| 0 | `NONE` | Gate passed (required for `PASSED`) |
| 1 | `HELPER_REFUSED` | The claim helper refused the opportunity |
| 2 | `CUSTOM_TOKEN` | Non-standard token — never auto-claimed |
| 3 | `UNEXPECTED_CALL_SET` | Helper produced something other than exactly one call |
| 4 | `PREVIEW_TARGET_MISMATCH` | Signed preview did not name the expected contract |
| 5 | `PREVIEW_VALUE_NONZERO` | Preview carried a non-zero value |
| 6 | `PREVIEW_BLOCKED` | Preview error, risk flag, or execution failure |
| 7 | `CODE_REQUIRED` | Held for a human-supplied code/passphrase |
| 8 | `OTHER` | Any other fail-closed stop |

### Owner permissions & asset safety (explicit, per program rules)

- **The contract has no owner.** There are no admin functions of any kind: no mint, no
  pause, no freeze, no withdraw, no upgrade path, no fee setting.
- **The contract is asset-free by construction:** no payable functions, no `receive` /
  `fallback`, no token transfers, no approvals requested or granted. The only immutable
  configuration is the Agent ID registry address set once in the constructor.
- Registration and attestation are free of any protocol fee; users pay only BNB Chain gas.

## The safety gates (reference monitor)

The monitor that produces the attestations evaluates every opportunity fail-closed:

1. **Helper-only calls** — only calls produced by the audited claim helper are executed.
2. **Exactly one call** per claim.
3. **Exact preview validation** — the signing preview must name the expected contract and
   the exact incoming asset with value `0`; Binance "Risky Txn Handling = AutoReject" is on.
4. **Standard assets only** (BNB / USDT / USDC) — custom tokens are refused and reported.
5. **Code-gated packets are held** for a human-supplied code, never guessed.
6. Attestations are written **after** the gate decision and go through the same
   preview → validate → execute discipline; an attestation failure never alters a claim
   decision.

## Repository layout

```
src/ClaimGuardRegistry.sol        the contract (dependency-free, MIT)
test/ClaimGuardRegistry.t.sol     Foundry tests (registration gate, attestations,
                                  counters, asset-free invariants) — 17 tests
script/Deploy.s.sol               deployment script (registry address via env)
monitor-integration/attest.mjs    monitor attestation hook — in the production
                                  deployment this module is wired into the live
                                  monitor and enabled (config-gated, fail-open;
                                  disabled + dry-run by default when unconfigured)
site/index.html                   the static project site
docs/index.html                   byte-identical copy of the site, served by
                                  GitHub Pages
```

## Build & test

```bash
forge install foundry-rs/forge-std   # dev-only test dependency
forge build
forge test
```

## Deployment (done — BNB Chain mainnet, 2026-11-21)

The contract is deployed and live at
`0x9B6f33D9aE6B01eb56e44DADA9F7FF2fAB9B0d14` (see *Live deployment* above). It was
deployed with the script in this repository; the deployer key was supplied via the
environment at deploy time only and is never stored in this repository:

```bash
AGENT_ID_REGISTRY=0x60B9262456dE011F7d15a54CdD8c48bAaa8B022F \
forge script script/Deploy.s.sol --rpc-url $BSC_RPC --broadcast --private-key $DEPLOYER_KEY
```

After deployment the source was verified on Sourcify (exact match), the address was
published on the project site, `CLAIMGUARD_REGISTRY` was set for the monitor
integration, and the operating agent (`meevm.ai`) registered itself as agent #1.

## Risk notice

ClaimGuard is a record-keeping and safety-gating tool. It does not hold, manage, or move
user assets, and it makes no promise of returns of any kind. Interacting with any smart
contract carries risk; review the verified source before registering. ClaimGuard is an
independent project built for the Binance Agent ID Hackathon; it is not affiliated with or
endorsed by Binance.

## License

MIT — see [LICENSE](LICENSE).
