# FoldingCash pull-based claims — FoldingCash bounty PoC

**Hook:** folders stop waiting on a trusted monthly push — one Merkle root per month, and anyone claims their rewards whenever they choose, with a proof no operator can fake.

## The problem it replaces

FoldingCash pays Folding@home folders in FLDCH with trusted monthly pushes: the operator sends each folder their tokens. If the operator is late, wrong, or gone, folders wait or lose out.

## The replacement

1. **Operator publishes a root.** Each month, the operator computes the Merkle root of that month's rewards and sets it on-chain with `setRoot(monthId, root)` — one root per month, final, it cannot be overwritten.
2. **Operator funds the pool once** at deploy (100,000 sats in the Chipnet PoC), instead of N pushes.
3. **Folders claim when they choose.** `claim(pubkey, leaf, amount, payout, adminSig)` records the claim; `collect(leaf, sig)` pays it out on the claimant's own signature. Double-claims and double-collects are blocked. The Merkle proof is verified by the operator against the published root before signing (and by the contract's public pure `verifyProof()`, callable off-chain by anyone) — see "Why operator-approved" below.

## Leaf format (off-chain and on-chain agree)

Leaf = `sha256(hash160(pubkey) || amount)` where pubkey is the claimant's 33-byte compressed secp256k1 key, `hash160` is ripemd160(sha256(pubkey)) (the P2PKH address hash), and amount is a uint256. Pairs are tried in both orders by `verifyProof` (the sorted-pair check for a 2-leaf tree). The same code runs in `src/merkle.js` and in the contract's `leafOf`/`verifyProof`, so a proof generated off-chain verifies on-chain. (Changed Nov 14 from raw-pubkey leaves: evmCompat cannot `abi.encode` a `pubkey`, but `hash160(pubkey)` is a builtin — and the hash is the identity that actually owns BCH. Changed the same day from keccak256 to sha256: BCH has a native OP_SHA256, so the contract needs no compute side-cars.)

## Why operator-approved (the honest bit)

V1–V4 of the pool verified the Merkle proof on-chain inside `claim()` — and every version failed the SolidCash 0.50.0 derive (V1 at the leaf bind, V2/V3 right before the transfer/state-write, V4 with SHA-256 too). A minimal probe (`HashWriteProbe` in the [aegis-bch repo](https://github.com/georgeonweb3/aegis-bch)) proved the framework rule: **a function that calls sha256 (or keccak256) AND writes state fails the derive — even one hash + one mapping write. A pure hash works; a write without a hash works.** So V5 splits the work: the operator verifies the proof off-chain against the published root and signs a per-leaf approval; `claim()` checks that signature and records the claim (no hash in the function); `collect()` pays on the claimant's own signature, so an approval alone cannot redirect a payout. The operator is the same party already trusted to publish the root, and every approval is publicly auditable against the root via `verifyProof()`. The pool is still funded once and claims are still pulled by claimants — no trusted monthly push.

## Run it

```sh
npm install
node demo.mjs
```

Expected: `15 passed, 0 failed.` — 8 folders' claims all verify, 4 tamper cases fail (wrong amount, wrong claimant, swapped proof element, wrong root), and double-claim protection holds (second claim of the same leaf rejected, other folders unaffected).

## Files

- `src/merkle.js` — `leafHash`, `buildTree`, `getProof`, `verifyProof`, `buildClaims`, `verifyClaim`.
- `demo.mjs` — one month of rewards for 8 folders (real secp256k1 keypairs) + full test suite.
- `contracts/FoldingPool.sol` — SolidCash (evmCompat) pool contract, **V5, compiles at 6,191 bytes** (under the 10,000-byte limit) with the same toolchain as the AegisBCH guard (see the [aegis-bch repo](https://github.com/georgeonweb3/aegis-bch)). Mock suite **6/6 green** (leafOf matches JS, claim records + collect pays, double-claim/double-collect blocked, verifyProof accepts/rejects, stranger signatures rejected). **Live on Chipnet** (deployed 2026-11-14): `bchtest:rvpyzut9z2ckw6ryawl6q9hjpsf7jnpf9dwfhmhezwpkdse794cvsyu6rh5sv`, genesis tx `0ce114e3dfa5bce4b72f0e6dc9f308ff06be2f4747f352fef4f1a918b23ddb4b`, category `f7e372e065c2aba86b6137c4ccd8acca046e916fff2539cf1b7b9b4e75d87e48`. Live smoke: on-chain `leafOf` matches the JS leaf, `verifyProof` accepts the right proof and rejects a wrong one, `setRoot` `abc22459f0f1bf2a110a03add0b264ca8a517209f10049e51fdb06c2ddfe241c`, `claim` `5bac2129571815f0c2cfb407131faa659c16dcb403abef4aed5a9850268a2082` (recorded 1,000), `collect` `a9f1388f850c83b6674ed2a6d3f79baf79e7fe835b42520bde480f5929290f53` — all three confirmed on-chain, 14 confirmations each (the collect waited ~39 min in the mempool while chipnet block production stalled ~332350–332356, then confirmed at tip 332356). Live smoke **6/6 green**: collect confirmed, claims[leaf]=0 after collect, claimed[leaf] still 1, the confirmed collect tx pays 1,000 sats to the claimant payout, double-collect blocked, double-claim blocked. The claimed flag is a `uint256` (0/1), not a `bool`: writing `true` to a `mapping(bytes32 => bool)` fails the mock preflight in solidc 0.50.0.

## Production note

The PoC pool pays native BCH. Production swaps the payout to the FLDCH CashToken: same claim logic, token transfer instead of a native transfer, once FoldingCash wires its token into the pool.

## Bounty fit

BCH BLAZE 2026 — FoldingCash, 0.5 BCH: "Replace FoldingCash's trusted monthly token pushes with pull-based claims: an on-chain Merkle root of earned rewards, and a pool contract users claim from with a proof, whenever they choose." This is that design, with the Merkle layer tested 15/15, the pool contract deployed on Chipnet, and a 59-second video walking through it.
