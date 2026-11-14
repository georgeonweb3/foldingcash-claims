# FoldingCash pull-based claims — FoldingCash bounty PoC

**Hook:** folders stop waiting on a trusted monthly push — one Merkle root per month, and anyone claims their rewards whenever they choose, with a proof no operator can fake.

## The problem it replaces

FoldingCash pays Folding@home folders in FLDCH with trusted monthly pushes: the operator sends each folder their tokens. If the operator is late, wrong, or gone, folders wait or lose out.

## The replacement

1. **Operator publishes a root.** Each month, the operator computes the Merkle root of that month's rewards and sets it on-chain with `setRoot(monthId, root)` — one root per month, final, it cannot be overwritten.
2. **Operator funds the pool once** (`fund()`), instead of N pushes.
3. **Folders claim when they choose.** `claim(monthId, pubkey, amount, proof, sig, payout)` verifies the Merkle proof against the root, checks the leaf was never claimed, checks the signature against the claimant's pubkey, then pays out. Double-claims are blocked by the `claimed` set.

## Leaf format (off-chain and on-chain agree)

Leaf = `keccak256(hash160(pubkey) || amount)` where pubkey is the claimant's 33-byte compressed secp256k1 key, `hash160` is ripemd160(sha256(pubkey)) (the P2PKH address hash), and amount is a uint256. Pairs are sorted before hashing (OpenZeppelin `MerkleProof` convention). The same code runs in `src/merkle.js` and in the contract's `_verify`, so a proof generated off-chain verifies on-chain. (Changed Nov 14 from raw-pubkey leaves: evmCompat cannot `abi.encode` a `pubkey`, but `hash160(pubkey)` is a builtin — and the hash is the identity that actually owns BCH.)

## Run it

```sh
npm install
node demo.mjs
```

Expected: `15 passed, 0 failed.` — 8 folders' claims all verify, 4 tamper cases fail (wrong amount, wrong claimant, swapped proof element, wrong root), and double-claim protection holds (second claim of the same leaf rejected, other folders unaffected).

## Files

- `src/merkle.js` — `leafHash`, `buildTree`, `getProof`, `verifyProof`, `buildClaims`, `verifyClaim`.
- `demo.mjs` — one month of rewards for 8 folders (real secp256k1 keypairs) + full test suite.
- `contracts/FoldingPool.sol` — SolidCash (evmCompat) pool contract. **Compiles at 6,579 bytes** (under the 10,000-byte limit) with the same toolchain as the AegisBCH guard (see the [aegis-bch repo](https://github.com/georgeonweb3/aegis-bch)). `leafOf` on-chain returns exactly the JS leaf. The full `claim` call is still unproven on the mock network (framework derive/preflight issue, bisected Nov 14 — no single piece is the culprit; needs a Chipnet run to settle). The claimed flag is a `uint256` (0/1), not a `bool`: writing `true` to a `mapping(bytes32 => bool)` fails the mock preflight in solidc 0.50.0.

## Production note

The PoC pool pays native BCH. Production swaps the payout to the FLDCH CashToken: same claim logic, token transfer instead of a native transfer, once FoldingCash wires its token into the pool.

## Bounty fit

BCH BLAZE 2026 — FoldingCash, 0.5 BCH: "Replace FoldingCash's trusted monthly token pushes with pull-based claims: an on-chain Merkle root of earned rewards, and a pool contract users claim from with a proof, whenever they choose." This is that design, with the Merkle layer tested and the pool contract drafted.
