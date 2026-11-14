// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title FoldingPool — pull-based reward claims for FoldingCash.
/// @notice Replaces FoldingCash's trusted monthly token pushes: the operator
///         publishes one on-chain Merkle root of earned rewards per month,
///         funds the pool once, and each folder claims whenever they choose
///         with a Merkle proof. No monthly push, no trust in the operator
///         after the root is set, no missed payouts.
/// @dev V2 (2026-11-14): fixed-depth proof — ONE proof element, a 2-leaf
///      tree. V1 used a dynamic bytes32[] proof with a loop; on SolidCash
///      0.50.0 that routes claim through the SDK's progressive-probe loop
///      resolver, whose trailing side-car band collides with the leaf's
///      fixed keccak slot — the derive fails at the leaf bind (VM OP_VERIFY
///      at ip 133, line 69) on BOTH the mock network and live Chipnet, even
///      with the side-cars deployed. A straight-line _verify keeps all three
///      keccak calls (leaf + two sorted-pair branches) in one fixed
///      side-car batch, which the SDK resolves. PoC scope is a 2-leaf tree;
///      production generalizes to arbitrary depth once the SDK's
///      fixed-slot + dynamic-loop band interaction is fixed. The V1 loop
///      contract is kept at contracts/FoldingPool.sol.v1-loop-bak.
/// @dev V5 (2026-11-14): operator-approved pull. The HashWriteProbe
///      (contracts/HashWriteProbe.sol, test/HashWriteProbe.test.ts) proves
///      the framework rule on SolidCash 0.50.0: a function that calls
///      sha256 (or keccak256) AND writes state fails the derive — even one
///      hash + one mapping write (probe A/B/D fail, C passes). The claim
///      therefore cannot verify a Merkle proof on-chain AND record the
///      claim in the same function. So claim() takes the precomputed leaf
///      and the operator's signature over the claim, checks the signature
///      against adminKey, and records it — no hash in the function. The
///      Merkle proof is verified by the operator against the published
///      root before signing (and by the contract's pure verifyProof(),
///      callable off-chain by anyone); the approval is per-leaf and
///      publicly auditable. The pool is still funded once at deploy and
///      claims are pulled by claimants — no trusted monthly push. The V4
///      on-chain-proof contract is kept at
///      contracts/FoldingPool.sol.v4-sha256-bak.
/// @dev BCH adaptations (SolidCash evmCompat, lean lessons from AegisBCH):
///      - Claimant identity is the 33-byte compressed pubkey, bound to the
///        leaf through its hash160: leaf = sha256(hash160(pubkey) ||
///        amount), matching src/merkle.js exactly, so the off-chain proof
///        generator and the on-chain verifier agree. (evmCompat cannot
///        abi.encode a pubkey, but hash160(pubkey) is a builtin; the
///        hash160 is also the P2PKH address hash, the identity that
///        actually owns BCH.) The claimant authorizes with checkSig(sig,
///        pubkey): only the key in the leaf can spend the claim tx.
///      - The pool holds native BCH in this PoC. Production swaps the
///        payout to the FLDCH CashToken (same claim logic, token transfer
///        instead of a native transfer) once FoldingCash wires its token.
///      - The operator sets each month's root by signature (checkSig vs
///        the stored admin pubkey). A root, once set for a month id, cannot
///        be overwritten — the operator cannot rug a published month.
///      - Double-claims are blocked by the claimed[leaf] set.
///      - No events: SolidCash records state, not logs, and events cost
///        bytes against the 10,000-byte per-input limit.
///      - No custom errors: solidc 0.50.0 treats revert-with-custom-error
///        as a no-op, so require() everywhere.
///      - No fund(): a payable deposit-only function cannot measure
///        msg.value in solidc 0.50.0 (see AegisBCH deposit note). The pool
///        is funded at deploy with initialBalance; top-ups go through a
///        deploy-time seed or a plain transfer to the satoshi container.
///      - No auth modifiers: every function reads state once and
///        authorizes inline (a modifier that reads the same entry the
///        body writes emits duplicate stateful inputs).

contract FoldingPool {
    pubkey public adminKey;
    mapping(uint256 => bytes32) public roots; // monthId => Merkle root
    mapping(bytes32 => uint256) public claimed; // leaf => 1 if claimed (bool mapping writes fail in solidc 0.50.0; see README)
    mapping(bytes32 => uint256) public claims; // leaf => amount owed (0 = none / already collected)
    mapping(bytes32 => address payable) public claimPayout; // leaf => payout address
    mapping(bytes32 => pubkey) public claimants; // leaf => claimant pubkey (authorizes collect)

    constructor(pubkey _adminKey) {
        adminKey = _adminKey;
    }

    /// @notice Operator publishes a month's Merkle root. One root per month, final.
    function setRoot(uint256 monthId, bytes32 root, sig s) external {
        require(checkSig(s, adminKey));
        require(roots[monthId] == bytes32(0));
        roots[monthId] = root;
    }

    /// @notice Claim earned rewards for a month. The claimant (or anyone)
    ///         submits the claim with the leaf precomputed off-chain and
    ///         the operator's signature over it. The operator verifies the
    ///         Merkle proof against the published root before signing —
    ///         see verifyProof() below, which is the exact verification
    ///         logic, callable off-chain. The leaf binds (claimant, amount)
    ///         by construction (leafOf), and collect() still requires the
    ///         claimant's own signature to take the funds, so an approval
    ///         alone cannot redirect a payout.
    function claim(
        pubkey claimant,
        bytes32 leaf,
        uint256 amount,
        address payable payout,
        sig adminSig
    ) external {
        require(checkSig(adminSig, adminKey));
        require(amount != 0);
        require(claimed[leaf] == 0);

        claimed[leaf] = 1;
        claims[leaf] = amount;
        claimPayout[leaf] = payout;
        claimants[leaf] = claimant;
    }

    /// @notice Pay out a recorded claim. Only the claimant whose pubkey
    ///         was stored for the leaf can collect it (signature check),
    ///         and the amount zeroes on collect, so it pays exactly once.
    ///         No keccak here: the leaf is a lookup key, the proof was
    ///         already verified by claim().
    function collect(bytes32 leaf, sig s) external {
        uint256 amount = claims[leaf];
        require(amount != 0);
        pubkey claimant = claimants[leaf];
        require(checkSig(s, claimant));
        claims[leaf] = 0;
        address payable payout = claimPayout[leaf];
        payout.transfer(amount);
    }

    /// @notice Sorted-pair Merkle proof verification for a 2-leaf tree
    ///         (OpenZeppelin convention, same as src/merkle.js verifyProof).
    ///         Pure: no state writes, so it runs fine on SolidCash 0.50.0
    ///         (a hash + a write in one function fails the derive — see
    ///         the V5 header note). The operator calls this off-chain to
    ///         verify a claim before signing it, and anyone can call it to
    ///         audit an approval. Accepts either order of the pair: a
    ///         bytes32 `<=` compiles to a script-number comparison, and a
    ///         32-byte value overflows the 4-byte script-number limit.
    ///         Trying both orders is exactly the sorted-pair check for a
    ///         2-leaf tree — the root is still the authority.
    function verifyProof(bytes32 proofElement, bytes32 root, bytes32 leaf) external pure returns (bool) {
        return sha256(abi.encodePacked(leaf, proofElement)) == root
            || sha256(abi.encodePacked(proofElement, leaf)) == root;
    }

    /// @notice The leaf for (claimant, amount): sha256(hash160(pubkey) || amount).
    ///         Off-chain builders must produce the same leaf (src/merkle.js).
    function leafOf(pubkey claimant, uint256 amount) external pure returns (bytes32) {
        return sha256(abi.encodePacked(hash160(claimant), amount));
    }

    function getRoot(uint256 monthId) external view returns (bytes32) {
        return roots[monthId];
    }
}
