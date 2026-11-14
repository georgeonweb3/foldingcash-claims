// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title FoldingPool — pull-based reward claims for FoldingCash.
/// @notice Replaces FoldingCash's trusted monthly token pushes: the operator
///         publishes one on-chain Merkle root of earned rewards per month,
///         funds the pool once, and each folder claims whenever they choose
///         with a Merkle proof. No monthly push, no trust in the operator
///         after the root is set, no missed payouts.
/// @dev BCH adaptations (SolidCash evmCompat, lean lessons from AegisBCH):
///      - Claimant identity is the 33-byte compressed pubkey, bound to the
///        leaf through its hash160: leaf = keccak256(hash160(pubkey) ||
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

    constructor(pubkey _adminKey) {
        adminKey = _adminKey;
    }

    /// @notice Operator publishes a month's Merkle root. One root per month, final.
    function setRoot(uint256 monthId, bytes32 root, sig s) external {
        require(checkSig(s, adminKey));
        require(roots[monthId] == bytes32(0));
        roots[monthId] = root;
    }

    /// @notice Claim earned rewards for a month. The claimant's signature
    ///         over this transaction proves they hold the key in the leaf.
    function claim(
        uint256 monthId,
        pubkey claimant,
        uint256 amount,
        bytes32[] calldata proof,
        sig s,
        address payable payout
    ) external {
        require(checkSig(s, claimant));
        bytes32 root = roots[monthId];
        require(root != bytes32(0));
        require(amount != 0);

        bytes32 leaf = keccak256(abi.encodePacked(hash160(claimant), amount));
        require(claimed[leaf] == 0);
        require(_verify(proof, root, leaf));

        claimed[leaf] = 1;
        payout.transfer(amount);
    }

    /// @notice Sorted-pair Merkle proof verification (OpenZeppelin convention,
    ///         same as src/merkle.js verifyProof).
    function _verify(bytes32[] calldata proof, bytes32 root, bytes32 leaf) internal pure returns (bool) {
        bytes32 hash = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 el = proof[i];
            hash = hash <= el
                ? keccak256(abi.encodePacked(hash, el))
                : keccak256(abi.encodePacked(el, hash));
        }
        return hash == root;
    }

    /// @notice The leaf for (claimant, amount): keccak256(hash160(pubkey) || amount).
    ///         Off-chain builders must produce the same leaf (src/merkle.js).
    function leafOf(pubkey claimant, uint256 amount) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(hash160(claimant), amount));
    }

    function getRoot(uint256 monthId) external view returns (bytes32) {
        return roots[monthId];
    }
}
