// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title FoldingPool — pull-based reward claims for FoldingCash.
/// @notice Replaces FoldingCash's trusted monthly token pushes: the operator
///         publishes one on-chain Merkle root of earned rewards per month,
///         funds the pool once, and each folder claims whenever they choose
///         with a Merkle proof. No monthly push, no trust in the operator
///         after the root is set, no missed payouts.
/// @dev BCH adaptations (SolidCash evmCompat):
///      - Claimant identity is the 33-byte compressed pubkey. The leaf is
///        keccak256(pubkey || amount), matching src/merkle.js exactly, so
///        the off-chain proof generator and the on-chain verifier agree.
///        The claimant authorizes with checkSig(sig, pubkey): only the key
///        in the leaf can spend the claim transaction.
///      - The pool holds native BCH in this PoC. Production swaps the
///        payout to the FLDCH CashToken (same claim logic, token transfer
///        instead of a native transfer) once FoldingCash wires its token.
///      - The operator sets each month's root by signature (checkSig vs
///        the stored admin pubkey). A root, once set for a month id, cannot
///        be overwritten — the operator cannot rug a published month.
///      - Double-claims are blocked by the claimed[leaf] set.

contract FoldingPool {
    pubkey public adminKey;
    mapping(uint256 => bytes32) public roots; // monthId => Merkle root
    mapping(bytes32 => bool) public claimed; // leaf => claimed

    event RootSet(uint256 indexed monthId, bytes32 root);
    event Claimed(bytes32 indexed leaf, pubkey indexed claimant, uint256 amount);

    error NotAdmin();
    error NotClaimant();
    error RootAlreadySet();
    error RootNotSet();
    error AlreadyClaimed();
    error InvalidProof();
    error InvalidAmount();

    constructor(pubkey _adminKey) {
        adminKey = _adminKey;
    }

    /// @notice Fund the pool with BCH (anyone can top it up).
    function fund() external payable {}

    /// @notice Operator publishes a month's Merkle root. One root per month, final.
    function setRoot(uint256 monthId, bytes32 root, sig s) external {
        if (!checkSig(s, adminKey)) revert NotAdmin();
        if (roots[monthId] != bytes32(0)) revert RootAlreadySet();
        roots[monthId] = root;
        emit RootSet(monthId, root);
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
        if (!checkSig(s, claimant)) revert NotClaimant();
        bytes32 root = roots[monthId];
        if (root == bytes32(0)) revert RootNotSet();
        if (amount == 0) revert InvalidAmount();

        bytes32 leaf = keccak256(abi.encodePacked(claimant, amount));
        if (claimed[leaf]) revert AlreadyClaimed();
        if (!_verify(proof, root, leaf)) revert InvalidProof();

        claimed[leaf] = true;
        payout.transfer(amount);
        emit Claimed(leaf, claimant, amount);
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

    function getRoot(uint256 monthId) external view returns (bytes32) {
        return roots[monthId];
    }
}
