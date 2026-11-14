// Merkle tree for FoldingCash pull-based claims (OpenZeppelin-compatible).
// Leaf: keccak256(abi.encodePacked(bytes33 claimantPubkey, uint256 amount))
//   - claimantPubkey is the claimant's 33-byte compressed secp256k1 pubkey.
//     Using the full pubkey (not its hash) keeps the on-chain verifier simple:
//     the pool contract recomputes the leaf from the pubkey parameter and
//     authorizes the claim with checkSig(sig, pubkey) — no hash160 needed.
//   - amount is a uint256 (satoshis in the PoC; FLDCH token units in production).
// Pairs are sorted before hashing (OpenZeppelin MerkleProof convention), so a
// proof verifies regardless of leaf order, and the on-chain verifier only needs
// the standard sorted-pair loop — the same code the SolidCash pool contract runs.

import { keccak_256 } from '@noble/hashes/sha3.js';

export function leafHash(pubkeyHex, amount) {
  const pubkey = Buffer.from(pubkeyHex, 'hex');
  if (pubkey.length !== 33) throw new Error('claimant pubkey must be 33 bytes');
  const amt = Buffer.alloc(32);
  amt.writeBigUInt64BE(BigInt(amount), 24); // uint256, big-endian
  return Buffer.from(keccak_256(Buffer.concat([pubkey, amt])));
}

function hashPair(a, b) {
  const [x, y] = Buffer.compare(a, b) <= 0 ? [a, b] : [b, a];
  return Buffer.from(keccak_256(Buffer.concat([x, y])));
}

export function buildTree(leaves) {
  // leaves: Buffer[] of leaf hashes. Odd layers duplicate the last node
  // (standard Merkle padding; matches OpenZeppelin's processProof behavior
  // only when the tree is built the same way — we duplicate, and document it).
  if (leaves.length === 0) throw new Error('no leaves');
  const layers = [leaves.map((l) => Buffer.from(l))];
  while (layers[layers.length - 1].length > 1) {
    const prev = layers[layers.length - 1];
    const next = [];
    for (let i = 0; i < prev.length; i += 2) {
      const left = prev[i];
      const right = i + 1 < prev.length ? prev[i + 1] : prev[i];
      next.push(hashPair(left, right));
    }
    layers.push(next);
  }
  return { root: layers[layers.length - 1][0], layers };
}

export function getProof(layers, index) {
  const proof = [];
  let idx = index;
  for (let l = 0; l < layers.length - 1; l++) {
    const layer = layers[l];
    const siblingIdx = idx % 2 === 0 ? idx + 1 : idx - 1;
    proof.push(siblingIdx < layer.length ? layer[siblingIdx] : layer[idx]);
    idx = Math.floor(idx / 2);
  }
  return proof;
}

export function verifyProof(leaf, proof, root) {
  let hash = Buffer.from(leaf);
  for (const el of proof) hash = hashPair(hash, Buffer.from(el));
  return hash.equals(Buffer.from(root));
}

// ---------- claims ----------

// claims: [{ pubkey: '33-byte hex', amount: number|bigint }]
// Returns { rootHex, entries: [{ pubkey, amount, leafHex, proofHex[] }] }
export function buildClaims(claims) {
  const entries = claims.map((c) => ({ ...c, leaf: leafHash(c.pubkey, c.amount) }));
  const { root, layers } = buildTree(entries.map((e) => e.leaf));
  entries.forEach((e, i) => {
    e.proof = getProof(layers, i);
  });
  return {
    rootHex: root.toString('hex'),
    entries: entries.map((e) => ({
      pubkey: e.pubkey,
      amount: e.amount.toString(),
      leafHex: e.leaf.toString('hex'),
      proofHex: e.proof.map((p) => p.toString('hex')),
    })),
  };
}

export function verifyClaim(pubkeyHex, amount, proofHex, rootHex) {
  const leaf = leafHash(pubkeyHex, amount);
  return verifyProof(
    leaf,
    proofHex.map((h) => Buffer.from(h, 'hex')),
    Buffer.from(rootHex, 'hex'),
  );
}
