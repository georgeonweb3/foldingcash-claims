// Demo + test suite for the FoldingCash Merkle-claims PoC.
// Simulates one month of Folding@home rewards for 8 folders, builds the
// Merkle root + proofs, verifies every claim, and checks the tamper cases
// plus double-claim protection (the claimed-set the pool contract enforces).
// Run: node demo.mjs — exit 0 only if every check passes.

import { randomBytes } from 'node:crypto';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { buildClaims, verifyClaim } from './src/merkle.js';

let passed = 0;
let failed = 0;
function check(name, cond, extra = '') {
  if (cond) {
    passed++;
    console.log(`  PASS  ${name}`);
  } else {
    failed++;
    console.log(`  FAIL  ${name} ${extra}`);
  }
}

function fakeFolder(seed) {
  // Real secp256k1 keypair; the compressed pubkey is the claimant identity.
  const privkey = secp256k1.utils.randomPrivateKey
    ? secp256k1.utils.randomPrivateKey()
    : randomBytes(32);
  const pubkey = secp256k1.getPublicKey(privkey, true);
  return Buffer.from(pubkey).toString('hex');
}

console.log('FoldingCash pull-based claims — PoC demo\n');

// 8 folders, one month of earned FLDCH (amounts in satoshi-sized units for the PoC).
const folders = Array.from({ length: 8 }, (_, i) => ({
  name: `folder-${i + 1}`,
  pubkey: fakeFolder(`folder-${i + 1}`),
  amount: 1000n * BigInt((i + 1) * 137),
}));
const total = folders.reduce((s, f) => s + f.amount, 0n);
console.log(`Month rewards: ${folders.length} folders, total ${total} units`);

const { rootHex, entries } = buildClaims(folders);
console.log(`Merkle root: ${rootHex}\n`);

console.log('Every claim verifies against the root:');
for (const [i, e] of entries.entries()) {
  check(
    `${folders[i].name} claims ${e.amount}`,
    verifyClaim(e.pubkey, e.amount, e.proofHex, rootHex),
  );
}

console.log('\nTamper cases (all must FAIL):');
const victim = entries[0];
check(
  'wrong amount rejected',
  !verifyClaim(victim.pubkey, (BigInt(victim.amount) + 1n).toString(), victim.proofHex, rootHex),
);
check(
  'wrong claimant rejected',
  !verifyClaim(entries[1].pubkey, victim.amount, victim.proofHex, rootHex),
);
check(
  'swapped proof element rejected',
  !verifyClaim(
    victim.pubkey,
    victim.amount,
    [entries[1].proofHex[0], ...victim.proofHex.slice(1)],
    rootHex,
  ),
);
check(
  'wrong root rejected',
  !verifyClaim(victim.pubkey, victim.amount, victim.proofHex, entries[1].leafHex),
);

console.log('\nDouble-claim protection (pool contract claimed-set):');
const claimed = new Set();
function claim(entry) {
  if (claimed.has(entry.leafHex)) return false; // already claimed
  if (!verifyClaim(entry.pubkey, entry.amount, entry.proofHex, rootHex)) return false;
  claimed.add(entry.leafHex);
  return true;
}
check('first claim succeeds', claim(entries[2]));
check('second claim of the same leaf rejected', !claim(entries[2]));
check('other folders can still claim', claim(entries[3]) && claim(entries[4]));

console.log(`\n${passed} passed, ${failed} failed.`);
process.exit(failed === 0 ? 0 : 1);
