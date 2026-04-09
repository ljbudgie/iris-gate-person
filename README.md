# @iris-gate/person

Keep your case facts on your own device, send only a cryptographic fingerprint, and force institutions to prove whether a real human reviewed your case.

---

## Installation

```bash
npm install @iris-gate/person
```

No external dependencies. Uses only Node.js built-in `crypto`.

---

## The Inversion

Normally you hand over all your facts and trust the institution to act fairly. **This flips it.**

1. Your facts stay on your device.
2. You send a one-way fingerprint (SHA-256 hash) — not the facts themselves.
3. The institution must return a signed receipt: **SOVEREIGN** (a human reviewed your case) or **NULL** (no human review).
4. You store the receipt in your encrypted local vault.
5. When you need it, you export a complete, self-contained bundle — ready for a tribunal, ombudsman, or court.

A `NULL` receipt is grounds for challenge. A `SOVEREIGN` receipt is proof of accountability.

---

## Quick Start

```ts
import { createPerson, buildReceipt, generateKeyPair, verifyPackage } from '@iris-gate/person';

// 1. Create your personal vault
const person = createPerson();

// 2. Commit your case facts — they stay on your device
const { commitment, record } = person.commit(
  'DWP ESA Appeal 2026',
  {
    claimReference: 'XY123456',
    dateOfBirth: '1980-01-01',
    condition: 'fibromyalgia',
    appealDate: '2026-03-15',
  },
  ['dwp', 'esa', 'appeal'],
);

// Send ONLY the commitment hash to the institution — not your facts
console.log(commitment);
// { hash: 'a3f9...', timestamp: '...', nonce: '...', version: 1 }

// 3. Receive the institution's signed receipt
const institutionKeys = generateKeyPair();
const receipt = buildReceipt({
  commitment,
  outcome: 'NULL',
  reason: 'Automated decision system applied standard criteria.',
  issuer: 'Department for Work and Pensions',
  keyPair: institutionKeys,
});

person.receive(record.id, receipt);

// 4. Identify NULL receipts — no human review means grounds for challenge
const nullCases = person.challenge();
console.log(`${nullCases.length} case(s) with no human review — ready to challenge`);

// 5. Export a verifiable bundle for a tribunal
const exportBundle = person.exportRecord(record.id);
console.log(exportBundle.verificationInstructions.join('\n'));

// 6. Any third party can independently verify the bundle
const result = verifyPackage(exportBundle);
console.log(result.valid);    // true
console.log(result.summary);  // plain-English explanation
```

---

## Key Features

- **On-device vault** — your case facts never leave your machine unless you choose
- **Zero-knowledge commitments** — the hash reveals nothing about your data
- **Signed receipts** — institutions can't deny what they returned
- **Encrypted backups** — protect your vault and restore it anywhere
- **Export bundles** — plain-English verification steps included for any tribunal

---

## Cryptographic Guarantees

| Guarantee | How |
|---|---|
| Facts stay private | Only a SHA-256 hash is shared |
| Receipts are tamper-evident | ed25519 signatures must verify against the institution's public key |
| Linkage is provable | The receipt hash must match your original commitment |
| Vault is encrypted | AES-256-GCM, PBKDF2-SHA256, 200,000 iterations |

---

## Vault Backup & Restore

```ts
// Back up your vault (encrypted)
const encrypted = person.exportVaultEncrypted('my-strong-passphrase');

// Restore on any device
const fresh = createPerson();
fresh.importVaultEncrypted(encrypted, 'my-strong-passphrase');
```

---

## Connection to Iris

This package is the personal-vault layer of **Iris** — the command centre for The Burgess Principle.

- **Iris** — [github.com/ljbudgie/Iris](https://github.com/ljbudgie/Iris)
- **@iris-gate/person** — this sovereign personal vault

---

## License

MIT © 2026 LJ

---

## The Burgess Principle

> *"A human must review the specific case. Not the type of case. The actual case."*

UK Certification Mark **UK00004343685**
