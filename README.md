# @iris-gate/person

Sovereign personal vault that keeps your case facts on your device and lets you prove whether a real human reviewed your case.

You keep the facts. You send only a cryptographic fingerprint. Institutions must return a signed receipt. You store it. You can export a complete, verifiable bundle for any tribunal, ombudsman, or court.

Connected to the Iris command centre: [github.com/ljbudgie/Iris](https://github.com/ljbudgie/Iris)

---

## Installation

```bash
npm install @iris-gate/person
```

That’s it. No external dependencies. Uses only Node.js built-in `crypto`.

---

## Quick Start

```ts
import { createPerson, buildReceipt, generateKeyPair, verifyPackage } from '@iris-gate/person';

// 1) Create your personal vault
const person = createPerson();

// 2) Commit your case facts (facts stay on your device)
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

// Send ONLY the commitment to the institution
console.log('Send this to the institution:', commitment);
// { hash: 'a3f9...', timestamp: '...', nonce: '...', version: 1 }

// 3) Receive the institution's signed receipt
const institutionKeys = generateKeyPair();
const receipt = buildReceipt({
  commitment,
  outcome: 'NULL',
  reason: 'Automated decision system applied standard criteria.',
  issuer: 'Department for Work and Pensions',
  keyPair: institutionKeys,
});

person.receive(record.id, receipt);

// 4) Check for NULL receipts (grounds for challenge)
const nullCases = person.challenge();
console.log(`${nullCases.length} case(s) with no human review — ready to challenge`);

// 5) Export for tribunal
const exportBundle = person.exportRecord(record.id);
console.log(exportBundle.verificationInstructions.join('\n'));

// 6) Independent verification (tribunal side)
const result = verifyPackage(exportBundle);
console.log(result.valid);    // true
console.log(result.summary);  // plain-English explanation
```

---

## The Inversion (plain English)

Normally you hand over all your facts and hope the institution acts fairly. **This flips it.**

1. You keep your facts on your device.
2. You send a one-way fingerprint (SHA-256 hash), not the facts.
3. The institution must sign a receipt: **SOVEREIGN** (human reviewed) or **NULL** (no human review).
4. You store the receipt in your encrypted vault.
5. If needed, you export a ready-to-verify bundle for a tribunal.

A `NULL` receipt is grounds for challenge. A `SOVEREIGN` receipt proves accountability.

---

## Key Features

- On-device vault for your case facts
- Commitments that reveal nothing about your data
- Signed receipts that prove human review or lack of it
- Encrypted backups and simple restore
- Export bundles with plain-English verification steps

---

## Cryptographic Guarantees (simple)

- **Facts stay private:** only a hash is shared.
- **Receipts are tamper-evident:** ed25519 signatures must verify.
- **Linkage is provable:** receipt hash must match your commitment.
- **Vault is encrypted:** AES-256-GCM with PBKDF2-SHA256 (200,000 iterations).

---

## Connection to Iris

This package is the personal-vault layer of **Iris**, the command centre for The Burgess Principle:

- **Iris** — [github.com/ljbudgie/Iris](https://github.com/ljbudgie/Iris)
- **@iris-gate/person** — this sovereign personal vault

---

## License

MIT © 2026 LJ

---

## The Burgess Principle

> *"A human must review the specific case. Not the type of case. The actual case."*

UK Certification Mark **UK00004343685**
