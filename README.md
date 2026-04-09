# @iris-gate/person

Keep your case facts on your device. Send only a fingerprint. Force institutions to prove a human reviewed your case.

---

## The Inversion

Normally you hand over all your facts and hope for fairness. This flips it.

You send a one-way hash — not your data. The institution must sign a receipt: **SOVEREIGN** (human reviewed) or **NULL** (no human review). A `NULL` receipt is grounds for challenge. You keep the proof.

---

## Installation

```bash
npm install @iris-gate/person
```

No external dependencies. Uses only Node.js built-in `crypto`.

---

## Quick Start

```ts
import { createPerson, buildReceipt, generateKeyPair, verifyPackage } from '@iris-gate/person';

const person = createPerson();

// Commit your facts — only a hash leaves your device
const { commitment, record } = person.commit('ESA Appeal', { ref: 'XY123456' }, ['dwp']);

// Receive and store the institution's signed receipt
const keys = generateKeyPair();
const receipt = buildReceipt({ commitment, outcome: 'NULL', reason: 'Automated.', issuer: 'DWP', keyPair: keys });
person.receive(record.id, receipt);

// Find cases with no human review
const nullCases = person.challenge();
console.log(`${nullCases.length} case(s) ready to challenge`);

// Export a verifiable bundle for any tribunal
const bundle = person.exportRecord(record.id);
const result = verifyPackage(bundle);
console.log(result.valid, result.summary);
```

---

## Key Features

- On-device vault — your facts never leave unless you choose
- Signed receipts that prove human review or the absence of it
- `NULL` detection — instantly spot cases that were never reviewed by a person
- Export bundles with plain-English verification steps for tribunals
- Encrypted backup and restore

---

## Part of Iris

This package is the personal-vault layer of **Iris** — the command centre for The Burgess Principle.

> *"A human must review the specific case. Not the type of case. The actual case."*

[github.com/ljbudgie/Iris](https://github.com/ljbudgie/Iris) · UK Certification Mark **UK00004343685**

---

MIT © 2026 LJ
