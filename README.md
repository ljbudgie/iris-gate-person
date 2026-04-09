# @iris-gate/person

**Keep your case facts private. Prove whether a human reviewed them.**

A sovereign personal vault that lets you send a cryptographic fingerprint (not your data) to institutions, then collect signed receipts showing if a real person looked at your case — or if you were ignored.

---

## The Inversion

Normally, you hand over all your personal information and hope for the best. This inverts that:

1. **Your facts stay on your device.** You never send them.
2. **You send a fingerprint** — a one-way hash that can't be reversed.
3. **The institution signs a receipt** saying `SOVEREIGN` (human reviewed) or `NULL` (no human review).
4. **You store the receipt** in your encrypted vault.
5. **If needed**, you export everything for a tribunal with built-in instructions anyone can follow.

`NULL` = grounds for challenge. `SOVEREIGN` = proof of accountability.

---

## Installation

```bash
npm install @iris-gate/person
```

Zero dependencies. Uses only Node.js built-in crypto.

---

## Quick Start

```ts
import { createPerson, buildReceipt, generateKeyPair, verifyPackage } from '@iris-gate/person';

// 1. Create your vault
const person = createPerson();

// 2. Commit your case facts (they never leave your device)
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

// Send ONLY the commitment to the institution — never your facts
console.log('Send this:', commitment);

// 3. Receive their signed receipt
const institutionKeys = generateKeyPair();
const receipt = buildReceipt({
  commitment,
  outcome: 'NULL',  // No human reviewed this
  reason: 'Automated decision system applied standard criteria.',
  issuer: 'Department for Work and Pensions',
  keyPair: institutionKeys,
});

person.receive(record.id, receipt);

// 4. Find cases with no human review
const nullCases = person.challenge();
console.log(`${nullCases.length} case(s) ready to challenge`);

// 5. Export for tribunal
const bundle = person.exportRecord(record.id);

// 6. Anyone can verify
const result = verifyPackage(bundle);
console.log(result.valid);   // true
console.log(result.summary); // Plain-English explanation
```

---

## Key Features

- **Commit facts** → Creates a tamper-proof hash. Your data never leaves your device.
- **Receive receipts** → Stores signed institutional responses. Verifies signatures automatically.
- **Challenge NULL outcomes** → Find all cases where no human reviewed your data.
- **Export for tribunal** → Self-contained bundle with step-by-step verification instructions.
- **Encrypted backup** → AES-256-GCM vault with secure key derivation.

---

## API Reference

### `createPerson(keyPair?)`

Create a new vault or restore from saved keys.

```ts
const person = createPerson();          // New vault
const person = createPerson(savedKeys); // Restore
```

### PersonClient Methods

| Method | What it does |
|--------|--------------|
| `commit(label, facts, tags?)` | Hash facts into a commitment. Facts stay local. |
| `receive(recordId, receipt)` | Store a signed receipt (validates signature first). |
| `challenge()` | Get all records with `NULL` receipts. |
| `challengeAll(filters?)` | Filter by issuer, label, or tags. |
| `search(query)` | Search by label, tag, or outcome. |
| `verify(recordId)` | Cryptographically verify a record. |
| `exportRecord(recordId)` | Export for tribunal with instructions. |
| `exportVaultEncrypted(passphrase)` | Encrypted vault backup. |
| `importVaultEncrypted(vault, passphrase)` | Restore from backup. |
| `listRecords()` | List all records. |
| `getRecord(recordId)` | Get one record. |

### For Institutions

```ts
import { buildReceipt, verifyPersonCommitment } from '@iris-gate/person';

const receipt = buildReceipt({ commitment, outcome: 'SOVEREIGN', reason, issuer, keyPair });
const valid = verifyPersonCommitment(commitment, facts, nonce);
```

### For Tribunals

```ts
import { verifyPackage } from '@iris-gate/person';

const result = verifyPackage(exportBundle);
// result.valid           → All checks passed
// result.commitmentValid → Facts hash matches
// result.signatureValid  → Institution signature valid
// result.hashesMatch     → Receipt links to commitment
// result.summary         → Plain-English explanation
```

---

## Cryptographic Guarantees

| What | How |
|------|-----|
| **Hashing** | SHA-256 |
| **Signatures** | ed25519 |
| **Vault encryption** | AES-256-GCM with PBKDF2-SHA256 (200,000 iterations) |

All crypto uses Node.js built-ins. No third-party libraries.

---

## Backup & Restore

```ts
// Backup
const encrypted = person.exportVaultEncrypted('strong-passphrase');

// Restore
const fresh = createPerson();
fresh.importVaultEncrypted(encrypted, 'strong-passphrase');
```

---

## Connection to Iris

This is the personal vault layer of the [Iris](https://github.com/ljbudgie/Iris) ecosystem — the command centre for The Burgess Principle.

---

## The Burgess Principle

> *"A human must review the specific case. Not the type of case. The actual case."*

**UK Certification Mark UK00004343685**

---

## License

MIT © 2026 LJ

