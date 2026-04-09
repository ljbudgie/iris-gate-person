# @iris-gate/person

**Sovereign personal vault for The Burgess Principle.**

Keep your real case facts private on your device. Send only a cryptographic fingerprint to institutions and AIs. Receive a signed receipt proving whether a real human reviewed your specific case — or not. Store everything in an encrypted vault. Export for any tribunal, ombudsman, or court.

> Protected under UK Certification Mark **UK00004343685** — *The Burgess Principle*.  
> Connected to the main Iris command centre: [github.com/ljbudgie/Iris](https://github.com/ljbudgie/Iris)

---

## The Inversion (plain English)

Normally, you hand over all your facts to an institution and hope they act fairly. **The Burgess Principle inverts this.**

1. **You keep your facts.** They never leave your device.  
2. **You send a fingerprint** — a one-way SHA-256 hash — no institution can reverse it back to your data.  
3. **They sign a receipt** saying whether a real human reviewed your case (`SOVEREIGN`) or whether you were processed by automation, ignored, or refused (`NULL`).  
4. **You store the signed receipt** in an encrypted vault that only you control.  
5. **If needed**, you export a self-contained verification bundle for a tribunal — including step-by-step instructions that require no specialist knowledge.

A `NULL` receipt is grounds for challenge. A `SOVEREIGN` receipt proves accountability.

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

// ── 1. Create your personal vault ──────────────────────────────────────────
const person = createPerson();

// ── 2. Commit your case facts (facts stay on your device) ──────────────────
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

// Send ONLY `commitment` to the institution — never the facts object
console.log('Send this to the institution:', commitment);
// { hash: 'a3f9...', timestamp: '...', nonce: '...', version: 1 }

// ── 3. Receive the institution's signed receipt ────────────────────────────
// (In real use, the institution builds and sends this to you)
const institutionKeys = generateKeyPair(); // institution's keys

const receipt = buildReceipt({
  commitment,
  outcome: 'NULL',      // No human reviewed this case
  reason: 'Automated decision system applied standard criteria.',
  issuer: 'Department for Work and Pensions',
  keyPair: institutionKeys,
});

person.receive(record.id, receipt);

// ── 4. Check for NULL receipts (grounds for challenge) ────────────────────
const nullCases = person.challenge();
console.log(`${nullCases.length} case(s) with no human review — ready to challenge`);

// ── 5. Export for tribunal ────────────────────────────────────────────────
const exportBundle = person.exportRecord(record.id);
console.log(exportBundle.verificationInstructions.join('\n'));

// ── 6. Independent verification (tribunal side) ───────────────────────────
const result = verifyPackage(exportBundle);
console.log(result.valid);    // true
console.log(result.summary);  // plain-English explanation
```

---

## API Reference

### `createPerson(keyPair?)`

Creates a new sovereign personal vault. Returns a `PersonClient`.

```ts
const person = createPerson();          // fresh key-pair
const person = createPerson(savedKeys); // restore from saved key-pair
```

### `PersonClient` methods

| Method | Description |
|---|---|
| `commit(label, facts, tags?)` | Hash facts into a commitment. Facts stay local. |
| `receive(recordId, receipt)` | Store a signed receipt (validates signature first). |
| `challenge()` | Return all records with `NULL` receipts. |
| `challengeAll(filters?)` | Filter NULL receipts by issuer, label, or tags. |
| `search(query)` | Search by label/tag or `"SOVEREIGN"` / `"NULL"`. |
| `verify(recordId)` | Cryptographically verify a vault record. |
| `exportRecord(recordId)` | Export a self-contained bundle for tribunals. |
| `exportVaultEncrypted(passphrase)` | AES-256-GCM encrypted vault backup. |
| `importVaultEncrypted(vault, passphrase)` | Restore from encrypted backup. |
| `listRecords()` | Return all vault records. |
| `getRecord(recordId)` | Return one record by ID. |

### Institution helpers

```ts
import { buildReceipt, verifyPersonCommitment } from '@iris-gate/person';

// Build and sign a receipt (institution side)
const receipt = buildReceipt({ commitment, outcome: 'SOVEREIGN', reason, issuer, keyPair });

// Verify that a person's revealed facts match their commitment
const ok = verifyPersonCommitment(commitment, facts, nonce); // → boolean
```

### Third-party verification

```ts
import { verifyPackage } from '@iris-gate/person';

const result = verifyPackage(exportBundle);
// result.valid           → boolean
// result.commitmentValid → boolean  (facts hash matches)
// result.signatureValid  → boolean  (institution signature valid)
// result.hashesMatch     → boolean  (receipt links to commitment)
// result.summary         → string   (plain-English explanation)
```

---

## Cryptographic Flow

```
PERSON DEVICE                         INSTITUTION
─────────────────                     ─────────────────────
facts = { ... }  ─────────────────────────────────────────▶  (never sent)
nonce = random32bytes

hash = SHA256(nonce + ":" + JSON(facts))  ──▶  commitment = { hash, nonce*, timestamp }
                                               (* nonce optionally kept private)

                   ◀──────────────────────────  receipt = {
                                                  commitmentHash: hash,
                                                  outcome: "SOVEREIGN" | "NULL",
                                                  reason: "...",
                                                  issuer: "...",
                                                  issuedAt: "...",
                                                  signature: ed25519(body, privKey),
                                                  issuerPublicKey: pubKey,
                                                }

person.receive(recordId, receipt)  →  verifies ed25519 signature before storing

person.exportRecord(recordId)  →  ExportPackage { record, verificationInstructions, ... }

TRIBUNAL: verifyPackage(exportBundle)
  ├─ Re-hash facts + nonce  →  must match commitment.hash
  ├─ Verify ed25519 sig     →  must be valid for issuerPublicKey
  └─ Check hash linkage     →  receipt.commitmentHash === commitment.hash
```

**Algorithms:**
- Hashing: **SHA-256** (Node.js `crypto.createHash`)
- Signatures: **ed25519** (Node.js `crypto.generateKeyPairSync` / `sign` / `verify`)
- Vault encryption: **AES-256-GCM** with **PBKDF2-SHA256** key derivation (200,000 iterations)

---

## Vault Backup & Restore

```ts
// Back up (encrypted)
const encrypted = person.exportVaultEncrypted('my-strong-passphrase');
// → { algorithm: 'aes-256-gcm', iv, authTag, salt, ciphertext, version }
// Save this JSON to a file or cloud storage

// Restore
const fresh = createPerson();
fresh.importVaultEncrypted(encrypted, 'my-strong-passphrase');
```

---

## Connection to Iris

This package is the personal-vault layer of the **Iris** command centre ecosystem:

- **Iris** ([github.com/ljbudgie/Iris](https://github.com/ljbudgie/Iris)) — the main command centre for The Burgess Principle.
- **@iris-gate/person** *(this package)* — sovereign personal vault for individuals.

---

## The Burgess Principle

> *"A human must review the specific case. Not the type of case. The actual case."*

UK Certification Mark **UK00004343685** — all institutions using Iris-gate are certified under this standard.

---

## License

MIT © 2026 LJ

