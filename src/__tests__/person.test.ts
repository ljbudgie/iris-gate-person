/**
 * Tests for @iris-gate/person
 *
 * Covers the full flow: commit → receipt → verify → export → encrypt/decrypt.
 */

import {
  createPerson,
  generateKeyPair,
  buildReceipt,
  verifyPersonCommitment,
  verifyReceipt,
  verifyPackage,
  verifyRecord,
} from '../index';
import type { KeyPair, Commitment, Receipt, VaultRecord } from '../types';
import {
  decryptVault,
  encryptVault,
  hashPayload,
  randomHex,
  sha256,
  signMessage,
  verifySignature,
} from '../crypto';

// ── Shared institution key-pair ────────────────────────────────────────────
let institutionKeys: KeyPair;
beforeAll(() => {
  institutionKeys = generateKeyPair();
});

// ---------------------------------------------------------------------------
// createPerson
// ---------------------------------------------------------------------------

describe('createPerson', () => {
  it('creates a person with a public key', () => {
    const person = createPerson();
    expect(person.publicKey).toBeTruthy();
    expect(person.publicKey.length).toBeGreaterThan(0);
  });

  it('accepts an existing key pair', () => {
    const keys = generateKeyPair();
    const person = createPerson(keys);
    expect(person.publicKey).toBe(keys.publicKey);
  });

  it('starts with an empty vault', () => {
    const person = createPerson();
    expect(person.listRecords()).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// commit
// ---------------------------------------------------------------------------

describe('commit', () => {
  it('returns a commitment and vault record', () => {
    const person = createPerson();
    const facts = { claimRef: 'XY123', condition: 'fibromyalgia' };
    const { commitment, record } = person.commit('Test case', facts, ['test']);

    expect(commitment.hash).toBeTruthy();
    expect(commitment.nonce).toBeTruthy();
    expect(commitment.timestamp).toBeTruthy();
    expect(commitment.version).toBe(1);

    expect(record.id).toBeTruthy();
    expect(record.label).toBe('Test case');
    expect(record.facts).toEqual(facts);
    expect(record.tags).toEqual(['test']);
    expect(record.receipt).toBeUndefined();
  });

  it('stores the record in the vault', () => {
    const person = createPerson();
    const { record } = person.commit('Stored case', { x: 1 });
    expect(person.getRecord(record.id)).toEqual(record);
    expect(person.listRecords()).toHaveLength(1);
  });

  it('does NOT include facts in the commitment object', () => {
    const person = createPerson();
    const facts = { secret: 'my private data' };
    const { commitment } = person.commit('Privacy test', facts);
    expect(JSON.stringify(commitment)).not.toContain('my private data');
  });

  it('produces different hashes for different facts', () => {
    const person = createPerson();
    const { commitment: c1 } = person.commit('Case A', { a: 1 });
    const { commitment: c2 } = person.commit('Case B', { a: 2 });
    expect(c1.hash).not.toBe(c2.hash);
  });

  it('produces unique nonces for otherwise identical facts', () => {
    const person = createPerson();
    const facts = { repeated: true };
    const { commitment: c1 } = person.commit('Case A', facts);
    const { commitment: c2 } = person.commit('Case B', facts);
    expect(c1.nonce).not.toBe(c2.nonce);
    expect(c1.hash).not.toBe(c2.hash);
  });
});

// ---------------------------------------------------------------------------
// receive
// ---------------------------------------------------------------------------

describe('receive', () => {
  function makeReceipt(commitment: Commitment, outcome: 'SOVEREIGN' | 'NULL', keys: KeyPair): Receipt {
    return buildReceipt({
      commitment,
      outcome,
      reason: 'Test reason',
      issuer: 'Test Institution',
      keyPair: keys,
    });
  }

  it('stores a valid SOVEREIGN receipt', () => {
    const person = createPerson();
    const { commitment, record } = person.commit('ESA appeal', { ref: 'A1' });
    const receipt = makeReceipt(commitment, 'SOVEREIGN', institutionKeys);
    const updated = person.receive(record.id, receipt);
    expect(updated.receipt?.outcome).toBe('SOVEREIGN');
  });

  it('stores a valid NULL receipt', () => {
    const person = createPerson();
    const { commitment, record } = person.commit('PIP claim', { ref: 'B2' });
    const receipt = makeReceipt(commitment, 'NULL', institutionKeys);
    const updated = person.receive(record.id, receipt);
    expect(updated.receipt?.outcome).toBe('NULL');
  });

  it('throws for unknown record ID', () => {
    const person = createPerson();
    const { commitment } = person.commit('temp', {});
    const receipt = makeReceipt(commitment, 'NULL', institutionKeys);
    expect(() => person.receive('non-existent-id', receipt)).toThrow('Record not found');
  });

  it('throws for a tampered receipt', () => {
    const person = createPerson();
    const { commitment, record } = person.commit('Tamper test', { x: 1 });
    const receipt = makeReceipt(commitment, 'SOVEREIGN', institutionKeys);
    const tampered: Receipt = { ...receipt, outcome: 'NULL' }; // change outcome after signing
    expect(() => person.receive(record.id, tampered)).toThrow('invalid signature');
  });
});

// ---------------------------------------------------------------------------
// challenge / challengeAll
// ---------------------------------------------------------------------------

describe('challenge', () => {
  it('returns only NULL receipts', () => {
    const person = createPerson();
    const { commitment: c1, record: r1 } = person.commit('Null case', { n: 1 });
    const { commitment: c2, record: r2 } = person.commit('Sovereign case', { s: 2 });

    person.receive(r1.id, buildReceipt({ commitment: c1, outcome: 'NULL', reason: '', issuer: 'DWP', keyPair: institutionKeys }));
    person.receive(r2.id, buildReceipt({ commitment: c2, outcome: 'SOVEREIGN', reason: '', issuer: 'DWP', keyPair: institutionKeys }));

    const challenged = person.challenge();
    expect(challenged).toHaveLength(1);
    expect(challenged[0].id).toBe(r1.id);
  });

  it('returns empty array when no NULL receipts', () => {
    const person = createPerson();
    const { commitment, record } = person.commit('Good case', { ok: true });
    person.receive(record.id, buildReceipt({ commitment, outcome: 'SOVEREIGN', reason: '', issuer: 'Test', keyPair: institutionKeys }));
    expect(person.challenge()).toHaveLength(0);
  });
});

describe('challengeAll', () => {
  it('filters by issuer', () => {
    const person = createPerson();
    const { commitment: c1, record: r1 } = person.commit('DWP case', { a: 1 }, ['dwp']);
    const { commitment: c2, record: r2 } = person.commit('HMRC case', { b: 2 }, ['hmrc']);

    person.receive(r1.id, buildReceipt({ commitment: c1, outcome: 'NULL', reason: '', issuer: 'DWP', keyPair: institutionKeys }));
    person.receive(r2.id, buildReceipt({ commitment: c2, outcome: 'NULL', reason: '', issuer: 'HMRC', keyPair: institutionKeys }));

    const dwpChallenges = person.challengeAll({ issuer: 'DWP' });
    expect(dwpChallenges).toHaveLength(1);
    expect(dwpChallenges[0].receipt?.issuer).toBe('DWP');
  });

  it('filters by tags', () => {
    const person = createPerson();
    const { commitment: c1, record: r1 } = person.commit('Tagged case', { x: 1 }, ['urgent']);
    const { commitment: c2, record: r2 } = person.commit('Normal case', { y: 2 }, ['routine']);

    person.receive(r1.id, buildReceipt({ commitment: c1, outcome: 'NULL', reason: '', issuer: 'Test', keyPair: institutionKeys }));
    person.receive(r2.id, buildReceipt({ commitment: c2, outcome: 'NULL', reason: '', issuer: 'Test', keyPair: institutionKeys }));

    const urgent = person.challengeAll({ tags: ['urgent'] });
    expect(urgent).toHaveLength(1);
    expect(urgent[0].tags).toContain('urgent');
  });

  it('filters by label case-insensitively', () => {
    const person = createPerson();
    const { commitment: c1, record: r1 } = person.commit('ESA Tribunal', { a: 1 });
    const { commitment: c2, record: r2 } = person.commit('PIP Review', { b: 2 });

    person.receive(r1.id, buildReceipt({ commitment: c1, outcome: 'NULL', reason: '', issuer: 'Test', keyPair: institutionKeys }));
    person.receive(r2.id, buildReceipt({ commitment: c2, outcome: 'NULL', reason: '', issuer: 'Test', keyPair: institutionKeys }));

    const results = person.challengeAll({ label: 'tribunal' });
    expect(results).toHaveLength(1);
    expect(results[0].id).toBe(r1.id);
  });

  it('requires all supplied filters to match', () => {
    const person = createPerson();
    const { commitment: c1, record: r1 } = person.commit('DWP urgent case', { a: 1 }, ['urgent']);
    const { commitment: c2, record: r2 } = person.commit('DWP routine case', { b: 2 }, ['routine']);
    const { commitment: c3, record: r3 } = person.commit('HMRC urgent case', { c: 3 }, ['urgent']);

    person.receive(r1.id, buildReceipt({ commitment: c1, outcome: 'NULL', reason: '', issuer: 'DWP', keyPair: institutionKeys }));
    person.receive(r2.id, buildReceipt({ commitment: c2, outcome: 'NULL', reason: '', issuer: 'DWP', keyPair: institutionKeys }));
    person.receive(r3.id, buildReceipt({ commitment: c3, outcome: 'NULL', reason: '', issuer: 'HMRC', keyPair: institutionKeys }));

    const results = person.challengeAll({ issuer: 'DWP', label: 'urgent', tags: ['urgent'] });
    expect(results).toHaveLength(1);
    expect(results[0].id).toBe(r1.id);
  });
});

// ---------------------------------------------------------------------------
// search
// ---------------------------------------------------------------------------

describe('search', () => {
  it('finds records by label substring', () => {
    const person = createPerson();
    person.commit('ESA Tribunal 2026', { a: 1 });
    person.commit('PIP Review 2026', { b: 2 });
    const results = person.search('ESA');
    expect(results).toHaveLength(1);
    expect(results[0].label).toContain('ESA');
  });

  it('finds records by tag', () => {
    const person = createPerson();
    person.commit('Case A', { a: 1 }, ['ombudsman']);
    person.commit('Case B', { b: 2 }, ['tribunal']);
    const results = person.search('ombudsman');
    expect(results).toHaveLength(1);
  });

  it('returns SOVEREIGN records when queried with "SOVEREIGN"', () => {
    const person = createPerson();
    const { commitment: c1, record: r1 } = person.commit('Sov case', {});
    const { commitment: c2, record: r2 } = person.commit('Null case', {});
    person.receive(r1.id, buildReceipt({ commitment: c1, outcome: 'SOVEREIGN', reason: '', issuer: 'X', keyPair: institutionKeys }));
    person.receive(r2.id, buildReceipt({ commitment: c2, outcome: 'NULL', reason: '', issuer: 'X', keyPair: institutionKeys }));
    expect(person.search('SOVEREIGN')).toHaveLength(1);
    expect(person.search('NULL')).toHaveLength(1);
  });

  it('trims and matches label and tags case-insensitively', () => {
    const person = createPerson();
    person.commit('Uppercase Label', { a: 1 }, ['MixedCaseTag']);
    expect(person.search('  uppercase  ')).toHaveLength(1);
    expect(person.search('mixedcase')).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------

describe('verify', () => {
  it('returns valid=true for a correct record with receipt', () => {
    const person = createPerson();
    const { commitment, record } = person.commit('Verify test', { key: 'value' });
    person.receive(record.id, buildReceipt({ commitment, outcome: 'SOVEREIGN', reason: '', issuer: 'Test', keyPair: institutionKeys }));
    const result = person.verify(record.id);
    expect(result.valid).toBe(true);
    expect(result.commitmentValid).toBe(true);
    expect(result.signatureValid).toBe(true);
    expect(result.hashesMatch).toBe(true);
  });

  it('returns signatureValid=false for missing receipt', () => {
    const person = createPerson();
    const { record } = person.commit('No receipt', { a: 1 });
    const result = person.verify(record.id);
    expect(result.signatureValid).toBe(false);
    expect(result.valid).toBe(false);
  });

  it('throws for unknown record ID', () => {
    const person = createPerson();
    expect(() => person.verify('bad-id')).toThrow('Record not found');
  });
});

// ---------------------------------------------------------------------------
// exportRecord
// ---------------------------------------------------------------------------

describe('exportRecord', () => {
  it('produces an export package with instructions', () => {
    const person = createPerson();
    const { commitment, record } = person.commit('Export test', { ref: 'E1' });
    person.receive(record.id, buildReceipt({ commitment, outcome: 'SOVEREIGN', reason: 'Reviewed', issuer: 'Ombudsman', keyPair: institutionKeys }));
    const pkg = person.exportRecord(record.id);

    expect(pkg.record.id).toBe(record.id);
    expect(pkg.verificationInstructions.length).toBeGreaterThan(0);
    expect(pkg.exportedBy).toContain('@iris-gate/person');
  });

  it('can be re-verified with verifyPackage', () => {
    const person = createPerson();
    const { commitment, record } = person.commit('Tribunal export', { detail: 'facts here' });
    person.receive(record.id, buildReceipt({ commitment, outcome: 'NULL', reason: 'Auto response', issuer: 'DWP', keyPair: institutionKeys }));
    const pkg = person.exportRecord(record.id);
    const result = verifyPackage(pkg);
    expect(result.valid).toBe(true);
  });

  it('throws for unknown record ID', () => {
    const person = createPerson();
    expect(() => person.exportRecord('missing-record')).toThrow('Record not found');
  });

  it('includes pending verification instructions when no receipt exists', () => {
    const person = createPerson();
    const { record } = person.commit('Pending export', { ref: 'P1' });
    const pkg = person.exportRecord(record.id);
    expect(pkg.verificationInstructions).toContain('  No receipt present in this record yet.');
    expect(pkg.verificationInstructions).toContain('  Outcome: PENDING (no receipt received)');
  });
});

// ---------------------------------------------------------------------------
// Encrypted vault backup / restore
// ---------------------------------------------------------------------------

describe('exportVaultEncrypted / importVaultEncrypted', () => {
  it('round-trips the vault through encryption', () => {
    const person = createPerson();
    const { commitment, record } = person.commit('Backup test', { secret: 'top secret' }, ['backup']);
    person.receive(record.id, buildReceipt({ commitment, outcome: 'SOVEREIGN', reason: '', issuer: 'Test', keyPair: institutionKeys }));

    const passphrase = 'correct-horse-battery-staple';
    const encrypted = person.exportVaultEncrypted(passphrase);

    // Create a fresh person and import
    const restored = createPerson();
    restored.importVaultEncrypted(encrypted, passphrase);

    expect(restored.listRecords()).toHaveLength(1);
    const restoredRecord = restored.getRecord(record.id);
    expect(restoredRecord?.label).toBe('Backup test');
    expect(restoredRecord?.receipt?.outcome).toBe('SOVEREIGN');
    // publicKey must match the original person's key after restore
    expect(restored.publicKey).toBe(person.publicKey);
  });

  it('throws with wrong passphrase', () => {
    const person = createPerson();
    person.commit('Secret', { x: 1 });
    const encrypted = person.exportVaultEncrypted('correct-passphrase');
    const fresh = createPerson();
    expect(() => fresh.importVaultEncrypted(encrypted, 'wrong-passphrase')).toThrow();
  });

  it('overwrites records with the same ID on import without removing existing records', () => {
    const source = createPerson();
    const { record } = source.commit('Original label', { original: true });
    const encrypted = source.exportVaultEncrypted('passphrase');

    const destination = createPerson();
    destination.commit('Existing destination record', { keep: true });
    destination.importVaultEncrypted(encrypted, 'passphrase');
    const imported = destination.getRecord(record.id);

    expect(destination.listRecords()).toHaveLength(2);
    expect(imported?.label).toBe('Original label');
  });
});

// ---------------------------------------------------------------------------
// buildReceipt / verifyPersonCommitment (institution helpers)
// ---------------------------------------------------------------------------

describe('buildReceipt', () => {
  it('produces a valid signed receipt', () => {
    const keys = generateKeyPair();
    const person = createPerson();
    const { commitment } = person.commit('Receipt test', { data: 'x' });
    const receipt = buildReceipt({ commitment, outcome: 'SOVEREIGN', reason: 'Reviewed', issuer: 'Test', keyPair: keys });
    expect(verifyReceipt(receipt)).toBe(true);
  });

  it('uses the supplied issuedAt timestamp in the signed receipt', () => {
    const keys = generateKeyPair();
    const person = createPerson();
    const { commitment } = person.commit('Timestamped receipt', { data: 'x' });
    const issuedAt = '2026-05-03T21:29:32.499Z';
    const receipt = buildReceipt({ commitment, outcome: 'NULL', reason: 'Automated', issuer: 'Test', keyPair: keys, issuedAt });
    expect(receipt.issuedAt).toBe(issuedAt);
    expect(verifyReceipt(receipt)).toBe(true);
  });
});

describe('verifyPersonCommitment', () => {
  it('returns true when facts + nonce match commitment', () => {
    const person = createPerson();
    const facts = { name: 'Alice', ref: '001' };
    const { commitment, record } = person.commit('Commitment check', facts);
    expect(verifyPersonCommitment(commitment, facts, record.commitment.nonce)).toBe(true);
  });

  it('returns false when facts are altered', () => {
    const person = createPerson();
    const facts = { name: 'Alice' };
    const { commitment, record } = person.commit('Altered facts', facts);
    expect(verifyPersonCommitment(commitment, { name: 'Bob' }, record.commitment.nonce)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// verifyRecord (standalone)
// ---------------------------------------------------------------------------

describe('verifyRecord', () => {
  it('verifies a complete record', () => {
    const person = createPerson();
    const { commitment, record } = person.commit('Verify record test', { v: 1 });
    person.receive(record.id, buildReceipt({ commitment, outcome: 'SOVEREIGN', reason: '', issuer: 'X', keyPair: institutionKeys }));
    const updated = person.getRecord(record.id)!;
    const result = verifyRecord(updated);
    expect(result.valid).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// crypto primitives
// ---------------------------------------------------------------------------

describe('crypto primitives', () => {
  it('hashes strings and buffers consistently with sha256', () => {
    expect(sha256('hello')).toBe(sha256(Buffer.from('hello')));
    expect(sha256('hello')).toHaveLength(64);
  });

  it('creates deterministic payload hashes when key order differs', () => {
    const nonce = 'fixed-nonce';
    expect(hashPayload({ b: 2, a: 1 }, nonce)).toBe(hashPayload({ a: 1, b: 2 }, nonce));
  });

  it('generates default 32-byte random hex values', () => {
    const value = randomHex();
    expect(value).toMatch(/^[0-9a-f]+$/);
    expect(value).toHaveLength(64);
  });

  it('signs and verifies buffer messages', () => {
    const keys = generateKeyPair();
    const message = Buffer.from('buffer-message');
    const signature = signMessage(message, keys.privateKey);
    expect(verifySignature(message, signature, keys.publicKey)).toBe(true);
  });

  it('returns false for malformed signatures or public keys', () => {
    const keys = generateKeyPair();
    const signature = signMessage('message', keys.privateKey);
    expect(verifySignature('message', 'not-hex', keys.publicKey)).toBe(false);
    expect(verifySignature('message', signature, 'not-a-public-key')).toBe(false);
  });

  it('encrypts the same plaintext differently each time and decrypts both vaults', () => {
    const plaintext = JSON.stringify({ secret: 'value' });
    const first = encryptVault(plaintext, 'passphrase');
    const second = encryptVault(plaintext, 'passphrase');

    expect(first.ciphertext).not.toBe(second.ciphertext);
    expect(first.iv).not.toBe(second.iv);
    expect(decryptVault(first, 'passphrase')).toBe(plaintext);
    expect(decryptVault(second, 'passphrase')).toBe(plaintext);
  });

  it('rejects corrupted encrypted vault data', () => {
    const encrypted = encryptVault('secret', 'passphrase');
    const corrupted = { ...encrypted, ciphertext: Buffer.from('corrupted').toString('base64') };
    expect(() => decryptVault(corrupted, 'passphrase')).toThrow('Decryption failed');
  });
});

// ---------------------------------------------------------------------------
// verifyPackage failure modes
// ---------------------------------------------------------------------------

describe('verifyPackage failure modes', () => {
  it('marks packages invalid when facts no longer match the commitment', () => {
    const person = createPerson();
    const { commitment, record } = person.commit('Altered package', { original: true });
    person.receive(record.id, buildReceipt({ commitment, outcome: 'SOVEREIGN', reason: '', issuer: 'Test', keyPair: institutionKeys }));
    const pkg = person.exportRecord(record.id);
    pkg.record.facts = { original: false };

    const result = verifyPackage(pkg);

    expect(result.valid).toBe(false);
    expect(result.commitmentValid).toBe(false);
    expect(result.signatureValid).toBe(true);
    expect(result.hashesMatch).toBe(true);
    expect(result.summary).toContain('The commitment hash does not match the facts');
  });

  it('marks packages invalid when the receipt points at a different commitment', () => {
    const person = createPerson();
    const { commitment, record } = person.commit('Hash mismatch', { original: true });
    person.receive(record.id, buildReceipt({ commitment, outcome: 'SOVEREIGN', reason: '', issuer: 'Test', keyPair: institutionKeys }));
    const pkg = person.exportRecord(record.id);
    pkg.record.receipt = { ...pkg.record.receipt!, commitmentHash: '0'.repeat(64) };

    const result = verifyPackage(pkg);

    expect(result.valid).toBe(false);
    expect(result.signatureValid).toBe(false);
    expect(result.hashesMatch).toBe(false);
    expect(result.summary).toContain('references a different commitment');
  });

  it('handles facts that cannot be serialised for commitment verification', () => {
    const circular: Record<string, unknown> = {};
    circular.self = circular;
    const record: VaultRecord = {
      id: 'circular-record',
      label: 'Circular record',
      commitment: {
        hash: 'not-recomputed',
        timestamp: '2026-05-03T21:29:32.499Z',
        nonce: 'nonce',
        version: 1,
      },
      facts: circular,
      createdAt: '2026-05-03T21:29:32.499Z',
      tags: [],
    };

    const result = verifyPackage({
      record,
      verificationInstructions: [],
      exportedBy: '@iris-gate/person',
      exportedAt: '2026-05-03T21:29:32.499Z',
    });

    expect(result.commitmentValid).toBe(false);
    expect(result.valid).toBe(false);
  });

  it('handles receipts with unserialisable fields during signature verification', () => {
    const person = createPerson();
    const { record } = person.commit('Bad receipt', { a: 1 });
    const badReceipt = {
      commitmentHash: record.commitment.hash,
      outcome: 'SOVEREIGN',
      reason: BigInt(1),
      issuer: 'Test',
      issuedAt: '2026-05-03T21:29:32.499Z',
      signature: '00',
      issuerPublicKey: institutionKeys.publicKey,
    } as unknown as Receipt;
    const pkg = {
      record: { ...record, receipt: badReceipt },
      verificationInstructions: [],
      exportedBy: '@iris-gate/person',
      exportedAt: '2026-05-03T21:29:32.499Z',
    };

    const result = verifyPackage(pkg);

    expect(result.signatureValid).toBe(false);
    expect(result.valid).toBe(false);
  });
});
