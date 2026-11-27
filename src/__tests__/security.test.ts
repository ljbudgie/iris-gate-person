/**
 * Security regression tests:
 *  1. Nested facts are fully covered by the commitment hash (RFC 8785-style
 *     canonical JSON). Previously nested keys were silently dropped.
 *  2. Receipts must be signed by a key tied to the named issuer. Previously
 *     any self-generated key could impersonate any institution.
 */

import {
  createPerson,
  generateKeyPair,
  buildReceipt,
  verifyReceipt,
  verifyReceiptSignature,
  verifyPackage,
  verifyPackageWithDidWeb,
  verifyPersonCommitment,
  checkIssuer,
  canonicalize,
  didWebToUrl,
  ed25519KeysFromDidDocument,
  resolveDidWeb,
  trustedIssuersFromDidWeb,
  normaliseEd25519PublicKey,
} from '../index';
import type { FetchLike } from '../index';
import { hashPayload } from '../crypto';
import { createHash } from 'crypto';

// Helpers ------------------------------------------------------------------

const BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58btcEncode(bytes: Uint8Array): string {
  const digits = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let i = 0; i < digits.length; i++) {
      carry += digits[i] << 8;
      digits[i] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  let out = '';
  for (const byte of bytes) {
    if (byte !== 0) break;
    out += '1';
  }
  for (let i = digits.length - 1; i >= 0; i--) out += BASE58[digits[i]];
  return out;
}
const rawFromSpki = (spkiHex: string) => spkiHex.slice(-64);
const multibaseFromSpki = (spkiHex: string) =>
  'z' + base58btcEncode(Uint8Array.from([0xed, 0x01, ...Buffer.from(rawFromSpki(spkiHex), 'hex')]));

function legacyHash(payload: Record<string, unknown>, nonce: string): string {
  const canonical = JSON.stringify(payload, Object.keys(payload).sort());
  return createHash('sha256').update(`${nonce}:${canonical}`).digest('hex');
}

function mockFetch(docs: Record<string, unknown>): FetchLike {
  return async (url: string) => ({
    ok: url in docs,
    status: url in docs ? 200 : 404,
    json: async () => docs[url],
  });
}

// 1. Canonical hashing --------------------------------------------------------

describe('canonical JSON hashing of nested facts', () => {
  it('canonicalize sorts keys at every depth and keeps nested values', () => {
    expect(canonicalize({ b: 1, a: { d: [3, { z: 1, y: 2 }], c: 'x' } })).toBe(
      '{"a":{"c":"x","d":[3,{"y":2,"z":1}]},"b":1}',
    );
  });

  it('the old serialisation dropped nested keys (documents the bug)', () => {
    const nonce = 'n';
    expect(legacyHash({ case: { amount: 100 } }, nonce)).toBe(
      legacyHash({ case: { amount: 999999, reason: 'tampered' } }, nonce),
    );
  });

  it('TAMPER CASE: changing a nested fact now changes the hash and fails verification', () => {
    const person = createPerson();
    const facts = { case: { amount: 100, decision: { by: 'officer', date: '2026-11-01' } } };
    const { commitment, record } = person.commit('Nested facts', facts);

    const tampered = { case: { amount: 999999, decision: { by: 'officer', date: '2026-11-01' } } };
    expect(hashPayload(tampered, record.commitment.nonce)).not.toBe(commitment.hash);
    expect(verifyPersonCommitment(commitment, facts, record.commitment.nonce)).toBe(true);
    expect(verifyPersonCommitment(commitment, tampered, record.commitment.nonce)).toBe(false);

    const institution = generateKeyPair();
    person.receive(record.id, buildReceipt({ commitment, outcome: 'SOVEREIGN', reason: '', issuer: 'Council', keyPair: institution }));
    const pkg = person.exportRecord(record.id);
    const trustedIssuers = { Council: [institution.publicKey] };
    expect(verifyPackage(pkg, { trustedIssuers }).valid).toBe(true);

    const tamperedPkg = { ...pkg, record: { ...pkg.record, facts: tampered } };
    const result = verifyPackage(tamperedPkg, { trustedIssuers });
    expect(result.commitmentValid).toBe(false);
    expect(result.valid).toBe(false);
  });

  it('is key-order independent at every depth', () => {
    expect(hashPayload({ a: { x: 1, y: 2 }, b: 2 }, 'n')).toBe(hashPayload({ b: 2, a: { y: 2, x: 1 } }, 'n'));
  });

  it('flat payloads hash identically to format version 1 (backward compatible)', () => {
    const flat = { name: 'Alice', ref: '001', n: 3, ok: true, tags: ['a', 'b'] };
    expect(hashPayload(flat, 'abc')).toBe(legacyHash(flat, 'abc'));
  });

  it('rejects values with no JSON representation', () => {
    expect(() => canonicalize({ n: Infinity })).toThrow();
    expect(() => canonicalize({ n: BigInt(1) })).toThrow();
    const loop: Record<string, unknown> = {};
    loop.self = loop;
    expect(() => canonicalize(loop)).toThrow();
  });
});

// 2. Issuer binding -----------------------------------------------------------

describe('receipt issuer binding', () => {
  function setup() {
    const realInstitution = generateKeyPair();
    const attacker = generateKeyPair();
    const person = createPerson();
    const { commitment, record } = person.commit('Benefit decision', { ref: 'B1', detail: { step: 2 } });
    return { realInstitution, attacker, person, commitment, record };
  }

  it('IMPERSONATION CASE: a receipt signed by an attacker key claiming to be "HMRC" fails', () => {
    const { realInstitution, attacker, person, commitment, record } = setup();
    const forged = buildReceipt({ commitment, outcome: 'SOVEREIGN', reason: 'Reviewed', issuer: 'HMRC', keyPair: attacker });

    // The signature itself is mathematically valid for the embedded key...
    expect(verifyReceiptSignature(forged)).toBe(true);
    // ...but it is not HMRC's key.
    const trustedIssuers = { HMRC: [realInstitution.publicKey] };
    expect(checkIssuer(forged, trustedIssuers)).toBe('KEY_MISMATCH');
    expect(verifyReceipt(forged, { trustedIssuers })).toBe(false);
    // Even allowUnverifiedIssuer does not rescue a key mismatch.
    expect(verifyReceipt(forged, { trustedIssuers, allowUnverifiedIssuer: true })).toBe(false);

    person.receive(record.id, forged);
    const result = verifyPackage(person.exportRecord(record.id), { trustedIssuers });
    expect(result.signatureValid).toBe(true);
    expect(result.issuerStatus).toBe('KEY_MISMATCH');
    expect(result.valid).toBe(false);
    expect(result.summary).toContain('KEY_MISMATCH');
  });

  it('embedded-key-only verification reports UNVERIFIED_ISSUER and fails by default', () => {
    const { attacker, person, commitment, record } = setup();
    const receipt = buildReceipt({ commitment, outcome: 'SOVEREIGN', reason: '', issuer: 'HMRC', keyPair: attacker });
    expect(verifyReceipt(receipt)).toBe(false);
    expect(checkIssuer(receipt)).toBe('UNVERIFIED_ISSUER');

    person.receive(record.id, receipt);
    const result = person.verify(record.id);
    expect(result.issuerStatus).toBe('UNVERIFIED_ISSUER');
    expect(result.valid).toBe(false);
    expect(result.summary).toContain('UNVERIFIED_ISSUER');

    // Explicit opt-in still flags it.
    const optIn = person.verify(record.id, { allowUnverifiedIssuer: true });
    expect(optIn.valid).toBe(true);
    expect(optIn.issuerStatus).toBe('UNVERIFIED_ISSUER');
    expect(optIn.summary).toContain('NOT tied to the named issuer');
  });

  it('a receipt from the pinned institution key is TRUSTED (SPKI or raw hex pins)', () => {
    const { realInstitution, person, commitment, record } = setup();
    const receipt = buildReceipt({ commitment, outcome: 'NULL', reason: 'Automated', issuer: 'HMRC', keyPair: realInstitution });
    expect(verifyReceipt(receipt, { trustedIssuers: { HMRC: [realInstitution.publicKey] } })).toBe(true);
    expect(verifyReceipt(receipt, { trustedIssuers: { HMRC: [rawFromSpki(realInstitution.publicKey)] } })).toBe(true);

    const pinnedPerson = createPerson(undefined, { trustedIssuers: { HMRC: [realInstitution.publicKey] } });
    const c = pinnedPerson.commit('x', { a: 1 });
    pinnedPerson.receive(c.record.id, buildReceipt({ commitment: c.commitment, outcome: 'NULL', reason: '', issuer: 'HMRC', keyPair: realInstitution }));
    expect(pinnedPerson.verify(c.record.id).valid).toBe(true);
    void person; void record;
  });

  it('a key pinned for one issuer does not vouch for another issuer name', () => {
    const { realInstitution, commitment } = setup();
    const receipt = buildReceipt({ commitment, outcome: 'SOVEREIGN', reason: '', issuer: 'DWP', keyPair: realInstitution });
    expect(checkIssuer(receipt, { HMRC: [realInstitution.publicKey] })).toBe('UNVERIFIED_ISSUER');
  });

  it('normalises keys and rejects garbage', () => {
    const k = generateKeyPair();
    expect(normaliseEd25519PublicKey(rawFromSpki(k.publicKey))).toBe(k.publicKey);
    expect(normaliseEd25519PublicKey('zz')).toBeNull();
    expect(normaliseEd25519PublicKey('ab'.repeat(10))).toBeNull();
  });
});

// 3. did:web ------------------------------------------------------------------

describe('did:web resolution', () => {
  it('maps did:web identifiers to HTTPS URLs and rejects malformed ones', () => {
    expect(didWebToUrl('did:web:example.gov.uk')).toBe('https://example.gov.uk/.well-known/did.json');
    expect(didWebToUrl('did:web:example.gov.uk:receipts:v1')).toBe('https://example.gov.uk/receipts/v1/did.json');
    expect(didWebToUrl('did:web:localhost%3A8443')).toBe('https://localhost:8443/.well-known/did.json');
    expect(() => didWebToUrl('did:key:z6Mk')).toThrow();
    expect(() => didWebToUrl('did:web:evil.com%2F..')).toThrow();
    expect(() => didWebToUrl('did:web:example.com:%2E%2E')).toThrow();
  });

  it('extracts Multikey and JWK Ed25519 keys from assertionMethod only', () => {
    const did = 'did:web:council.example';
    const a = generateKeyPair();
    const b = generateKeyPair();
    const notForSigning = generateKeyPair();
    const doc = {
      id: did,
      verificationMethod: [
        { id: `${did}#a`, type: 'Multikey', controller: did, publicKeyMultibase: multibaseFromSpki(a.publicKey) },
        { id: '#b', type: 'JsonWebKey2020', controller: did, publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(rawFromSpki(b.publicKey), 'hex').toString('base64url') } },
        { id: `${did}#auth`, type: 'Multikey', controller: did, publicKeyMultibase: multibaseFromSpki(notForSigning.publicKey) },
      ],
      assertionMethod: [`${did}#a`, '#b'],
    };
    const keys = ed25519KeysFromDidDocument(did, doc);
    expect(keys.sort()).toEqual([a.publicKey, b.publicKey].sort());
    expect(keys).not.toContain(notForSigning.publicKey);
    expect(() => ed25519KeysFromDidDocument('did:web:other.example', doc)).toThrow();
  });

  it('verifies a receipt whose issuer is a did:web, and rejects an impersonator', async () => {
    const did = 'did:web:council.example';
    const council = generateKeyPair();
    const attacker = generateKeyPair();
    const fetch = mockFetch({
      'https://council.example/.well-known/did.json': {
        id: did,
        verificationMethod: [{ id: `${did}#k1`, type: 'Multikey', controller: did, publicKeyMultibase: multibaseFromSpki(council.publicKey) }],
        assertionMethod: [`${did}#k1`],
      },
    });

    expect(await resolveDidWeb(did, fetch)).toEqual([council.publicKey]);

    const person = createPerson();
    const genuine = person.commit('genuine', { a: { b: 1 } });
    person.receive(genuine.record.id, buildReceipt({ commitment: genuine.commitment, outcome: 'SOVEREIGN', reason: '', issuer: did, keyPair: council }));
    const ok = await verifyPackageWithDidWeb(person.exportRecord(genuine.record.id), { fetch });
    expect(ok.issuerStatus).toBe('TRUSTED');
    expect(ok.valid).toBe(true);

    const forged = person.commit('forged', { a: { b: 2 } });
    person.receive(forged.record.id, buildReceipt({ commitment: forged.commitment, outcome: 'SOVEREIGN', reason: '', issuer: did, keyPair: attacker }));
    const bad = await verifyPackageWithDidWeb(person.exportRecord(forged.record.id), { fetch });
    expect(bad.issuerStatus).toBe('KEY_MISMATCH');
    expect(bad.valid).toBe(false);

    // Unresolvable DID → UNVERIFIED_ISSUER, invalid.
    const unknown = person.commit('unknown', { a: 3 });
    person.receive(unknown.record.id, buildReceipt({ commitment: unknown.commitment, outcome: 'SOVEREIGN', reason: '', issuer: 'did:web:nowhere.example', keyPair: attacker }));
    const unres = await verifyPackageWithDidWeb(person.exportRecord(unknown.record.id), { fetch });
    expect(unres.issuerStatus).toBe('UNVERIFIED_ISSUER');
    expect(unres.valid).toBe(false);
  });

  it('builds a TrustedIssuers map for named institutions from their did:web', async () => {
    const did = 'did:web:hmrc.example';
    const hmrc = generateKeyPair();
    const fetch = mockFetch({
      'https://hmrc.example/.well-known/did.json': {
        id: did,
        verificationMethod: [{ id: `${did}#k`, type: 'Multikey', controller: did, publicKeyMultibase: multibaseFromSpki(hmrc.publicKey) }],
      },
    });
    const trusted = await trustedIssuersFromDidWeb({ HMRC: did }, fetch);
    expect(trusted).toEqual({ HMRC: [hmrc.publicKey] });
  });
});
