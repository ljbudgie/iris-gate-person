/**
 * @iris-gate/person – Binding receipt signing keys to named institutions.
 *
 * A receipt carries the public key that signed it. On its own that proves
 * only that *someone* holding *some* key signed the receipt: anyone can
 * generate a key-pair and write `issuer: "HMRC"`. To prove that the named
 * institution signed it, the verifier must check the key against a source it
 * already trusts:
 *
 * 1. a pinned list of institution keys ({@link TrustedIssuers}), or
 * 2. a `did:web` DID document published on the institution's own domain
 *    ({@link resolveDidWeb} / {@link trustedIssuersFromDidWeb}).
 *
 * Verification that relies only on the key embedded in the receipt reports
 * `UNVERIFIED_ISSUER` and is not treated as valid by default.
 */

import type { Receipt } from './types';

/** Ed25519 SPKI DER prefix (RFC 8410): SEQUENCE { AlgorithmIdentifier(1.3.101.112), BIT STRING }. */
const ED25519_SPKI_PREFIX = '302a300506032b6570032100';

/**
 * Map of issuer name (exactly as it appears in `receipt.issuer`) to the
 * Ed25519 public keys that issuer is known to sign with. Keys may be given as
 * SPKI DER hex (as produced by {@link generateKeyPair}) or as raw 32-byte hex.
 */
export type TrustedIssuers = Record<string, string[]>;

/**
 * - `TRUSTED`           – the signing key is pinned/resolved for this issuer.
 * - `UNVERIFIED_ISSUER` – no trusted key is known for this issuer; only the
 *                         key embedded in the receipt is available.
 * - `KEY_MISMATCH`      – trusted keys are known for this issuer, but the
 *                         receipt was signed with a different key
 *                         (likely impersonation).
 * - `NO_RECEIPT`        – there is no receipt to check.
 */
export type IssuerStatus = 'TRUSTED' | 'UNVERIFIED_ISSUER' | 'KEY_MISMATCH' | 'NO_RECEIPT';

/** Options accepted by the verification functions. */
export interface VerifyOptions {
  /** Pinned or resolved institution keys. */
  trustedIssuers?: TrustedIssuers;
  /**
   * Opt-in escape hatch: treat a receipt as valid even when the issuer key
   * cannot be tied to the named institution. The result still reports
   * `issuerStatus: 'UNVERIFIED_ISSUER'`. Default `false`.
   */
  allowUnverifiedIssuer?: boolean;
}

/**
 * Normalise an Ed25519 public key (SPKI DER hex or raw 32-byte hex) to
 * lower-case SPKI DER hex. Returns `null` if the input is not a valid key
 * encoding.
 */
export function normaliseEd25519PublicKey(key: string): string | null {
  if (typeof key !== 'string') return null;
  const hex = key.trim().toLowerCase();
  if (!/^[0-9a-f]*$/.test(hex)) return null;
  if (hex.length === 64) return ED25519_SPKI_PREFIX + hex;
  if (hex.length === ED25519_SPKI_PREFIX.length + 64 && hex.startsWith(ED25519_SPKI_PREFIX)) return hex;
  return null;
}

/**
 * Decide whether the key that signed `receipt` belongs to the named issuer.
 * This does **not** check the signature itself; combine it with
 * {@link verifyReceiptSignature}.
 */
export function checkIssuer(receipt: Receipt | undefined, trustedIssuers?: TrustedIssuers): IssuerStatus {
  if (!receipt) return 'NO_RECEIPT';
  const pinned = trustedIssuers && Object.prototype.hasOwnProperty.call(trustedIssuers, receipt.issuer)
    ? trustedIssuers[receipt.issuer]
    : undefined;
  if (!pinned || pinned.length === 0) return 'UNVERIFIED_ISSUER';
  const signingKey = normaliseEd25519PublicKey(receipt.issuerPublicKey);
  if (!signingKey) return 'KEY_MISMATCH';
  const known = pinned.map(normaliseEd25519PublicKey).filter((k): k is string => k !== null);
  return known.includes(signingKey) ? 'TRUSTED' : 'KEY_MISMATCH';
}

// ---------------------------------------------------------------------------
// did:web resolution
// ---------------------------------------------------------------------------

/** Minimal fetch signature so callers can inject their own implementation. */
export type FetchLike = (url: string) => Promise<{ ok: boolean; status: number; json(): Promise<unknown> }>;

/**
 * Convert a `did:web` identifier to the HTTPS URL of its DID document
 * (W3C did:web method spec §3.2).
 *
 * - `did:web:example.gov.uk`             → `https://example.gov.uk/.well-known/did.json`
 * - `did:web:example.gov.uk:receipts`    → `https://example.gov.uk/receipts/did.json`
 * - `did:web:localhost%3A8443`           → `https://localhost:8443/.well-known/did.json`
 */
export function didWebToUrl(did: string): string {
  if (typeof did !== 'string' || !did.startsWith('did:web:')) {
    throw new Error(`Not a did:web identifier: ${did}`);
  }
  const parts = did.slice('did:web:'.length).split(':');
  if (parts.some((p) => p.length === 0)) {
    throw new Error(`Malformed did:web identifier: ${did}`);
  }
  const host = decodeURIComponent(parts[0]);
  if (!/^[a-z0-9.-]+(:[0-9]+)?$/i.test(host)) {
    throw new Error(`Invalid host in did:web identifier: ${did}`);
  }
  const path = parts.slice(1).map((p) => decodeURIComponent(p));
  if (path.some((p) => p.includes('/') || p === '..' || p === '.')) {
    throw new Error(`Invalid path in did:web identifier: ${did}`);
  }
  return path.length === 0
    ? `https://${host}/.well-known/did.json`
    : `https://${host}/${path.join('/')}/did.json`;
}

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58btcDecode(input: string): Uint8Array {
  const bytes: number[] = [0];
  for (const char of input) {
    const value = BASE58_ALPHABET.indexOf(char);
    if (value < 0) throw new Error('Invalid base58btc character.');
    let carry = value;
    for (let i = 0; i < bytes.length; i++) {
      carry += bytes[i] * 58;
      bytes[i] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  for (const char of input) {
    if (char !== '1') break;
    bytes.push(0);
  }
  return Uint8Array.from(bytes.reverse());
}

function rawKeyFromVerificationMethod(vm: Record<string, unknown>): string | null {
  // Multikey / Ed25519VerificationKey2020: publicKeyMultibase = 'z' + base58btc(0xed 0x01 || key)
  if (typeof vm.publicKeyMultibase === 'string' && vm.publicKeyMultibase.startsWith('z')) {
    try {
      const decoded = base58btcDecode(vm.publicKeyMultibase.slice(1));
      if (decoded.length === 34 && decoded[0] === 0xed && decoded[1] === 0x01) {
        return Buffer.from(decoded.slice(2)).toString('hex');
      }
    } catch {
      return null;
    }
    return null;
  }
  // JsonWebKey2020: { kty: 'OKP', crv: 'Ed25519', x: base64url(key) }
  const jwk = vm.publicKeyJwk as Record<string, unknown> | undefined;
  if (jwk && jwk.kty === 'OKP' && jwk.crv === 'Ed25519' && typeof jwk.x === 'string') {
    const raw = Buffer.from(jwk.x, 'base64url');
    return raw.length === 32 ? raw.toString('hex') : null;
  }
  return null;
}

/**
 * Extract the Ed25519 signing keys (SPKI DER hex) from a DID document.
 * Only keys usable for `assertionMethod` are returned; if the document has no
 * `assertionMethod` section, all `verificationMethod` entries are used.
 * The document's `id` must equal `did`.
 */
export function ed25519KeysFromDidDocument(did: string, doc: unknown): string[] {
  if (!doc || typeof doc !== 'object') throw new Error('DID document is not an object.');
  const d = doc as Record<string, unknown>;
  if (d.id !== did) throw new Error(`DID document id "${String(d.id)}" does not match ${did}.`);

  const methods = Array.isArray(d.verificationMethod) ? (d.verificationMethod as Record<string, unknown>[]) : [];
  const byId = new Map<string, Record<string, unknown>>();
  for (const vm of methods) {
    if (vm && typeof vm.id === 'string') {
      byId.set(vm.id, vm);
      if (vm.id.startsWith('#')) byId.set(`${did}${vm.id}`, vm);
    }
  }

  let candidates: Record<string, unknown>[];
  if (Array.isArray(d.assertionMethod)) {
    candidates = (d.assertionMethod as unknown[])
      .map((entry) => {
        if (typeof entry === 'string') return byId.get(entry) ?? byId.get(`${did}${entry}`);
        return entry && typeof entry === 'object' ? (entry as Record<string, unknown>) : undefined;
      })
      .filter((vm): vm is Record<string, unknown> => vm !== undefined);
  } else {
    candidates = methods;
  }

  const keys = new Set<string>();
  for (const vm of candidates) {
    if (typeof vm.controller === 'string' && vm.controller !== did) continue;
    const raw = rawKeyFromVerificationMethod(vm);
    const spki = raw ? normaliseEd25519PublicKey(raw) : null;
    if (spki) keys.add(spki);
  }
  return Array.from(keys);
}

/**
 * Resolve a `did:web` DID over HTTPS and return its Ed25519 signing keys
 * (SPKI DER hex). Uses the global `fetch` unless one is supplied.
 */
export async function resolveDidWeb(did: string, fetchImpl?: FetchLike): Promise<string[]> {
  const url = didWebToUrl(did);
  const f: FetchLike | undefined = fetchImpl ?? (globalThis as { fetch?: FetchLike }).fetch;
  if (!f) throw new Error('No fetch implementation available to resolve did:web.');
  const res = await f(url);
  if (!res.ok) throw new Error(`Failed to resolve ${did}: HTTP ${res.status}`);
  return ed25519KeysFromDidDocument(did, await res.json());
}

/**
 * Build a {@link TrustedIssuers} map by resolving a did:web for each issuer.
 *
 * @param issuers - Map of issuer name → did:web of that institution, e.g.
 *                  `{ "Example Council": "did:web:example.gov.uk" }`.
 *                  An issuer name that is itself a did:web may map to itself.
 */
export async function trustedIssuersFromDidWeb(
  issuers: Record<string, string>,
  fetchImpl?: FetchLike,
): Promise<TrustedIssuers> {
  const out: TrustedIssuers = {};
  for (const [name, did] of Object.entries(issuers)) {
    out[name] = await resolveDidWeb(did, fetchImpl);
  }
  return out;
}
