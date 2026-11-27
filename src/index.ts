/**
 * @iris-gate/person
 *
 * Sovereign personal vault for The Burgess Principle.
 *
 * Keep your facts private. Send only a cryptographic fingerprint.
 * Receive signed receipts proving whether a human reviewed your case.
 *
 * @module @iris-gate/person
 */

// ── Core factory ────────────────────────────────────────────────────────────
export { createPerson } from './person';
export type { PersonClient } from './person';

// ── Institution helpers ─────────────────────────────────────────────────────
export { buildReceipt, verifyPersonCommitment, verifyReceipt, verifyReceiptSignature } from './receipt';

// ── Issuer binding (pinned keys / did:web) ──────────────────────────────────
export {
  checkIssuer,
  normaliseEd25519PublicKey,
  didWebToUrl,
  ed25519KeysFromDidDocument,
  resolveDidWeb,
  trustedIssuersFromDidWeb,
} from './issuer';
export type { TrustedIssuers, IssuerStatus, VerifyOptions, FetchLike } from './issuer';

// ── Third-party verification (tribunals, ombudsmen, courts) ─────────────────
export { verifyPackage, verifyPackageWithDidWeb, verifyRecord } from './verify';

// ── Crypto primitives (for advanced use / institutional side) ───────────────
export { generateKeyPair } from './crypto';
export { canonicalize } from './canonical';

// ── Shared types ────────────────────────────────────────────────────────────
export type {
  KeyPair,
  Commitment,
  Receipt,
  ReceiptOutcome,
  VaultRecord,
  EncryptedVault,
  ExportPackage,
  VerificationResult,
} from './types';
