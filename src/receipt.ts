/**
 * @iris-gate/person – Receipt module.
 *
 * Institution-side helpers for building and verifying receipts.
 * Institutions receive a {@link Commitment} from a person and respond
 * with a signed {@link Receipt} indicating whether a real human reviewed
 * the specific case (SOVEREIGN) or not (NULL).
 */

import type { Commitment, Receipt, ReceiptOutcome, KeyPair } from './types';
import { signMessage, verifySignature, hashPayload } from './crypto';
import { checkIssuer } from './issuer';
import type { VerifyOptions } from './issuer';

// ---------------------------------------------------------------------------
// Canonical form
// ---------------------------------------------------------------------------

/**
 * Produce the canonical string that is signed/verified for a receipt.
 * All fields are deterministically ordered so both sides can reproduce it.
 */
function receiptCanonical(
  commitmentHash: string,
  outcome: ReceiptOutcome,
  reason: string,
  issuer: string,
  issuedAt: string,
): string {
  return JSON.stringify({ commitmentHash, outcome, reason, issuer, issuedAt });
}

// ---------------------------------------------------------------------------
// buildReceipt
// ---------------------------------------------------------------------------

/**
 * Build a signed receipt in response to a person's commitment.
 *
 * This is an **institution-side** helper. The institution:
 * 1. Receives the commitment hash from the person.
 * 2. Decides on an outcome (`"SOVEREIGN"` if a human reviewed; `"NULL"` otherwise).
 * 3. Calls this function with their private key to produce a tamper-proof receipt.
 *
 * @example
 * ```ts
 * const keys = generateKeyPair();
 * const receipt = buildReceipt({
 *   commitment,
 *   outcome: 'SOVEREIGN',
 *   reason: 'Case reviewed by caseworker Jane Doe on 2026-04-09',
 *   issuer: 'Department of Work and Pensions',
 *   keyPair: keys,
 * });
 * ```
 */
export function buildReceipt(options: {
  /** The commitment received from the person. */
  commitment: Commitment;
  /** Whether a human reviewed this specific case. */
  outcome: ReceiptOutcome;
  /** Free-text reason (may be empty but is recommended for tribunals). */
  reason: string;
  /** Identifying name of the issuing institution. */
  issuer: string;
  /** Institution's ed25519 key-pair (private key used to sign). */
  keyPair: KeyPair;
  /** Optional override for the issuedAt timestamp (ISO-8601). Defaults to now. */
  issuedAt?: string;
}): Receipt {
  const { commitment, outcome, reason, issuer, keyPair, issuedAt } = options;
  const timestamp = issuedAt ?? new Date().toISOString();

  const canonical = receiptCanonical(commitment.hash, outcome, reason, issuer, timestamp);
  const signature = signMessage(canonical, keyPair.privateKey);

  return {
    commitmentHash: commitment.hash,
    outcome,
    reason,
    issuer,
    issuedAt: timestamp,
    signature,
    issuerPublicKey: keyPair.publicKey,
  };
}

// ---------------------------------------------------------------------------
// verifyPersonCommitment
// ---------------------------------------------------------------------------

/**
 * Verify that a {@link Commitment} was produced correctly from the supplied
 * facts and nonce.
 *
 * Institutions MAY call this after receiving proof-of-facts from a person
 * during a challenge/tribunal process, to confirm the fingerprint matches.
 *
 * @param commitment - The commitment originally sent by the person.
 * @param facts      - The original facts the person claims to have committed.
 * @param nonce      - The nonce used when the commitment was created.
 * @returns `true` if the commitment hash matches the facts + nonce.
 */
export function verifyPersonCommitment(
  commitment: Commitment,
  facts: Record<string, unknown>,
  nonce: string,
): boolean {
  const expected = hashPayload(facts, nonce);
  return expected === commitment.hash;
}

// ---------------------------------------------------------------------------
// verifyReceiptSignature / verifyReceipt
// ---------------------------------------------------------------------------

/**
 * Check only that the receipt's ed25519 signature is valid for the public key
 * embedded in the receipt.
 *
 * **This does not prove who signed it.** Anyone can generate a key-pair and
 * put any institution name in `issuer`. Use {@link verifyReceipt} with
 * `trustedIssuers` to check the key belongs to the named institution.
 */
export function verifyReceiptSignature(receipt: Receipt): boolean {
  const canonical = receiptCanonical(
    receipt.commitmentHash,
    receipt.outcome,
    receipt.reason,
    receipt.issuer,
    receipt.issuedAt,
  );
  return verifySignature(canonical, receipt.signature, receipt.issuerPublicKey);
}

/**
 * Verify a receipt: the signature must be valid **and** the signing key must
 * be one of the keys trusted for `receipt.issuer` (pinned, or resolved via
 * did:web — see {@link trustedIssuersFromDidWeb}).
 *
 * Returns `false` when the issuer key cannot be tied to the named
 * institution (`UNVERIFIED_ISSUER`) unless `allowUnverifiedIssuer` is set.
 */
export function verifyReceipt(receipt: Receipt, options: VerifyOptions = {}): boolean {
  if (!verifyReceiptSignature(receipt)) return false;
  const status = checkIssuer(receipt, options.trustedIssuers);
  if (status === 'TRUSTED') return true;
  return status === 'UNVERIFIED_ISSUER' && options.allowUnverifiedIssuer === true;
}
