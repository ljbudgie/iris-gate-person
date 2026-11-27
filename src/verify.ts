/**
 * @iris-gate/person – Standalone verifyPackage for third parties.
 *
 * A tribunal, ombudsman, or court can use this module to independently
 * verify an export package with no external services, no trust in the
 * library vendor, and no specialist cryptographic knowledge.
 *
 * The verification is purely mathematical: if the numbers check out, the
 * record is authentic.
 */

import type { ExportPackage, VaultRecord, Receipt, VerificationResult } from './types';
import { hashPayload, verifySignature } from './crypto';
import { verifyReceiptSignature } from './receipt';
import { checkIssuer, resolveDidWeb } from './issuer';
import type { VerifyOptions, FetchLike, IssuerStatus } from './issuer';

// ---------------------------------------------------------------------------
// verifyPackage
// ---------------------------------------------------------------------------

/**
 * Independently verify an {@link ExportPackage} produced by
 * {@link PersonClient.exportRecord}.
 *
 * Three checks are performed:
 *
 * 1. **Commitment validity** – Re-hash the facts + nonce and confirm it
 *    matches the commitment hash that was sent to the institution. Proves
 *    the commitment was derived from *these* facts.
 *
 * 2. **Signature validity** – Verify the institution's ed25519 signature
 *    on the receipt body. Proves the institution issued *this* receipt.
 *
 * 3. **Hash linkage** – Confirm the receipt's `commitmentHash` equals the
 *    commitment's `hash`. Proves the receipt responds to *this* commitment.
 *
 * All three must pass for `valid` to be `true`.
 *
 * @example
 * ```ts
 * import { verifyPackage } from '@iris-gate/person';
 *
 * const result = verifyPackage(exportedBundle);
 * console.log(result.valid);    // true / false
 * console.log(result.summary);  // plain-English explanation
 * ```
 */
export function verifyPackage(pkg: ExportPackage, options: VerifyOptions = {}): VerificationResult {
  const { record } = pkg;
  const verifiedAt = new Date().toISOString();

  // ── Check 1: Commitment validity ────────────────────────────────────────
  let commitmentValid = false;
  try {
    const recomputed = hashPayload(record.facts, record.commitment.nonce);
    commitmentValid = recomputed === record.commitment.hash;
  } catch {
    commitmentValid = false;
  }

  // ── Check 2: Signature validity ─────────────────────────────────────────
  let signatureValid = false;
  if (record.receipt) {
    try {
      signatureValid = verifyReceiptSignature(record.receipt);
    } catch {
      signatureValid = false;
    }
  }

  // ── Check 3: Hash linkage ────────────────────────────────────────────────
  let hashesMatch = false;
  if (record.receipt) {
    hashesMatch = record.receipt.commitmentHash === record.commitment.hash;
  }

  // ── Check 4: Issuer binding ──────────────────────────────────────────────
  // The key embedded in the receipt proves nothing about *who* signed it. It
  // must match a key trusted (pinned or did:web-resolved) for the named issuer.
  let issuerStatus: IssuerStatus;
  try {
    issuerStatus = checkIssuer(record.receipt, options.trustedIssuers);
  } catch {
    issuerStatus = 'KEY_MISMATCH';
  }
  const issuerAcceptable =
    issuerStatus === 'TRUSTED' ||
    (issuerStatus === 'UNVERIFIED_ISSUER' && options.allowUnverifiedIssuer === true);

  const valid = commitmentValid && signatureValid && hashesMatch && issuerAcceptable;

  const summary = buildSummary({ commitmentValid, signatureValid, hashesMatch, issuerStatus, valid, record });

  return {
    signatureValid,
    commitmentValid,
    hashesMatch,
    issuerStatus,
    valid,
    summary,
    verifiedAt,
  };
}

// ---------------------------------------------------------------------------
// verifyPackageWithDidWeb
// ---------------------------------------------------------------------------

/**
 * Like {@link verifyPackage}, but when `receipt.issuer` is a `did:web`
 * identifier (e.g. `did:web:example.gov.uk`) its DID document is fetched
 * over HTTPS from the institution's own domain and the keys found there are
 * trusted for that issuer. Resolution failures leave the issuer unverified.
 */
export async function verifyPackageWithDidWeb(
  pkg: ExportPackage,
  options: VerifyOptions & { fetch?: FetchLike } = {},
): Promise<VerificationResult> {
  const issuer = pkg.record.receipt?.issuer;
  const trustedIssuers = { ...(options.trustedIssuers ?? {}) };
  if (issuer && issuer.startsWith('did:web:') && !trustedIssuers[issuer]) {
    try {
      trustedIssuers[issuer] = await resolveDidWeb(issuer, options.fetch);
    } catch {
      // leave unresolved → UNVERIFIED_ISSUER
    }
  }
  return verifyPackage(pkg, { ...options, trustedIssuers });
}

// ---------------------------------------------------------------------------
// verifyRecord (convenience wrapper – verify a raw VaultRecord + facts)
// ---------------------------------------------------------------------------

/**
 * Verify a raw {@link VaultRecord} directly (without an export package).
 * Useful for programmatic checks inside the vault.
 *
 * @param record - The vault record to verify.
 * @returns {@link VerificationResult}
 */
export function verifyRecord(record: VaultRecord, options: VerifyOptions = {}): VerificationResult {
  const pkg: ExportPackage = {
    record,
    verificationInstructions: [],
    exportedBy: '@iris-gate/person',
    exportedAt: new Date().toISOString(),
  };
  return verifyPackage(pkg, options);
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function buildSummary(opts: {
  commitmentValid: boolean;
  signatureValid: boolean;
  hashesMatch: boolean;
  issuerStatus: IssuerStatus;
  valid: boolean;
  record: VaultRecord;
}): string {
  const { commitmentValid, signatureValid, hashesMatch, issuerStatus, valid, record } = opts;
  const lines: string[] = [];

  lines.push(`Verification of record "${record.label}" (id: ${record.id})`);
  lines.push('');
  lines.push(`  [${commitmentValid ? '✓' : '✗'}] Commitment hash matches the supplied facts + nonce`);
  lines.push(`  [${signatureValid ? '✓' : '✗'}] Institution signature is cryptographically valid`);
  lines.push(`  [${hashesMatch ? '✓' : '✗'}] Receipt commitment hash matches the record commitment`);
  lines.push(`  [${issuerStatus === 'TRUSTED' ? '✓' : '✗'}] Signing key belongs to the named issuer (${issuerStatus})`);
  lines.push('');

  if (valid) {
    lines.push(
      issuerStatus === 'TRUSTED'
        ? 'RESULT: VALID – All checks passed. The receipt is authentic, unaltered and signed by a trusted key for the named issuer.'
        : 'RESULT: VALID (UNVERIFIED_ISSUER accepted by caller) – the signing key is NOT tied to the named issuer.',
    );
    if (record.receipt) {
      lines.push(`        Issued by: ${record.receipt.issuer}`);
      lines.push(`        Outcome:   ${record.receipt.outcome}`);
      if (record.receipt.reason) {
        lines.push(`        Reason:    ${record.receipt.reason}`);
      }
    }
  } else {
    lines.push('RESULT: INVALID – One or more checks failed. Details:');
    if (!commitmentValid) {
      lines.push('        • The commitment hash does not match the facts. The facts may have been altered.');
    }
    if (!signatureValid) {
      lines.push('        • The institution signature is invalid or the receipt has been tampered with.');
    }
    if (!hashesMatch) {
      lines.push('        • The receipt references a different commitment than this record.');
    }
    if (issuerStatus === 'UNVERIFIED_ISSUER') {
      lines.push('        • UNVERIFIED_ISSUER: no trusted key is known for this issuer, so the receipt');
      lines.push('          cannot be tied to the named institution. Pin its key or resolve its did:web.');
    }
    if (issuerStatus === 'KEY_MISMATCH') {
      lines.push('        • KEY_MISMATCH: the receipt was signed with a key that is not one of the');
      lines.push('          named institution\'s trusted keys. It may be an impersonation.');
    }
    if (!record.receipt) {
      lines.push('        • No receipt is present in this record.');
    }
  }

  return lines.join('\n');
}
