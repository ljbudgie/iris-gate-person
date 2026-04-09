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
import { verifyReceipt } from './receipt';

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
export function verifyPackage(pkg: ExportPackage): VerificationResult {
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
      signatureValid = verifyReceipt(record.receipt);
    } catch {
      signatureValid = false;
    }
  }

  // ── Check 3: Hash linkage ────────────────────────────────────────────────
  let hashesMatch = false;
  if (record.receipt) {
    hashesMatch = record.receipt.commitmentHash === record.commitment.hash;
  }

  const valid = commitmentValid && signatureValid && hashesMatch;

  const summary = buildSummary({ commitmentValid, signatureValid, hashesMatch, valid, record });

  return {
    signatureValid,
    commitmentValid,
    hashesMatch,
    valid,
    summary,
    verifiedAt,
  };
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
export function verifyRecord(record: VaultRecord): VerificationResult {
  const pkg: ExportPackage = {
    record,
    verificationInstructions: [],
    exportedBy: '@iris-gate/person',
    exportedAt: new Date().toISOString(),
  };
  return verifyPackage(pkg);
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function buildSummary(opts: {
  commitmentValid: boolean;
  signatureValid: boolean;
  hashesMatch: boolean;
  valid: boolean;
  record: VaultRecord;
}): string {
  const { commitmentValid, signatureValid, hashesMatch, valid, record } = opts;
  const lines: string[] = [];

  lines.push(`Verification of record "${record.label}" (id: ${record.id})`);
  lines.push('');
  lines.push(`  [${commitmentValid ? '✓' : '✗'}] Commitment hash matches the supplied facts + nonce`);
  lines.push(`  [${signatureValid ? '✓' : '✗'}] Institution signature is cryptographically valid`);
  lines.push(`  [${hashesMatch ? '✓' : '✗'}] Receipt commitment hash matches the record commitment`);
  lines.push('');

  if (valid) {
    lines.push('RESULT: VALID – All checks passed. The receipt is authentic and unaltered.');
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
    if (!record.receipt) {
      lines.push('        • No receipt is present in this record.');
    }
  }

  return lines.join('\n');
}
