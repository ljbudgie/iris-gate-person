/**
 * @iris-gate/person – Core PersonClient implementation.
 *
 * `createPerson()` is the main entry point for individuals. It returns a
 * `PersonClient` that lets you:
 *
 * - **commit()** – Hash your case facts into a commitment (no facts leave
 *   your device).
 * - **receive()** – Store a receipt from an institution.
 * - **challenge()** / **challengeAll()** – Identify NULL (no-human-review)
 *   receipts.
 * - **search()** – Search vault records by label, tag, or outcome.
 * - **verify()** – Cryptographically verify any vault record.
 * - **exportRecord()** – Export a self-contained bundle for tribunals.
 * - **exportVaultEncrypted()** / **importVaultEncrypted()** – Encrypted backup
 *   and restore of the entire vault.
 */

import { randomUUID } from 'crypto';
import type {
  KeyPair,
  Commitment,
  Receipt,
  VaultRecord,
  EncryptedVault,
  ExportPackage,
  VerificationResult,
} from './types';
import { generateKeyPair, hashPayload, randomHex, encryptVault, decryptVault } from './crypto';
import { verifyReceipt } from './receipt';
import { verifyRecord } from './verify';

// ---------------------------------------------------------------------------
// PersonClient interface
// ---------------------------------------------------------------------------

/**
 * The sovereign personal vault client.
 * Create one with {@link createPerson}.
 */
export interface PersonClient {
  /**
   * The person's ed25519 public key.
   * This can be shared openly so institutions can verify challenges.
   */
  readonly publicKey: string;

  /**
   * Create a cryptographic commitment from case facts.
   *
   * The commitment is a one-way SHA-256 hash – the original facts are **not**
   * included and should never leave the device. The returned commitment is safe
   * to hand to an institution or AI system.
   *
   * @param label   - Human-readable label for this case (stored locally only).
   * @param facts   - The actual case facts (stored locally, never transmitted).
   * @param tags    - Optional tags for later searching.
   * @returns The stored {@link VaultRecord} and the {@link Commitment} to send.
   *
   * @example
   * ```ts
   * const { commitment, record } = person.commit(
   *   'DWP ESA appeal 2026',
   *   { claimRef: 'XY123', dateOfBirth: '1980-01-01', condition: 'fibromyalgia' },
   *   ['dwp', 'esa'],
   * );
   * // Send only `commitment` to the institution – never `record.facts`
   * ```
   */
  commit(
    label: string,
    facts: Record<string, unknown>,
    tags?: string[],
  ): { commitment: Commitment; record: VaultRecord };

  /**
   * Store a receipt received from an institution.
   *
   * The receipt's ed25519 signature is verified before storing. If the
   * signature is invalid the receipt is rejected and an error is thrown.
   *
   * @param recordId - The vault record ID returned by {@link commit}.
   * @param receipt  - The signed receipt from the institution.
   * @returns The updated {@link VaultRecord}.
   * @throws If `recordId` is not found or the receipt signature is invalid.
   */
  receive(recordId: string, receipt: Receipt): VaultRecord;

  /**
   * Return all records whose receipts have `outcome === "NULL"` (no human
   * review) – i.e. records that are potential grounds for challenge.
   */
  challenge(): VaultRecord[];

  /**
   * Return records whose receipts have `outcome === "NULL"` **and** match
   * any of the supplied filters. Useful for bulk challenge across many records.
   *
   * @param filters - Optional `{ issuer?, label?, tags? }` filter object.
   */
  challengeAll(filters?: { issuer?: string; label?: string; tags?: string[] }): VaultRecord[];

  /**
   * Search vault records by label substring, tag, or receipt outcome.
   *
   * @param query - A free-text string matched against labels and tags,
   *                OR one of the special values `"SOVEREIGN"` / `"NULL"`.
   */
  search(query: string): VaultRecord[];

  /**
   * Cryptographically verify a vault record.
   * Re-hashes the facts and verifies the receipt signature.
   *
   * @param recordId - The vault record ID to verify.
   * @returns {@link VerificationResult} with full detail.
   * @throws If `recordId` is not found.
   */
  verify(recordId: string): VerificationResult;

  /**
   * Export a self-contained {@link ExportPackage} for a tribunal, ombudsman,
   * or court. Includes the original facts (for hash verification) and
   * step-by-step instructions for independent verification.
   *
   * @param recordId - The vault record ID to export.
   * @throws If `recordId` is not found.
   */
  exportRecord(recordId: string): ExportPackage;

  /**
   * Export the entire vault as an AES-256-GCM encrypted bundle.
   * Use this to back up your vault to a file or cloud storage.
   *
   * @param passphrase - A strong passphrase. Not stored anywhere.
   * @returns An {@link EncryptedVault} bundle (safe to serialise as JSON).
   */
  exportVaultEncrypted(passphrase: string): EncryptedVault;

  /**
   * Restore vault records from an {@link EncryptedVault} bundle.
   * Existing records with the same ID are overwritten.
   *
   * @param vault      - The encrypted bundle from {@link exportVaultEncrypted}.
   * @param passphrase - The passphrase used when the vault was exported.
   * @throws If the passphrase is wrong or data is corrupted.
   */
  importVaultEncrypted(vault: EncryptedVault, passphrase: string): void;

  /**
   * Return all vault records (read-only snapshot).
   */
  listRecords(): VaultRecord[];

  /**
   * Return a single vault record by ID, or `undefined` if not found.
   */
  getRecord(recordId: string): VaultRecord | undefined;
}

// ---------------------------------------------------------------------------
// createPerson
// ---------------------------------------------------------------------------

/**
 * Create a new sovereign personal vault.
 *
 * Optionally supply an existing `keyPair` (e.g. restored from secure storage).
 * If omitted, a fresh ed25519 key-pair is generated.
 *
 * @example
 * ```ts
 * import { createPerson } from '@iris-gate/person';
 *
 * const person = createPerson();
 *
 * // Commit your case facts locally
 * const { commitment, record } = person.commit(
 *   'Complaint to Ombudsman 2026',
 *   { ref: 'OMB-001', detail: 'No response in 6 months' },
 *   ['ombudsman'],
 * );
 *
 * // Send ONLY `commitment` to the institution
 * // Later, store their receipt:
 * person.receive(record.id, institutionReceipt);
 *
 * // Check for NULL receipts
 * const nullCases = person.challenge();
 * ```
 */
export function createPerson(keyPair?: KeyPair): PersonClient {
  let activeKeys: KeyPair = keyPair ?? generateKeyPair();
  const vault: Map<string, VaultRecord> = new Map();

  // ── commit ───────────────────────────────────────────────────────────────
  function commit(
    label: string,
    facts: Record<string, unknown>,
    tags: string[] = [],
  ): { commitment: Commitment; record: VaultRecord } {
    const nonce = randomHex(32);
    const hash = hashPayload(facts, nonce);
    const timestamp = new Date().toISOString();

    const commitment: Commitment = {
      hash,
      timestamp,
      nonce,
      version: 1,
    };

    const record: VaultRecord = {
      id: randomUUID(),
      label,
      commitment,
      facts,
      createdAt: timestamp,
      tags,
    };

    vault.set(record.id, record);
    return { commitment, record };
  }

  // ── receive ──────────────────────────────────────────────────────────────
  function receive(recordId: string, receipt: Receipt): VaultRecord {
    const record = vault.get(recordId);
    if (!record) {
      throw new Error(`Record not found: ${recordId}`);
    }
    if (!verifyReceipt(receipt)) {
      throw new Error('Receipt has an invalid signature and was rejected.');
    }
    const updated: VaultRecord = { ...record, receipt };
    vault.set(recordId, updated);
    return updated;
  }

  // ── challenge ────────────────────────────────────────────────────────────
  function challenge(): VaultRecord[] {
    return Array.from(vault.values()).filter((r) => r.receipt?.outcome === 'NULL');
  }

  // ── challengeAll ─────────────────────────────────────────────────────────
  function challengeAll(filters: { issuer?: string; label?: string; tags?: string[] } = {}): VaultRecord[] {
    return challenge().filter((r) => {
      if (filters.issuer && r.receipt?.issuer !== filters.issuer) return false;
      if (filters.label && !r.label.toLowerCase().includes(filters.label.toLowerCase())) return false;
      if (filters.tags && filters.tags.length > 0) {
        const matchesTag = filters.tags.some((t) => r.tags.includes(t));
        if (!matchesTag) return false;
      }
      return true;
    });
  }

  // ── search ───────────────────────────────────────────────────────────────
  function search(query: string): VaultRecord[] {
    const q = query.trim();
    if (q === 'SOVEREIGN' || q === 'NULL') {
      return Array.from(vault.values()).filter((r) => r.receipt?.outcome === q);
    }
    const lower = q.toLowerCase();
    return Array.from(vault.values()).filter(
      (r) =>
        r.label.toLowerCase().includes(lower) ||
        r.tags.some((t) => t.toLowerCase().includes(lower)),
    );
  }

  // ── verify ───────────────────────────────────────────────────────────────
  function verify(recordId: string): VerificationResult {
    const record = vault.get(recordId);
    if (!record) {
      throw new Error(`Record not found: ${recordId}`);
    }
    return verifyRecord(record);
  }

  // ── exportRecord ─────────────────────────────────────────────────────────
  function exportRecord(recordId: string): ExportPackage {
    const record = vault.get(recordId);
    if (!record) {
      throw new Error(`Record not found: ${recordId}`);
    }

    const verificationInstructions = buildVerificationInstructions(record);

    return {
      record,
      verificationInstructions,
      exportedBy: '@iris-gate/person@1.0.0',
      exportedAt: new Date().toISOString(),
    };
  }

  // ── exportVaultEncrypted ─────────────────────────────────────────────────
  function exportVaultEncrypted(passphrase: string): EncryptedVault {
    const data = {
      keys: activeKeys,
      records: Array.from(vault.values()),
    };
    return encryptVault(JSON.stringify(data), passphrase);
  }

  // ── importVaultEncrypted ─────────────────────────────────────────────────
  function importVaultEncrypted(encryptedVault: EncryptedVault, passphrase: string): void {
    const plaintext = decryptVault(encryptedVault, passphrase);
    const data = JSON.parse(plaintext) as { keys: KeyPair; records: VaultRecord[] };
    // Restore the original key-pair so that publicKey stays consistent with
    // the vault that was exported. This prevents key-mismatch issues when
    // restoring on a different PersonClient instance.
    activeKeys = data.keys;
    for (const record of data.records) {
      vault.set(record.id, record);
    }
  }

  // ── listRecords ──────────────────────────────────────────────────────────
  function listRecords(): VaultRecord[] {
    return Array.from(vault.values());
  }

  // ── getRecord ────────────────────────────────────────────────────────────
  function getRecord(recordId: string): VaultRecord | undefined {
    return vault.get(recordId);
  }

  return {
    get publicKey() { return activeKeys.publicKey; },
    commit,
    receive,
    challenge,
    challengeAll,
    search,
    verify,
    exportRecord,
    exportVaultEncrypted,
    importVaultEncrypted,
    listRecords,
    getRecord,
  };
}

// ---------------------------------------------------------------------------
// Internal: verification instructions
// ---------------------------------------------------------------------------

function buildVerificationInstructions(record: VaultRecord): string[] {
  const steps: string[] = [
    '== INDEPENDENT VERIFICATION INSTRUCTIONS ==',
    '',
    'These steps allow any tribunal, ombudsman, or court to verify this export',
    'package with no external services and no specialist knowledge.',
    '',
    '--- Step 1: Verify the commitment hash ---',
    '',
    `  The commitment hash in this record is:`,
    `    ${record.commitment.hash}`,
    '',
    '  To verify it yourself:',
    '    a) Take the "facts" object from this export.',
    '    b) Sort the keys alphabetically and serialise to JSON (no extra spaces).',
    '    c) Prepend the nonce followed by a colon:',
    `       "${record.commitment.nonce}:<json>"`,
    '    d) Compute SHA-256 of that string.',
    '    e) The result must match the hash above.',
    '',
    '--- Step 2: Verify the institution signature ---',
    '',
  ];

  if (record.receipt) {
    steps.push(
      '  The receipt was signed by:',
      `    Issuer: ${record.receipt.issuer}`,
      `    Public key (SPKI DER, hex): ${record.receipt.issuerPublicKey}`,
      '',
      '  To verify the signature:',
      '    a) Construct the signed message:',
      '       JSON.stringify({ commitmentHash, outcome, reason, issuer, issuedAt })',
      '       using the values from the receipt (keys in that order).',
      `    b) Decode the signature hex: ${record.receipt.signature}`,
      '    c) Verify the ed25519 signature using the issuer public key above.',
      '    d) The verification must succeed.',
      '',
      '--- Step 3: Confirm hash linkage ---',
      '',
      '  Confirm that receipt.commitmentHash equals record.commitment.hash:',
      `    Receipt hash:    ${record.receipt.commitmentHash}`,
      `    Commitment hash: ${record.commitment.hash}`,
      `    Match: ${record.receipt.commitmentHash === record.commitment.hash ? 'YES ✓' : 'NO ✗'}`,
    );
  } else {
    steps.push('  No receipt present in this record yet.');
  }

  steps.push(
    '',
    '--- Outcome ---',
    '',
    record.receipt
      ? `  Outcome: ${record.receipt.outcome}`
      : '  Outcome: PENDING (no receipt received)',
    '',
    '  SOVEREIGN = A real human reviewed this specific case.',
    '  NULL      = No human review was given (automated, ignored, or refused).',
    '',
    '== END OF INSTRUCTIONS ==',
  );

  return steps;
}
