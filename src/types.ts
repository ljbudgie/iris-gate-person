/**
 * @iris-gate/person – Shared TypeScript types and interfaces.
 *
 * These types flow through every layer of the library.
 * They are intentionally narrow so the API surface stays readable.
 */

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

/** An ed25519 key-pair used to sign and verify receipts. */
export interface KeyPair {
  /** 32-byte public key (hex-encoded). */
  publicKey: string;
  /** 64-byte private key (hex-encoded). Never leave the device. */
  privateKey: string;
}

// ---------------------------------------------------------------------------
// Commitment
// ---------------------------------------------------------------------------

/**
 * A cryptographic commitment produced by the person (client-side).
 * Contains NO original case facts – only a one-way hash fingerprint.
 */
export interface Commitment {
  /** SHA-256 hash of the canonical case payload (hex). */
  hash: string;
  /** ISO-8601 timestamp of when the commitment was created. */
  timestamp: string;
  /** Nonce (hex) added to prevent pre-image attacks on predictable inputs. */
  nonce: string;
  /** Commitment format version for future-proofing. */
  version: number;
}

// ---------------------------------------------------------------------------
// Receipt
// ---------------------------------------------------------------------------

/**
 * Receipt outcome – mirrors The Burgess Principle's core distinction.
 *
 * - `"SOVEREIGN"` – a real human reviewed this specific case.
 * - `"NULL"`      – no human review was given (automated, ignored, refused).
 */
export type ReceiptOutcome = 'SOVEREIGN' | 'NULL';

/**
 * A receipt issued by an institution in response to a {@link Commitment}.
 * The receipt is ed25519-signed so it cannot be repudiated.
 */
export interface Receipt {
  /** The commitment hash this receipt responds to. */
  commitmentHash: string;
  /** Whether a human reviewed this specific case. */
  outcome: ReceiptOutcome;
  /** Free-text reason supplied by the institution (may be empty). */
  reason: string;
  /** Name or identifier of the issuing institution. */
  issuer: string;
  /** ISO-8601 timestamp of when the receipt was issued. */
  issuedAt: string;
  /** ed25519 signature over the canonical receipt body (hex). */
  signature: string;
  /** Public key of the institution that signed the receipt (hex). */
  issuerPublicKey: string;
}

// ---------------------------------------------------------------------------
// Vault record
// ---------------------------------------------------------------------------

/**
 * A complete, self-contained record stored in the encrypted vault.
 * Each record links a commitment to its receipt and the original facts
 * (kept local – never transmitted).
 */
export interface VaultRecord {
  /** Stable unique identifier for this record (UUID v4). */
  id: string;
  /** Human-readable label for this record. */
  label: string;
  /** The commitment that was sent to the institution. */
  commitment: Commitment;
  /** The receipt received from the institution (may be undefined if pending). */
  receipt?: Receipt;
  /** Original case facts – kept local, never transmitted. */
  facts: Record<string, unknown>;
  /** ISO-8601 timestamp of when the record was created. */
  createdAt: string;
  /** Free-text tags for searching. */
  tags: string[];
}

// ---------------------------------------------------------------------------
// Vault (encrypted backup)
// ---------------------------------------------------------------------------

/**
 * Serialisable encrypted vault bundle for backup/restore.
 * The body is AES-256-GCM encrypted so only someone with the vault key
 * can read the contents.
 */
export interface EncryptedVault {
  /** Algorithm identifier – always `"aes-256-gcm"`. */
  algorithm: 'aes-256-gcm';
  /** Hex-encoded initialisation vector. */
  iv: string;
  /** Hex-encoded authentication tag. */
  authTag: string;
  /** Hex-encoded salt used to derive the key from the passphrase. */
  salt: string;
  /** Base64-encoded ciphertext. */
  ciphertext: string;
  /** Format version for forward-compatibility. */
  version: number;
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/**
 * Result of an independent third-party verification of a vault record.
 * Returned by {@link verifyPackage}.
 */
export interface VerificationResult {
  /** Whether the receipt signature is cryptographically valid. */
  signatureValid: boolean;
  /** Whether the commitment hash matches the facts provided. */
  commitmentValid: boolean;
  /** Whether the receipt's commitment hash matches the record's commitment. */
  hashesMatch: boolean;
  /** Overall pass/fail. True only when all checks pass. */
  valid: boolean;
  /** Human-readable summary of the verification. */
  summary: string;
  /** ISO-8601 timestamp of when this verification was performed. */
  verifiedAt: string;
}

// ---------------------------------------------------------------------------
// Export package (for tribunals / ombudsmen)
// ---------------------------------------------------------------------------

/**
 * A self-contained export bundle that a person can hand to a tribunal,
 * ombudsman, or court. Includes everything needed for independent
 * verification without any external services.
 */
export interface ExportPackage {
  /** The vault record (commitment + receipt + facts). */
  record: VaultRecord;
  /**
   * Step-by-step verification instructions written in plain English.
   * A tribunal can follow these with no specialist knowledge.
   */
  verificationInstructions: string[];
  /** Library version that produced this export. */
  exportedBy: string;
  /** ISO-8601 timestamp. */
  exportedAt: string;
}
