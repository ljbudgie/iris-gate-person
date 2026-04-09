/**
 * @iris-gate/person – Low-level cryptographic primitives.
 *
 * Uses only Node.js built-in `crypto` module (no external dependencies).
 * Signatures use ed25519; hashing uses SHA-256; encryption uses AES-256-GCM.
 */

import { createHash, randomBytes, createCipheriv, createDecipheriv, generateKeyPairSync, sign, verify, pbkdf2Sync } from 'crypto';
import type { KeyPair, EncryptedVault } from './types';

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

/**
 * Generate a fresh ed25519 key-pair.
 * The private key must be stored securely and never transmitted.
 */
export function generateKeyPair(): KeyPair {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
  });
  return {
    publicKey: publicKey.toString('hex'),
    privateKey: privateKey.toString('hex'),
  };
}

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

/**
 * Compute a SHA-256 digest of `data` and return it as a lower-case hex string.
 */
export function sha256(data: string | Buffer): string {
  return createHash('sha256').update(data).digest('hex');
}

/**
 * Compute a SHA-256 commitment over a canonical JSON representation of
 * `payload`, mixed with a random `nonce` to prevent pre-image attacks.
 *
 * @param payload - Arbitrary object; keys are sorted for determinism.
 * @param nonce   - Hex-encoded random bytes (from {@link randomHex}).
 */
export function hashPayload(payload: Record<string, unknown>, nonce: string): string {
  const canonical = JSON.stringify(payload, Object.keys(payload).sort());
  return sha256(`${nonce}:${canonical}`);
}

/**
 * Return `length` random bytes as a lower-case hex string.
 */
export function randomHex(length: number = 32): string {
  return randomBytes(length).toString('hex');
}

// ---------------------------------------------------------------------------
// Ed25519 signing / verification
// ---------------------------------------------------------------------------

/**
 * Sign `message` with an ed25519 private key.
 *
 * @param message    - The data to sign (string or Buffer).
 * @param privateKey - Hex-encoded PKCS#8 DER private key from {@link generateKeyPair}.
 * @returns Hex-encoded 64-byte signature.
 */
export function signMessage(message: string | Buffer, privateKey: string): string {
  const keyBuffer = Buffer.from(privateKey, 'hex');
  const sig = sign(null, Buffer.isBuffer(message) ? message : Buffer.from(message, 'utf8'), {
    key: keyBuffer,
    format: 'der',
    type: 'pkcs8',
  });
  return sig.toString('hex');
}

/**
 * Verify an ed25519 signature.
 *
 * @param message   - The original data that was signed.
 * @param signature - Hex-encoded signature from {@link signMessage}.
 * @param publicKey - Hex-encoded SPKI DER public key from {@link generateKeyPair}.
 * @returns `true` if the signature is valid, `false` otherwise.
 */
export function verifySignature(message: string | Buffer, signature: string, publicKey: string): boolean {
  try {
    const keyBuffer = Buffer.from(publicKey, 'hex');
    const sigBuffer = Buffer.from(signature, 'hex');
    return verify(
      null,
      Buffer.isBuffer(message) ? message : Buffer.from(message, 'utf8'),
      { key: keyBuffer, format: 'der', type: 'spki' },
      sigBuffer,
    );
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// AES-256-GCM encryption / decryption
// ---------------------------------------------------------------------------

const AES_KEY_BYTES = 32; // 256 bits
const AES_IV_BYTES = 12;  // 96-bit IV recommended for GCM
const SALT_BYTES = 32;
const PBKDF2_ITERATIONS = 200_000;
const PBKDF2_DIGEST = 'sha256';

/**
 * Derive a 256-bit AES key from a passphrase and salt using PBKDF2-SHA256.
 */
function deriveKey(passphrase: string, salt: Buffer): Buffer {
  return pbkdf2Sync(passphrase, salt, PBKDF2_ITERATIONS, AES_KEY_BYTES, PBKDF2_DIGEST);
}

/**
 * Encrypt `plaintext` with AES-256-GCM using a key derived from `passphrase`.
 *
 * @param plaintext  - UTF-8 string to encrypt.
 * @param passphrase - User-supplied passphrase. Not stored anywhere.
 * @returns {@link EncryptedVault} bundle ready for serialisation.
 */
export function encryptVault(plaintext: string, passphrase: string): EncryptedVault {
  const salt = randomBytes(SALT_BYTES);
  const iv = randomBytes(AES_IV_BYTES);
  const key = deriveKey(passphrase, salt);

  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return {
    algorithm: 'aes-256-gcm',
    iv: iv.toString('hex'),
    authTag: authTag.toString('hex'),
    salt: salt.toString('hex'),
    ciphertext: encrypted.toString('base64'),
    version: 1,
  };
}

/**
 * Decrypt an {@link EncryptedVault} bundle using `passphrase`.
 *
 * @throws If the passphrase is wrong or the data is corrupted.
 */
export function decryptVault(vault: EncryptedVault, passphrase: string): string {
  const salt = Buffer.from(vault.salt, 'hex');
  const iv = Buffer.from(vault.iv, 'hex');
  const authTag = Buffer.from(vault.authTag, 'hex');
  const ciphertext = Buffer.from(vault.ciphertext, 'base64');
  const key = deriveKey(passphrase, salt);

  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);

  try {
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
  } catch {
    throw new Error('Decryption failed – incorrect passphrase or corrupted data.');
  }
}
