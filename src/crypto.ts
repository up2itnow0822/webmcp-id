import * as ed from '@noble/ed25519';
import { createHash } from 'node:crypto';

// Configure noble to use Node's built-in sha512
ed.etc.sha512Sync = (...m: Uint8Array[]) => {
  const h = createHash('sha512');
  m.forEach((msg) => h.update(msg));
  return new Uint8Array(h.digest());
};

/**
 * Ed25519 key pair for agent identity signing.
 * Keys never leave the process boundary.
 */
export class AgentKeyPair {
  private privateKey: Uint8Array;
  public publicKey: Uint8Array;

  constructor(privateKey?: Uint8Array) {
    this.privateKey = privateKey ?? ed.utils.randomPrivateKey();
    this.publicKey = ed.getPublicKey(this.privateKey);
  }

  /** Sign a message and return the signature */
  sign(message: Uint8Array): Uint8Array {
    return ed.sign(message, this.privateKey);
  }

  /** Verify a signature against a public key */
  static verify(
    signature: Uint8Array,
    message: Uint8Array,
    publicKey: Uint8Array
  ): boolean {
    return ed.verify(signature, message, publicKey);
  }

  /** Export private key as hex */
  exportPrivateKeyHex(): string {
    return Buffer.from(this.privateKey).toString('hex');
  }

  /** Export public key as hex */
  exportPublicKeyHex(): string {
    return Buffer.from(this.publicKey).toString('hex');
  }

  /** Export public key as multibase (base58btc, 'z' prefix) for DID documents */
  exportPublicKeyMultibase(): string {
    // Multicodec prefix for Ed25519 public key: 0xed01
    const prefixed = new Uint8Array(2 + this.publicKey.length);
    prefixed[0] = 0xed;
    prefixed[1] = 0x01;
    prefixed.set(this.publicKey, 2);
    return 'z' + base58btcEncode(prefixed);
  }

  /** Create from hex private key */
  static fromHex(hex: string): AgentKeyPair {
    return new AgentKeyPair(Buffer.from(hex, 'hex'));
  }
}

// Base58btc encoding (Bitcoin alphabet)
const BASE58_ALPHABET =
  '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58btcEncode(bytes: Uint8Array): string {
  let num = BigInt(0);
  for (const byte of bytes) {
    num = num * 256n + BigInt(byte);
  }

  let encoded = '';
  while (num > 0n) {
    const remainder = Number(num % 58n);
    num = num / 58n;
    encoded = BASE58_ALPHABET[remainder] + encoded;
  }

  // Preserve leading zeros
  for (const byte of bytes) {
    if (byte === 0) {
      encoded = '1' + encoded;
    } else {
      break;
    }
  }

  return encoded;
}
