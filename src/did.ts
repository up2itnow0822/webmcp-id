import { AgentKeyPair } from './crypto.js';
import type { DIDDocument, VerificationMethod } from './types.js';

/**
 * DID:web resolution and document generation per W3C DID Core 1.0.
 * did:web identifiers resolve via HTTPS to a DID document at
 * https://<domain>/.well-known/did.json
 */
export class DIDWeb {
  private domain: string;
  private keyPair: AgentKeyPair;

  constructor(domain: string, keyPair: AgentKeyPair) {
    this.domain = domain;
    this.keyPair = keyPair;
  }

  /** Get the DID identifier string */
  getDID(): string {
    return `did:web:${this.domain}`;
  }

  /** Generate the full DID Document */
  generateDocument(services?: Array<{ id: string; type: string; serviceEndpoint: string }>): DIDDocument {
    const did = this.getDID();
    const verificationMethodId = `${did}#key-1`;

    const verificationMethod: VerificationMethod = {
      id: verificationMethodId,
      type: 'Ed25519VerificationKey2020',
      controller: did,
      publicKeyMultibase: this.keyPair.exportPublicKeyMultibase(),
    };

    return {
      '@context': [
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/suites/ed25519-2020/v1',
      ],
      id: did,
      verificationMethod: [verificationMethod],
      authentication: [verificationMethodId],
      assertionMethod: [verificationMethodId],
      service: services,
    };
  }

  /**
   * Resolve a did:web identifier to its DID Document.
   * Fetches https://<domain>/.well-known/did.json
   */
  static async resolve(did: string): Promise<DIDDocument | null> {
    if (!did.startsWith('did:web:')) {
      throw new Error(`Invalid did:web identifier: ${did}`);
    }

    const domain = did.slice('did:web:'.length).replace(/:/g, '/');
    const url = `https://${domain}/.well-known/did.json`;

    try {
      const response = await fetch(url, {
        headers: { Accept: 'application/did+json, application/json' },
        signal: AbortSignal.timeout(10_000),
      });

      if (!response.ok) return null;

      const document = await response.json();
      return document as DIDDocument;
    } catch {
      return null;
    }
  }

  /** Get the resolution URL for this DID */
  getResolutionURL(): string {
    return `https://${this.domain}/.well-known/did.json`;
  }

  /** Get the key pair */
  getKeyPair(): AgentKeyPair {
    return this.keyPair;
  }
}
