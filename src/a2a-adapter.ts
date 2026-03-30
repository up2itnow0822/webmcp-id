import type { A2AAgentCard, VerifiableCredential } from './types.js';
import type { DIDWeb } from './did.js';
import type { AgentManifestBuilder } from './manifest.js';

/**
 * Converts WebMCP Identity into Google A2A AgentCard format.
 * Bridges W3C DID-based identity with Google's agent discovery protocol.
 */
export class A2AAdapter {
  private didWeb: DIDWeb;
  private manifest: AgentManifestBuilder;
  private credentials: VerifiableCredential[];

  constructor(
    didWeb: DIDWeb,
    manifest: AgentManifestBuilder,
    credentials: VerifiableCredential[] = []
  ) {
    this.didWeb = didWeb;
    this.manifest = manifest;
    this.credentials = credentials;
  }

  /**
   * Convert identity + manifest + credentials to A2A AgentCard.
   * Maps W3C standards to Google's discovery format.
   */
  toAgentCard(): A2AAgentCard {
    const manifestData = this.manifest.toJSON();
    const did = this.didWeb.getDID();

    const card: A2AAgentCard = {
      name: manifestData.name,
      description: manifestData.description,
      url: `https://${did.replace('did:web:', '')}`,
      version: manifestData.version,
      provider: manifestData.operator
        ? {
            organization: manifestData.operator,
            url: manifestData.contact
              ? `mailto:${manifestData.contact}`
              : undefined,
          }
        : undefined,
      capabilities: {
        streaming: false,
        pushNotifications: false,
      },
      defaultInputModes: ['application/json'],
      defaultOutputModes: ['application/json'],
      skills: manifestData.capabilities.map((cap, i) => ({
        id: `skill-${i}`,
        name: cap,
        description: `Agent capability: ${cap}`,
        tags: [cap],
      })),
      securitySchemes: {
        didAuth: {
          type: 'http',
          scheme: 'bearer',
          description: `DID Authentication: ${did}`,
        },
      },
      security: [{ didAuth: [] }],
    };

    // Add payment methods as skills if present
    if (manifestData.paymentMethods?.length) {
      for (const method of manifestData.paymentMethods) {
        card.skills!.push({
          id: `payment-${method}`,
          name: `payment-${method}`,
          description: `Payment via ${method}`,
          tags: ['payment', method],
        });
      }
    }

    return card;
  }

  /** Add credentials for richer AgentCard metadata */
  addCredential(credential: VerifiableCredential): void {
    this.credentials.push(credential);
  }

  /**
   * Extract authorization limits from credentials for A2A trust signals.
   * Returns spending limits, allowed actions, and expiration from VCs.
   */
  getTrustSignals(): {
    maxSpend?: number;
    currency?: string;
    allowedActions?: string[];
    expiresAt?: string;
  } {
    const signals: {
      maxSpend?: number;
      currency?: string;
      allowedActions?: string[];
      expiresAt?: string;
    } = {};

    for (const vc of this.credentials) {
      if (vc.type.includes('AgentAuthorizationCredential')) {
        const subject = vc.credentialSubject;
        if (subject.maxSpend) signals.maxSpend = subject.maxSpend as number;
        if (subject.currency) signals.currency = subject.currency as string;
        if (subject.allowedActions)
          signals.allowedActions = subject.allowedActions as string[];
        if (vc.expirationDate) signals.expiresAt = vc.expirationDate;
      }
    }

    return signals;
  }
}
