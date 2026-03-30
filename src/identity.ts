import { AgentKeyPair } from './crypto.js';
import { DIDWeb } from './did.js';
import { CredentialIssuer } from './credentials.js';
import { AgentManifestBuilder } from './manifest.js';
import { A2AAdapter } from './a2a-adapter.js';
import type {
  IdentityConfig,
  VerifiableCredential,
  CredentialRequest,
  VerificationResult,
  A2AAgentCard,
  AgentManifest,
  DIDDocument,
} from './types.js';

/**
 * WebMCPIdentity — the main entry point for agent identity.
 *
 * Creates a W3C DID:web identity, issues verifiable credentials,
 * serves NAIS 1.1 discovery manifests, and converts to A2A AgentCards.
 *
 * No blockchain required. Standards-compliant identity for web agents.
 */
export class WebMCPIdentity {
  private config: IdentityConfig;
  private keyPair: AgentKeyPair;
  private didWeb: DIDWeb;
  private issuer: CredentialIssuer;
  private manifestBuilder: AgentManifestBuilder;
  private a2aAdapter: A2AAdapter;
  private issuedCredentials: VerifiableCredential[] = [];

  constructor(config: IdentityConfig, privateKeyHex?: string) {
    this.config = config;
    this.keyPair = privateKeyHex
      ? AgentKeyPair.fromHex(privateKeyHex)
      : new AgentKeyPair();
    this.didWeb = new DIDWeb(config.domain, this.keyPair);
    this.issuer = new CredentialIssuer(this.didWeb);
    this.manifestBuilder = new AgentManifestBuilder(
      {
        name: config.name,
        capabilities: config.capabilities ?? [],
        paymentMethods: config.paymentMethods,
        operator: config.operator,
        contact: config.contact,
        description: config.description,
        version: config.version,
        did: this.didWeb.getDID(),
      },
      this.didWeb
    );
    this.a2aAdapter = new A2AAdapter(
      this.didWeb,
      this.manifestBuilder,
      this.issuedCredentials
    );
  }

  // ── DID ──

  /** Get the DID identifier */
  getDID(): string {
    return this.didWeb.getDID();
  }

  /** Get the full DID Document */
  getDIDDocument(): DIDDocument {
    const services = [];
    if (this.config.paymentMethods?.length) {
      services.push({
        id: `${this.getDID()}#payment`,
        type: 'AgentPaymentService',
        serviceEndpoint: `https://${this.config.domain}/api/pay`,
      });
    }
    return this.didWeb.generateDocument(services.length ? services : undefined);
  }

  /** Get the URL where this DID document should be hosted */
  getDIDResolutionURL(): string {
    return this.didWeb.getResolutionURL();
  }

  // ── Credentials ──

  /** Issue a verifiable credential */
  async issueCredential(request: CredentialRequest): Promise<{
    credential: VerifiableCredential;
    jwt: string;
  }> {
    const result = await this.issuer.issue(request);
    this.issuedCredentials.push(result.credential);
    this.a2aAdapter.addCredential(result.credential);
    return result;
  }

  /** Verify a JWT credential */
  async verifyCredentialJWT(
    jwt: string,
    issuerPublicKey: Uint8Array
  ): Promise<VerifiableCredential> {
    return this.issuer.verifyJWT(jwt, issuerPublicKey);
  }

  /** Verify a credential's linked data proof */
  verifyCredentialProof(
    credential: VerifiableCredential,
    issuerPublicKey: Uint8Array
  ): boolean {
    return this.issuer.verifyProof(credential, issuerPublicKey);
  }

  // ── Manifest (NAIS 1.1) ──

  /** Get the agent manifest JSON */
  getManifest(): AgentManifest {
    return this.manifestBuilder.toJSON();
  }

  /** Get Express middleware for serving /.well-known/agent.json */
  manifestMiddleware() {
    return this.manifestBuilder.middleware();
  }

  // ── A2A AgentCard ──

  /** Convert to Google A2A AgentCard format */
  toA2AAgentCard(): A2AAgentCard {
    return this.a2aAdapter.toAgentCard();
  }

  /** Get trust signals extracted from issued credentials */
  getTrustSignals() {
    return this.a2aAdapter.getTrustSignals();
  }

  // ── Verification ──

  /**
   * Verify another agent's identity by resolving their DID
   * and checking their credentials.
   */
  async verify(did: string): Promise<VerificationResult> {
    const errors: string[] = [];

    // Resolve DID document
    const document = await DIDWeb.resolve(did);
    if (!document) {
      return {
        valid: false,
        did,
        credentials: [],
        capabilities: [],
        errors: [`Could not resolve DID document for ${did}`],
      };
    }

    // Extract public key from DID document
    const verificationMethod = document.verificationMethod?.[0];
    if (!verificationMethod) {
      return {
        valid: false,
        did,
        document,
        credentials: [],
        capabilities: [],
        errors: ['No verification method found in DID document'],
      };
    }

    // Resolve agent manifest for capabilities
    const domain = did.replace('did:web:', '').replace(/:/g, '/');
    const manifest = await AgentManifestBuilder.resolve(domain);
    const capabilities = manifest?.capabilities ?? [];

    return {
      valid: true,
      did,
      document,
      credentials: [],
      capabilities,
      errors,
    };
  }

  // ── Key Export ──

  /** Export public key as hex (for sharing with other agents) */
  getPublicKeyHex(): string {
    return this.keyPair.exportPublicKeyHex();
  }

  /** Export public key as raw bytes */
  getPublicKey(): Uint8Array {
    return this.keyPair.publicKey;
  }

  /** Export private key hex (for persistence — handle securely!) */
  exportPrivateKeyHex(): string {
    return this.keyPair.exportPrivateKeyHex();
  }
}
