import { describe, it, expect } from 'vitest';
import {
  WebMCPIdentity,
  AgentKeyPair,
  DIDWeb,
  CredentialIssuer,
  AgentManifestBuilder,
  A2AAdapter,
} from '../src/index.js';

describe('AgentKeyPair', () => {
  it('generates a valid key pair', () => {
    const kp = new AgentKeyPair();
    expect(kp.publicKey).toBeInstanceOf(Uint8Array);
    expect(kp.publicKey.length).toBe(32);
  });

  it('signs and verifies messages', () => {
    const kp = new AgentKeyPair();
    const message = new TextEncoder().encode('hello agent');
    const sig = kp.sign(message);
    expect(AgentKeyPair.verify(sig, message, kp.publicKey)).toBe(true);
  });

  it('rejects invalid signatures', () => {
    const kp = new AgentKeyPair();
    const kp2 = new AgentKeyPair();
    const message = new TextEncoder().encode('hello');
    const sig = kp.sign(message);
    expect(AgentKeyPair.verify(sig, message, kp2.publicKey)).toBe(false);
  });

  it('exports and imports from hex', () => {
    const kp = new AgentKeyPair();
    const hex = kp.exportPrivateKeyHex();
    const restored = AgentKeyPair.fromHex(hex);
    expect(restored.exportPublicKeyHex()).toBe(kp.exportPublicKeyHex());
  });

  it('exports multibase public key', () => {
    const kp = new AgentKeyPair();
    const mb = kp.exportPublicKeyMultibase();
    expect(mb.startsWith('z')).toBe(true);
    expect(mb.length).toBeGreaterThan(40);
  });
});

describe('DIDWeb', () => {
  it('generates correct DID identifier', () => {
    const kp = new AgentKeyPair();
    const dw = new DIDWeb('agent.example.com', kp);
    expect(dw.getDID()).toBe('did:web:agent.example.com');
  });

  it('generates a valid DID document', () => {
    const kp = new AgentKeyPair();
    const dw = new DIDWeb('agent.example.com', kp);
    const doc = dw.generateDocument();

    expect(doc['@context']).toContain('https://www.w3.org/ns/did/v1');
    expect(doc.id).toBe('did:web:agent.example.com');
    expect(doc.verificationMethod).toHaveLength(1);
    expect(doc.verificationMethod[0].type).toBe('Ed25519VerificationKey2020');
    expect(doc.authentication).toContain('did:web:agent.example.com#key-1');
    expect(doc.assertionMethod).toContain('did:web:agent.example.com#key-1');
  });

  it('includes services when provided', () => {
    const kp = new AgentKeyPair();
    const dw = new DIDWeb('agent.example.com', kp);
    const doc = dw.generateDocument([
      { id: '#pay', type: 'PaymentService', serviceEndpoint: 'https://pay.example.com' },
    ]);
    expect(doc.service).toHaveLength(1);
    expect(doc.service![0].type).toBe('PaymentService');
  });

  it('returns correct resolution URL', () => {
    const kp = new AgentKeyPair();
    const dw = new DIDWeb('my.agent.com', kp);
    expect(dw.getResolutionURL()).toBe('https://my.agent.com/.well-known/did.json');
  });
});

describe('CredentialIssuer', () => {
  it('issues an AgentAuthorizationCredential', async () => {
    const kp = new AgentKeyPair();
    const dw = new DIDWeb('issuer.example.com', kp);
    const issuer = new CredentialIssuer(dw);

    const { credential, jwt } = await issuer.issue({
      type: 'AgentAuthorizationCredential',
      subject: 'did:web:agent.example.com',
      claims: {
        maxSpend: 1000,
        allowedActions: ['read-api', 'pay-api'],
        expiresAt: '2027-01-01T00:00:00Z',
      },
    });

    expect(credential.type).toContain('AgentAuthorizationCredential');
    expect(credential.issuer).toBe('did:web:issuer.example.com');
    expect(credential.credentialSubject.id).toBe('did:web:agent.example.com');
    expect(credential.credentialSubject.maxSpend).toBe(1000);
    expect(credential.proof).toBeDefined();
    expect(credential.proof!.type).toBe('Ed25519Signature2020');
    expect(jwt).toBeTruthy();
    expect(jwt.split('.')).toHaveLength(3);
  });

  it('issues an AgentCapabilityCredential', async () => {
    const kp = new AgentKeyPair();
    const dw = new DIDWeb('issuer.example.com', kp);
    const issuer = new CredentialIssuer(dw);

    const { credential } = await issuer.issue({
      type: 'AgentCapabilityCredential',
      subject: 'did:web:worker.example.com',
      claims: {
        capabilities: ['market-data', 'trading'],
        version: '2.0',
      },
    });

    expect(credential.type).toContain('AgentCapabilityCredential');
    expect(credential.credentialSubject.capabilities).toEqual(['market-data', 'trading']);
  });

  it('verifies linked data proofs', async () => {
    const kp = new AgentKeyPair();
    const dw = new DIDWeb('issuer.example.com', kp);
    const issuer = new CredentialIssuer(dw);

    const { credential } = await issuer.issue({
      type: 'AgentAuthorizationCredential',
      subject: 'did:web:agent.example.com',
      claims: { maxSpend: 500 },
    });

    expect(issuer.verifyProof(credential, kp.publicKey)).toBe(true);
  });

  it('rejects proofs with wrong key', async () => {
    const kp = new AgentKeyPair();
    const kp2 = new AgentKeyPair();
    const dw = new DIDWeb('issuer.example.com', kp);
    const issuer = new CredentialIssuer(dw);

    const { credential } = await issuer.issue({
      type: 'AgentAuthorizationCredential',
      subject: 'did:web:agent.example.com',
      claims: { maxSpend: 500 },
    });

    expect(issuer.verifyProof(credential, kp2.publicKey)).toBe(false);
  });

  it('verifies JWT credentials', async () => {
    const kp = new AgentKeyPair();
    const dw = new DIDWeb('issuer.example.com', kp);
    const issuer = new CredentialIssuer(dw);

    const { jwt } = await issuer.issue({
      type: 'AgentAuthorizationCredential',
      subject: 'did:web:agent.example.com',
      claims: { maxSpend: 250, expiresAt: '2030-01-01T00:00:00Z' },
    });

    const verified = await issuer.verifyJWT(jwt, kp.publicKey);
    expect(verified.credentialSubject.maxSpend).toBe(250);
  });
});

describe('AgentManifestBuilder', () => {
  it('generates NAIS 1.1-compliant manifest', () => {
    const kp = new AgentKeyPair();
    const dw = new DIDWeb('agent.example.com', kp);
    const builder = new AgentManifestBuilder(
      {
        name: 'Test Agent',
        capabilities: ['data-analysis'],
        paymentMethods: ['x402', 'stripe-mpp'],
        operator: 'Acme',
      },
      dw
    );

    const json = builder.toJSON();
    expect(json['@context']).toBe('https://nais.id/v1.1');
    expect(json.name).toBe('Test Agent');
    expect(json.did).toBe('did:web:agent.example.com');
    expect(json.capabilities).toContain('data-analysis');
    expect(json.paymentMethods).toContain('x402');
    expect(json.operator).toBe('Acme');
  });

  it('creates middleware function', () => {
    const builder = new AgentManifestBuilder({
      name: 'Agent',
      capabilities: [],
    });
    const mw = builder.middleware();
    expect(typeof mw).toBe('function');
  });
});

describe('A2AAdapter', () => {
  it('converts identity to A2A AgentCard', () => {
    const kp = new AgentKeyPair();
    const dw = new DIDWeb('agent.example.com', kp);
    const manifest = new AgentManifestBuilder(
      {
        name: 'Trading Agent',
        capabilities: ['market-data', 'trading'],
        paymentMethods: ['x402'],
        operator: 'Acme Corp',
      },
      dw
    );

    const adapter = new A2AAdapter(dw, manifest);
    const card = adapter.toAgentCard();

    expect(card.name).toBe('Trading Agent');
    expect(card.url).toBe('https://agent.example.com');
    expect(card.provider?.organization).toBe('Acme Corp');
    expect(card.skills).toBeDefined();
    expect(card.skills!.length).toBeGreaterThanOrEqual(2);
    expect(card.securitySchemes).toHaveProperty('didAuth');
  });

  it('extracts trust signals from authorization credentials', async () => {
    const kp = new AgentKeyPair();
    const dw = new DIDWeb('issuer.example.com', kp);
    const manifest = new AgentManifestBuilder({ name: 'Agent', capabilities: [] }, dw);
    const issuer = new CredentialIssuer(dw);

    const { credential } = await issuer.issue({
      type: 'AgentAuthorizationCredential',
      subject: 'did:web:agent.example.com',
      claims: {
        maxSpend: 500,
        currency: 'USD',
        allowedActions: ['read-api'],
        expiresAt: '2027-01-01T00:00:00Z',
      },
    });

    const adapter = new A2AAdapter(dw, manifest, [credential]);
    const signals = adapter.getTrustSignals();

    expect(signals.maxSpend).toBe(500);
    expect(signals.currency).toBe('USD');
    expect(signals.allowedActions).toContain('read-api');
  });
});

describe('WebMCPIdentity (integration)', () => {
  it('creates a full identity with all components', async () => {
    const identity = new WebMCPIdentity({
      domain: 'myagent.example.com',
      name: 'My Trading Agent',
      capabilities: ['market-data', 'portfolio-analysis'],
      paymentMethods: ['x402', 'stripe-mpp'],
      operator: 'Acme Corp',
      contact: 'ops@acme.com',
    });

    // DID
    expect(identity.getDID()).toBe('did:web:myagent.example.com');

    // DID Document
    const doc = identity.getDIDDocument();
    expect(doc.id).toBe('did:web:myagent.example.com');
    expect(doc.verificationMethod).toHaveLength(1);
    expect(doc.service).toHaveLength(1);
    expect(doc.service![0].type).toBe('AgentPaymentService');

    // Issue credential
    const { credential, jwt } = await identity.issueCredential({
      type: 'AgentAuthorizationCredential',
      subject: identity.getDID(),
      claims: {
        maxSpend: 1000,
        allowedActions: ['read-api', 'pay-api'],
        expiresAt: '2027-01-01T00:00:00Z',
      },
    });
    expect(credential.type).toContain('AgentAuthorizationCredential');
    expect(jwt.split('.')).toHaveLength(3);

    // Verify proof
    const proofValid = identity.verifyCredentialProof(
      credential,
      identity.getPublicKey()
    );
    expect(proofValid).toBe(true);

    // Verify JWT
    const verified = await identity.verifyCredentialJWT(jwt, identity.getPublicKey());
    expect(verified.credentialSubject.maxSpend).toBe(1000);

    // Manifest
    const manifest = identity.getManifest();
    expect(manifest['@context']).toBe('https://nais.id/v1.1');
    expect(manifest.name).toBe('My Trading Agent');
    expect(manifest.did).toBe('did:web:myagent.example.com');

    // A2A AgentCard
    const card = identity.toA2AAgentCard();
    expect(card.name).toBe('My Trading Agent');
    expect(card.skills!.length).toBeGreaterThanOrEqual(2);

    // Trust signals
    const signals = identity.getTrustSignals();
    expect(signals.maxSpend).toBe(1000);

    // Key persistence
    const hex = identity.exportPrivateKeyHex();
    const restored = new WebMCPIdentity(
      {
        domain: 'myagent.example.com',
        name: 'My Trading Agent',
        capabilities: ['market-data'],
      },
      hex
    );
    expect(restored.getDID()).toBe(identity.getDID());
    expect(restored.getPublicKeyHex()).toBe(identity.getPublicKeyHex());
  });
});
