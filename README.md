# webmcp-id

> **Patent Pending** -- Non-Custodial Multi-Chain Financial Infrastructure System for Autonomous AI Agents (USPTO Provisional, filed March 2026)

W3C DID-based agent identity for AI agents. Standards-compliant identity, verifiable credentials, and DNS-based discovery. No blockchain required.

Part of the [WebMCP](https://github.com/up2itnow0822) ecosystem -- the standards-based layer for AI agent commerce.

## Why webmcp-id?

AI agents need identity before they can transact. Today, agents are anonymous processes with API keys. webmcp-id gives every agent a verifiable, standards-compliant identity that works with Google A2A, enterprise IAM, and the open web.

- **W3C DID:web** -- Decentralized identifiers resolved via DNS (no blockchain)
- **Verifiable Credentials** -- Cryptographic proofs of agent authorization and capabilities
- **NAIS 1.1 Discovery** -- `/.well-known/agent.json` for agent-to-agent discovery
- **A2A AgentCard** -- Direct conversion to Google A2A format
- **Ed25519 Signing** -- Audited cryptographic signatures via @noble/ed25519
- **Zero blockchain dependency** -- Pure web standards

## Install

```bash
npm install webmcp-id
```

## Quick Start

```typescript
import { WebMCPIdentity } from 'webmcp-id';

// Create an agent identity
const identity = new WebMCPIdentity({
  domain: 'myagent.example.com',
  name: 'Trading Analysis Agent',
  capabilities: ['market-data', 'portfolio-analysis'],
  paymentMethods: ['x402', 'stripe-mpp'],
  operator: 'Acme Corp',
  contact: 'ops@acme.com',
});

// Get DID
console.log(identity.getDID());
// 'did:web:myagent.example.com'

// Get DID Document (host at /.well-known/did.json)
const didDoc = identity.getDIDDocument();

// Issue authorization credential
const { credential, jwt } = await identity.issueCredential({
  type: 'AgentAuthorizationCredential',
  subject: identity.getDID(),
  claims: {
    maxSpend: 1000.00,
    allowedActions: ['read-api', 'pay-api'],
    expiresAt: '2026-12-31T00:00:00Z',
  },
});

// Get NAIS 1.1 manifest (serve at /.well-known/agent.json)
const manifest = identity.getManifest();

// Convert to Google A2A AgentCard
const agentCard = identity.toA2AAgentCard();

// Verify another agent
const result = await identity.verify('did:web:other-agent.example.com');
if (result.valid) {
  console.log('Verified:', result.capabilities);
}
```

## API Reference

### WebMCPIdentity

The main entry point. Creates a complete agent identity with DID, credentials, manifest, and A2A support.

```typescript
new WebMCPIdentity(config: IdentityConfig, privateKeyHex?: string)
```

**Config:**
- `domain` -- Domain for did:web (e.g., 'myagent.example.com')
- `name` -- Agent display name
- `capabilities` -- Array of capability strings
- `paymentMethods` -- Supported payment protocols (e.g., ['x402', 'stripe-mpp'])
- `operator` -- Organization operating the agent
- `contact` -- Contact email
- `description` -- Agent description
- `version` -- Agent version

**Methods:**
| Method | Returns | Description |
|--------|---------|-------------|
| `getDID()` | `string` | DID identifier |
| `getDIDDocument()` | `DIDDocument` | Full W3C DID Document |
| `issueCredential(req)` | `{credential, jwt}` | Issue a Verifiable Credential |
| `verifyCredentialJWT(jwt, pubKey)` | `VerifiableCredential` | Verify a JWT-VC |
| `verifyCredentialProof(vc, pubKey)` | `boolean` | Verify a linked data proof |
| `getManifest()` | `AgentManifest` | NAIS 1.1 agent manifest |
| `manifestMiddleware()` | Express middleware | Serve /.well-known/agent.json |
| `toA2AAgentCard()` | `A2AAgentCard` | Google A2A AgentCard format |
| `getTrustSignals()` | trust object | Extract spend limits from VCs |
| `verify(did)` | `VerificationResult` | Verify another agent's identity |
| `getPublicKeyHex()` | `string` | Public key for sharing |
| `exportPrivateKeyHex()` | `string` | Private key for persistence |

### CredentialIssuer

Issues and verifies W3C Verifiable Credentials.

```typescript
const issuer = new CredentialIssuer(didWeb);
const { credential, jwt } = await issuer.issue({
  type: 'AgentAuthorizationCredential',
  subject: 'did:web:agent.example.com',
  claims: { maxSpend: 500, allowedActions: ['read-api'] }
});
```

### AgentManifestBuilder

Generates NAIS 1.1-compliant `/.well-known/agent.json` manifests.

```typescript
// Express middleware
app.use(identity.manifestMiddleware());
// Serves /.well-known/agent.json automatically
```

### A2AAdapter

Converts WebMCP identity to Google A2A AgentCard format.

```typescript
const card = identity.toA2AAgentCard();
// { name, skills, securitySchemes, provider, ... }
```

## Credential Types

### AgentAuthorizationCredential
Proves an agent is authorized to act within defined boundaries.
- `maxSpend` -- Maximum spending limit
- `currency` -- Currency code
- `allowedActions` -- Permitted action types
- `expiresAt` -- Authorization expiration

### AgentCapabilityCredential
Declares an agent's capabilities.
- `capabilities` -- Array of capability strings
- `version` -- Capability version
- `endpoints` -- Service endpoints

## Standards Compliance

| Standard | Version | Coverage |
|----------|---------|----------|
| W3C DID Core | 1.0 | did:web method, DID Documents |
| W3C Verifiable Credentials | 2.0 | JWT-VC + Linked Data Proofs |
| NAIS | 1.1 | /.well-known/agent.json discovery |
| Google A2A | AgentCard | Identity + capability mapping |
| Ed25519 | RFC 8032 | All signing operations |

## WebMCP Ecosystem

webmcp-id is part of the WebMCP standards-based agent infrastructure:

- **webmcp-sdk** -- W3C Web MCP toolkit (v0.5.6)
- **webmcp-id** -- Agent identity (this package)
- **webmcp-pay** -- Multi-rail payment execution (coming soon)

For crypto-native identity (ERC-8004, ERC-6551, on-chain), see [agentwallet-sdk](https://www.npmjs.com/package/agentwallet-sdk).

## Production Credentials

This package is part of the AI Agent Economy ecosystem:
- NVIDIA NeMo-Agent-Toolkit-Examples [PR #17 merged](https://github.com/NVIDIA/NeMo-Agent-Toolkit-Examples/pull/17) -- x402 payment tool in official NVIDIA catalog
- USPTO Patent Pending (March 2026) -- covers identity binding, payment execution, and MCP integration

## License

MIT
