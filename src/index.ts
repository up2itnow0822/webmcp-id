// webmcp-id — W3C DID-based agent identity for AI agents
// Patent Pending — USPTO Provisional, filed March 2026

export { WebMCPIdentity } from './identity.js';
export { CredentialIssuer } from './credentials.js';
export { AgentManifestBuilder } from './manifest.js';
export { A2AAdapter } from './a2a-adapter.js';
export { DIDWeb } from './did.js';
export { AgentKeyPair } from './crypto.js';

export type {
  DIDDocument,
  VerificationMethod,
  VerifiableCredential,
  AgentAuthorizationClaims,
  AgentCapabilityClaims,
  CredentialClaims,
  CredentialRequest,
  AgentManifestData,
  AgentManifest,
  A2AAgentCard,
  VerificationResult,
  IdentityConfig,
} from './types.js';
