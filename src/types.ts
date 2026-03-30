import { z } from 'zod';

// ── DID Document Types ──

export const VerificationMethodSchema = z.object({
  id: z.string(),
  type: z.literal('Ed25519VerificationKey2020'),
  controller: z.string(),
  publicKeyMultibase: z.string(),
});

export const DIDDocumentSchema = z.object({
  '@context': z.array(z.string()),
  id: z.string(),
  verificationMethod: z.array(VerificationMethodSchema),
  authentication: z.array(z.string()),
  assertionMethod: z.array(z.string()),
  service: z.array(z.object({
    id: z.string(),
    type: z.string(),
    serviceEndpoint: z.string(),
  })).optional(),
});

export type VerificationMethod = z.infer<typeof VerificationMethodSchema>;
export type DIDDocument = z.infer<typeof DIDDocumentSchema>;

// ── Verifiable Credential Types ──

export interface VerifiableCredential {
  '@context': string[];
  type: string[];
  issuer: string;
  issuanceDate: string;
  expirationDate?: string;
  credentialSubject: {
    id: string;
    [key: string]: unknown;
  };
  proof?: {
    type: string;
    created: string;
    verificationMethod: string;
    proofPurpose: string;
    proofValue: string;
  };
}

export interface AgentAuthorizationClaims {
  maxSpend?: number;
  currency?: string;
  allowedActions?: string[];
  expiresAt?: string;
  issuedBy?: string;
}

export interface AgentCapabilityClaims {
  capabilities: string[];
  version?: string;
  endpoints?: Record<string, string>;
}

export type CredentialClaims = AgentAuthorizationClaims | AgentCapabilityClaims;

export interface CredentialRequest {
  type: 'AgentAuthorizationCredential' | 'AgentCapabilityCredential';
  subject: string;
  claims: CredentialClaims;
}

// ── Agent Manifest (NAIS 1.1) ──

export interface AgentManifestData {
  name: string;
  version?: string;
  description?: string;
  capabilities: string[];
  paymentMethods?: string[];
  operator?: string;
  contact?: string;
  did?: string;
  endpoints?: Record<string, string>;
}

export const AgentManifestSchema = z.object({
  '@context': z.literal('https://nais.id/v1.1'),
  name: z.string(),
  version: z.string().optional(),
  description: z.string().optional(),
  did: z.string().optional(),
  capabilities: z.array(z.string()),
  paymentMethods: z.array(z.string()).optional(),
  operator: z.string().optional(),
  contact: z.string().optional(),
  endpoints: z.record(z.string()).optional(),
  discoveredAt: z.string().optional(),
});

export type AgentManifest = z.infer<typeof AgentManifestSchema>;

// ── A2A AgentCard ──

export interface A2AAgentCard {
  name: string;
  description?: string;
  url?: string;
  provider?: { organization: string; url?: string };
  version?: string;
  capabilities?: {
    streaming?: boolean;
    pushNotifications?: boolean;
  };
  defaultInputModes?: string[];
  defaultOutputModes?: string[];
  skills?: Array<{
    id: string;
    name: string;
    description?: string;
    tags?: string[];
  }>;
  securitySchemes?: Record<string, unknown>;
  security?: Array<Record<string, string[]>>;
}

// ── Verification Result ──

export interface VerificationResult {
  valid: boolean;
  did: string;
  document?: DIDDocument;
  credentials: VerifiableCredential[];
  capabilities: string[];
  errors: string[];
}

// ── Identity Config ──

export interface IdentityConfig {
  domain: string;
  name: string;
  capabilities?: string[];
  paymentMethods?: string[];
  operator?: string;
  contact?: string;
  description?: string;
  version?: string;
}
