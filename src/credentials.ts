import { SignJWT, jwtVerify, importJWK, exportJWK, type JWK } from 'jose';
import { AgentKeyPair } from './crypto.js';
import { DIDWeb } from './did.js';
import type {
  VerifiableCredential,
  CredentialRequest,
  CredentialClaims,
} from './types.js';

/**
 * Issues W3C Verifiable Credentials (VC Data Model 2.0) for agent authorization.
 * Supports JWT-VC format for maximum interoperability.
 */
export class CredentialIssuer {
  private didWeb: DIDWeb;
  private keyPair: AgentKeyPair;

  constructor(didWeb: DIDWeb) {
    this.didWeb = didWeb;
    this.keyPair = didWeb.getKeyPair();
  }

  /**
   * Issue a Verifiable Credential.
   * Returns both the VC object and its JWT representation.
   */
  async issue(request: CredentialRequest): Promise<{
    credential: VerifiableCredential;
    jwt: string;
  }> {
    const now = new Date();
    const issuerDID = this.didWeb.getDID();
    const verificationMethodId = `${issuerDID}#key-1`;

    // Build the VC payload
    const credential: VerifiableCredential = {
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        'https://www.w3.org/2018/credentials/examples/v1',
      ],
      type: ['VerifiableCredential', request.type],
      issuer: issuerDID,
      issuanceDate: now.toISOString(),
      credentialSubject: {
        id: request.subject,
        ...request.claims,
      },
    };

    // Add expiration if specified in claims
    const claims = request.claims as Record<string, unknown>;
    if (claims.expiresAt) {
      credential.expirationDate = claims.expiresAt as string;
    }

    // Build JWT-VC using Ed25519 (OKP key type)
    const privateKeyJWK = await this.buildEdDSAJWK();

    const jwt = await new SignJWT({
      vc: credential,
      sub: request.subject,
      iss: issuerDID,
    })
      .setProtectedHeader({
        alg: 'EdDSA',
        typ: 'JWT',
        kid: verificationMethodId,
      })
      .setIssuedAt()
      .setIssuer(issuerDID)
      .setSubject(request.subject)
      .sign(await importJWK(privateKeyJWK, 'EdDSA'));

    // Add linked data proof to the credential object
    const signature = this.keyPair.sign(
      new TextEncoder().encode(JSON.stringify(credential))
    );

    credential.proof = {
      type: 'Ed25519Signature2020',
      created: now.toISOString(),
      verificationMethod: verificationMethodId,
      proofPurpose: 'assertionMethod',
      proofValue: Buffer.from(signature).toString('base64url'),
    };

    return { credential, jwt };
  }

  /**
   * Verify a JWT-VC credential.
   * Returns the decoded VC if valid, throws on failure.
   */
  async verifyJWT(
    jwt: string,
    issuerPublicKey: Uint8Array
  ): Promise<VerifiableCredential> {
    const jwk = this.buildPublicEdDSAJWK(issuerPublicKey);
    const key = await importJWK(jwk, 'EdDSA');

    const { payload } = await jwtVerify(jwt, key, {
      algorithms: ['EdDSA'],
    });

    const vc = (payload as Record<string, unknown>).vc as VerifiableCredential;
    if (!vc) {
      throw new Error('JWT does not contain a vc claim');
    }

    // Check expiration
    if (vc.expirationDate) {
      const expiration = new Date(vc.expirationDate);
      if (expiration < new Date()) {
        throw new Error('Credential has expired');
      }
    }

    return vc;
  }

  /**
   * Verify a linked data proof on a credential.
   */
  verifyProof(
    credential: VerifiableCredential,
    issuerPublicKey: Uint8Array
  ): boolean {
    if (!credential.proof) return false;

    const proofValue = Buffer.from(credential.proof.proofValue, 'base64url');

    // Reconstruct the credential without proof for verification
    const { proof, ...credentialWithoutProof } = credential;
    const message = new TextEncoder().encode(
      JSON.stringify(credentialWithoutProof)
    );

    return AgentKeyPair.verify(proofValue, message, issuerPublicKey);
  }

  private async buildEdDSAJWK(): Promise<JWK> {
    const pubHex = this.keyPair.exportPublicKeyHex();
    const privHex = this.keyPair.exportPrivateKeyHex();

    return {
      kty: 'OKP',
      crv: 'Ed25519',
      x: Buffer.from(pubHex, 'hex').toString('base64url'),
      d: Buffer.from(privHex, 'hex').toString('base64url'),
    };
  }

  private buildPublicEdDSAJWK(publicKey: Uint8Array): JWK {
    return {
      kty: 'OKP',
      crv: 'Ed25519',
      x: Buffer.from(publicKey).toString('base64url'),
    };
  }
}
