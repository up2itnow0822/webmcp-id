import type { AgentManifestData, AgentManifest } from './types.js';
import type { DIDWeb } from './did.js';

/**
 * Agent Manifest — serves /.well-known/agent.json per NAIS 1.1 spec.
 * Enables DNS-based agent discovery without blockchain dependency.
 */
export class AgentManifestBuilder {
  private data: AgentManifestData;
  private didWeb?: DIDWeb;

  constructor(data: AgentManifestData, didWeb?: DIDWeb) {
    this.data = data;
    this.didWeb = didWeb;
  }

  /** Generate the NAIS 1.1-compliant manifest JSON */
  toJSON(): AgentManifest {
    return {
      '@context': 'https://nais.id/v1.1',
      name: this.data.name,
      version: this.data.version,
      description: this.data.description,
      did: this.didWeb?.getDID() ?? this.data.did,
      capabilities: this.data.capabilities,
      paymentMethods: this.data.paymentMethods,
      operator: this.data.operator,
      contact: this.data.contact,
      endpoints: this.data.endpoints,
      discoveredAt: new Date().toISOString(),
    };
  }

  /**
   * Express/Connect middleware that serves /.well-known/agent.json
   * Usage: app.use(manifest.middleware())
   */
  middleware() {
    const json = this.toJSON();
    return (req: { url?: string; path?: string }, res: { json: (data: unknown) => void; setHeader: (key: string, value: string) => void }, next: () => void) => {
      const path = req.path ?? req.url;
      if (path === '/.well-known/agent.json') {
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.json(json);
      } else {
        next();
      }
    };
  }

  /**
   * Resolve an agent manifest from a domain.
   * Fetches https://<domain>/.well-known/agent.json
   */
  static async resolve(domain: string): Promise<AgentManifest | null> {
    const url = `https://${domain}/.well-known/agent.json`;
    try {
      const response = await fetch(url, {
        headers: { Accept: 'application/json' },
        signal: AbortSignal.timeout(10_000),
      });
      if (!response.ok) return null;
      return (await response.json()) as AgentManifest;
    } catch {
      return null;
    }
  }

  /** Update manifest data */
  update(data: Partial<AgentManifestData>): void {
    Object.assign(this.data, data);
  }
}
