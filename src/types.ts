export type Env = {
  Bindings: {
    RATE_LIMIT: KVNamespace;
    WEBHOOK_KV: KVNamespace;
    WEBHOOK_LISTENER: DurableObjectNamespace;
    ALLOWED_ORIGINS: string;
    FIREBLOCKS_API_KEY: string;
    FIREBLOCKS_SECRET_KEY: string;
    FIREBLOCKS_VAULT_ID: string;
    COSIGNER_API_KEY: string;
  };
};

export interface SessionData {
  hookIds: string[];
  handlerIds?: string[];
  createdAt: string;
}

export interface TxIdSessionData {
  privateKeyHex: string;
  publicKeyHex: string;
  createdAt: string;
}
