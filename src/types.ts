export type Env = {
  Bindings: {
    RATE_LIMIT: KVNamespace;
    WEBHOOK_KV: KVNamespace;
    WEBHOOK_LISTENER: DurableObjectNamespace;
    ALLOWED_ORIGINS: string;
    FIREBLOCKS_API_KEY: string;
    FIREBLOCKS_SECRET_KEY: string;
    FIREBLOCKS_VAULT_ID: string;
  };
};
