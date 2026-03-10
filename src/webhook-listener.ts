export class WebhookListener {
  private state: DurableObjectState;
  private env: { WEBHOOK_KV: KVNamespace };

  constructor(state: DurableObjectState, env: { WEBHOOK_KV: KVNamespace }) {
    this.state = state;
    this.env = env;
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (request.headers.get("Upgrade") === "websocket") {
      const pair = new WebSocketPair();
      this.state.acceptWebSocket(pair[1]);

      const hookId = url.pathname.split("/").pop()!;
      const events =
        (await this.env.WEBHOOK_KV.get(`events:${hookId}`, "json")) || [];
      pair[1].send(JSON.stringify({ type: "history", events }));

      return new Response(null, { status: 101, webSocket: pair[0] });
    }

    const message = await request.json();
    for (const ws of this.state.getWebSockets()) {
      try {
        ws.send(JSON.stringify(message));
      } catch {}
    }
    return new Response("ok");
  }

  webSocketClose() {}
}
