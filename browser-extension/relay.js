// No content scripts, external messages, plaintext credential handling, or logs.
// Apple's SRP messages pass through unchanged; the CLI owns authentication.
const ALLOWED_COMMANDS = new Set([2, 4, 5, 14, 16, 17]);
const EVENTS = new Set([8, 9, 10, 12, 15]);

export class NativeRelay {
  constructor(port, send, fail, timers = globalThis) {
    this.port = port;
    this.send = send;
    this.fail = fail;
    this.timers = timers;
    this.pending = null;
    this.closed = false;
    port.onMessage.addListener((message) => this.receive(message));
    port.onDisconnect.addListener(() => this.close());
  }

  request(envelope) {
    if (this.closed || envelope.type !== "request" || !Number.isSafeInteger(envelope.id) ||
        !ALLOWED_COMMANDS.has(envelope.payload?.cmd) || this.pending) {
      this.send({type: "response", id: envelope.id, error: "Invalid or concurrent helper request"});
      return;
    }
    this.pending = {id: envelope.id, cmd: envelope.payload.cmd};
    this.timeout = this.timers.setTimeout(() => {
      if (this.pending) {
        this.send({type: "response", id: this.pending.id, error: "Apple Passwords helper timed out"});
        this.port.disconnect();
        this.close();
      }
    }, 3500);
    try {
      this.port.postMessage(envelope.payload);
    } catch {
      this.close();
    }
  }

  receive(message) {
    // Native events are not replies, even if they arrive before a response.
    if (!this.pending || !message || typeof message !== "object" || EVENTS.has(message.cmd) || message.cmd !== this.pending.cmd) return;
    const id = this.pending.id;
    this.timers.clearTimeout(this.timeout);
    this.pending = null;
    this.send({type: "response", id, payload: message});
  }

  close() {
    if (this.closed) return;
    this.closed = true;
    this.timers.clearTimeout(this.timeout);
    this.pending = null;
    this.fail();
  }
}
