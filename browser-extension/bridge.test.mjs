import {test} from "node:test";
import assert from "node:assert/strict";

test("a user reconnect or daemon restart cleans up the old helper without disabling retries", async () => {
  const handlers = new Map();
  const elements = new Map(["connect-form", "status", "port", "token", "disconnect"].map((id) => [id, {
    value: id === "port" ? "32145" : "a".repeat(64),
    addEventListener: (name, fn) => handlers.set(`${id}:${name}`, fn),
  }]));
  const sockets = [], ports = [], retries = [];
  const globals = ["location", "chrome", "document", "window", "WebSocket", "setTimeout", "clearTimeout", "setInterval", "clearInterval"];
  const saved = new Map(globals.map((name) => [name, globalThis[name]]));
  class FakeSocket {
    static OPEN = 1;
    readyState = 1;
    constructor() { sockets.push(this); }
    send() {}
    close() { this.readyState = 3; }
  }
  try {
    globalThis.location = {search: "?tab"};
    globalThis.document = {getElementById: (id) => elements.get(id)};
    globalThis.window = {addEventListener() {}};
    globalThis.WebSocket = FakeSocket;
    globalThis.chrome = {runtime: {connectNative() {
      const port = {onMessage: {addListener() {}}, onDisconnect: {addListener(fn) { port.closed = fn; }},
        disconnect() { port.closed(); }, postMessage() {}};
      ports.push(port);
      return port;
    }}};
    globalThis.setInterval = () => 1;
    globalThis.clearInterval = () => {};
    globalThis.setTimeout = (fn) => { retries.push(fn); return retries.length; };
    globalThis.clearTimeout = () => {};
    await import("./bridge.js");
    const submit = () => handlers.get("connect-form:submit")({preventDefault() {}});
    const ready = (ws) => ws.onmessage({data: '{"type":"ready"}'});
    submit();
    ready(sockets[0]);
    submit(); // Deliberately replaces the old native port.
    ready(sockets[1]);
    assert.equal(ports.length, 2);
    sockets[1].onclose({code: 1006}); // Daemon stopped; the tab should retry.
    assert.equal(retries.length, 1);
    retries[0]();
    assert.equal(sockets.length, 3);
    ready(sockets[2]);
    sockets[2].onclose({code: 1008}); // Wrong pairing token must stop retries.
    assert.equal(retries.length, 1);
    assert.match(elements.get("status").textContent, /token rejected/);
  } finally {
    for (const [name, value] of saved) {
      if (value === undefined) delete globalThis[name];
      else globalThis[name] = value;
    }
  }
});
