import {test} from "node:test";
import assert from "node:assert/strict";
import {createHash} from "node:crypto";
import {readFileSync} from "node:fs";
import {NativeRelay} from "./relay.js";

function fixture() {
  const sent = [], native = [];
  let receive, close, timeout, failed = false;
  const port = {
    onMessage: {addListener: (fn) => { receive = fn; }},
    onDisconnect: {addListener: (fn) => { close = fn; }},
    postMessage: (msg) => native.push(msg),
    disconnect: () => close(),
  };
  const relay = new NativeRelay(port, (msg) => sent.push(msg), () => { failed = true; }, {
    setTimeout: (fn) => { timeout = fn; return 1; },
    clearTimeout: () => {},
  });
  return {relay, port, sent, native, receive: (msg) => receive(msg),
    timeout: () => timeout(), failed: () => failed};
}

test("packaged public key matches the native host and websocket allowlist", () => {
  const manifest = JSON.parse(readFileSync(new URL("manifest.json", import.meta.url)));
  const id = createHash("sha256").update(Buffer.from(manifest.key, "base64")).digest("hex").slice(0, 32)
    .replace(/[0-9a-f]/g, (digit) => String.fromCharCode(97 + parseInt(digit, 16)));
  assert.equal(id, "ocnafaklbiicdcplipchkaekhbdkkgpa");
  assert.deepEqual(manifest.permissions, ["nativeMessaging"]);
  assert.equal(manifest.content_scripts, undefined);
  assert.equal(manifest.externally_connectable, undefined);
});

test("preserves handshake and encrypted envelopes verbatim", () => {
  for (const cmd of [2, 4, 5, 14, 16, 17]) {
    const f = fixture();
    const payload = {cmd, msg: {PAKE: "opaque-handshake", SMSG: "opaque-ciphertext"}};
    f.relay.request({type: "request", id: 7, payload});
    assert.equal(f.native[0], payload);
    const response = {cmd, payload: {SMSG: "opaque-reply"}};
    f.receive(response);
    assert.deepEqual(f.sent, [{type: "response", id: 7, payload: response}]);
  }
});

test("unsolicited events and mismatched commands never consume a pending reply", () => {
  const f = fixture();
  f.relay.request({type: "request", id: 1, payload: {cmd: 14}});
  for (const cmd of [8, 9, 10, 12, 15, 2]) f.receive({cmd});
  assert.equal(f.sent.length, 0);
  f.receive({cmd: 14});
  assert.equal(f.sent[0].id, 1);
});

test("does not forward credential mutations or arbitrary native commands", () => {
  for (const cmd of [0, 6, 7, 1984]) {
    const f = fixture();
    f.relay.request({type: "request", id: 1, payload: {cmd}});
    assert.equal(f.native.length, 0);
    assert.ok(f.sent[0].error);
  }
});

test("rejects concurrent requests and preserves the first response", () => {
  const f = fixture();
  f.relay.request({type: "request", id: 1, payload: {cmd: 2}});
  f.relay.request({type: "request", id: 2, payload: {cmd: 2}});
  assert.equal(f.native.length, 1);
  assert.ok(f.sent[0].error);
  f.receive({cmd: 2});
  assert.equal(f.sent[1].id, 1);
});

test("timeout closes the helper so late responses cannot satisfy new requests", () => {
  const f = fixture();
  f.relay.request({type: "request", id: 1, payload: {cmd: 2}});
  f.timeout();
  assert.ok(f.failed());
  assert.ok(f.sent[0].error);
  f.receive({cmd: 2});
  assert.equal(f.sent.length, 1);
});

test("a native transport failure closes the bridge", () => {
  const f = fixture();
  f.port.postMessage = () => { throw new Error("test disconnect"); };
  f.relay.request({type: "request", id: 1, payload: {cmd: 14}});
  assert.ok(f.failed());
});
