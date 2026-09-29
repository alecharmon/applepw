import {NativeRelay} from "./relay.js";

// A popup cannot own the helper: it disappears on blur. Open a persistent tab.
if (location.search !== "?tab") {
  chrome.tabs.create({url: chrome.runtime.getURL("bridge.html?tab")});
  window.close();
}

const form = document.getElementById("connect-form");
const status = document.getElementById("status");
let socket;
let nativePort;
let heartbeat;
let retry;
let enabled = false;
let settings;

function disconnect() {
  clearInterval(heartbeat);
  const port = nativePort;
  nativePort = undefined;
  if (port) port.disconnect();
  const ws = socket;
  socket = undefined;
  if (ws) ws.close();
}

function connect() {
  disconnect();
  const ws = new WebSocket(`ws://127.0.0.1:${settings.port}`);
  socket = ws;
  status.textContent = "Connecting to local CLI…";
  ws.onopen = () => ws.send(JSON.stringify({type: "authenticate", token: settings.token}));
  let relay;
  let nativeError;
  ws.onmessage = (event) => {
    let message;
    try { message = JSON.parse(event.data); } catch { ws.close(); return; }
    if (message.type === "ready" && !relay) {
      const port = chrome.runtime.connectNative("com.applepw.browser_bridge");
      nativePort = port;
      relay = new NativeRelay(port,
        (reply) => { if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(reply)); },
        () => {
          if (nativePort !== port || socket !== ws) return;
          // Consume the browser error without logging protocol messages.
          void chrome.runtime.lastError;
          enabled = false;
          nativeError = "Apple helper disconnected. Check browser setup, then click Connect and authenticate again.";
          status.textContent = nativeError;
          ws.close();
        });
      status.textContent = "Connected. Open Raycast Search Passwords or run applepw auth.";
      heartbeat = setInterval(() => {
        if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({type: "heartbeat"}));
      }, 20000);
    } else if (message.type === "request" && relay) {
      relay.request(message);
    }
  };
  ws.onclose = (event) => {
    if (socket !== ws) return;
    disconnect();
    if (event.code === 1008) {
      enabled = false;
      status.textContent = "Pairing token rejected. Check the token from applepw bridge setup.";
    } else {
      status.textContent = nativeError || "Disconnected. Start the CLI or Raycast Search Passwords; waiting to reconnect…";
    }
    if (enabled) retry = setTimeout(connect, 1000);
  };
  ws.onerror = () => { /* onclose handles reconnect without exposing messages */ };
}

form.addEventListener("submit", (event) => {
  event.preventDefault();
  const port = Number(document.getElementById("port").value);
  const token = document.getElementById("token").value.trim();
  if (!Number.isInteger(port) || port < 1 || port > 65535 || !/^[a-f0-9]{64}$/.test(token)) {
    status.textContent = "Enter a valid port and the 64-character pairing token.";
    return;
  }
  settings = {port, token}; // Memory only; closing this tab forgets the token.
  enabled = true;
  clearTimeout(retry);
  connect();
});

document.getElementById("disconnect").addEventListener("click", () => {
  enabled = false;
  clearTimeout(retry);
  disconnect();
  status.textContent = "Disconnected";
});
window.addEventListener("pagehide", () => { enabled = false; disconnect(); });
