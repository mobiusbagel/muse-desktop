// Local Bridge — HTTP server. Always bound to loopback; when the user
// turns on remote access (settings bridgeRemoteAccess), it ADDITIONALLY
// binds the machine's Tailscale IPv4 (see bridgeNetwork.js). It never
// binds a wildcard, LAN, or public address. Both listeners run the exact
// same request handler — there is no second code path for remote calls.
//
//   GET  /health   open; liveness + storage-move state
//   GET  /storage  requires X-Bridge-Token (Phase 2; was open in Phase 1)
//   POST /rpc      requires X-Bridge-Token; JSON {method, params} tool calls,
//                  gated by permissions.json (see rpc.js)
//
// Responses: success { ok: true, result }, failure { ok: false,
// error: { code, message } }. HTTP status is 200 for tool-level outcomes,
// 400 for a malformed body, 401 for a missing/wrong token, 404 unknown path.
'use strict';

const http = require('http');
const { tokenMatches } = require('./bridgeAuth');

const BRIDGE_HOST = '127.0.0.1';
const BRIDGE_PORT = 47631;
const MAX_BODY_BYTES = 10 * 1024 * 1024; // 10 MB JSON body cap

function sendJson(res, status, obj) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(obj));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    req.on('data', (chunk) => {
      total += chunk.length;
      if (total > MAX_BODY_BYTES) {
        reject(Object.assign(new Error(`Request body exceeds ${MAX_BODY_BYTES} bytes`), { status: 413, code: 'payload_too_large' }));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

// The one and only request handler. Every listener (loopback, tailnet)
// serves this — auth, scope, permission, moving, and cap checks included.
function createBridgeHandler({ version, getStorageInfo, isMoving, getBridgeToken, handleRpc, onAuthFailure }) {
  const authorized = (req) =>
    typeof getBridgeToken === 'function' && tokenMatches(req.headers['x-bridge-token'], getBridgeToken());

  return async function bridgeHandler(req, res) {
    try {
      if (req.method === 'GET' && req.url === '/health') {
        // While an assistant-folder move is running, /health reports
        // storage: "moving" and fs tool calls refuse until it flips back.
        const moving = typeof isMoving === 'function' && isMoving();
        sendJson(res, 200, { app: 'Muse', version, bridge: 'live', storage: moving ? 'moving' : 'ok' });
        return;
      }

      if (req.method === 'GET' && req.url === '/storage' && getStorageInfo) {
        if (!authorized(req)) {
          sendJson(res, 401, { ok: false, error: { code: 'unauthorized', message: 'Missing or wrong X-Bridge-Token.' } });
          return;
        }
        try {
          sendJson(res, 200, getStorageInfo());
        } catch (err) {
          sendJson(res, 500, { ok: false, error: { code: 'storage_unavailable', message: err.message } });
        }
        return;
      }

      if (req.method === 'POST' && req.url === '/rpc' && typeof handleRpc === 'function') {
        if (!authorized(req)) {
          if (typeof onAuthFailure === 'function') {
            try {
              onAuthFailure();
            } catch {
              // Auditing an auth failure must never break the response.
            }
          }
          sendJson(res, 401, { ok: false, error: { code: 'unauthorized', message: 'Missing or wrong X-Bridge-Token.' } });
          return;
        }
        const raw = await readBody(req);
        let body;
        try {
          body = JSON.parse(raw);
        } catch {
          sendJson(res, 400, { ok: false, error: { code: 'bad_json', message: 'Request body is not valid JSON.' } });
          return;
        }
        if (!body || typeof body.method !== 'string') {
          sendJson(res, 400, { ok: false, error: { code: 'bad_request', message: 'Body must be {method, params}.' } });
          return;
        }
        try {
          const result = await handleRpc(body.method, body.params || {});
          sendJson(res, 200, { ok: true, result });
        } catch (err) {
          sendJson(res, 200, {
            ok: false,
            error: { code: err.code || 'tool_failed', message: err.message || String(err) },
          });
        }
        return;
      }

      sendJson(res, 404, { ok: false, error: { code: 'not_found', message: `No such route: ${req.method} ${req.url}` } });
    } catch (err) {
      const status = err.status || 500;
      sendJson(res, status, { ok: false, error: { code: err.code || 'internal', message: err.message } });
    }
  };
}

function wireServer(server, host, port, onListen) {
  server.on('error', (err) => {
    // EADDRINUSE etc. must not take the app down — the UI still works.
    console.error(`[bridge] error on ${host}:${port}:`, err.message);
  });
  server.listen(port, host, () => {
    const bound = server.address();
    console.log(`[bridge] listening on http://${bound.address}:${bound.port} (GET /health, GET /storage, POST /rpc)`);
    if (typeof onListen === 'function') onListen({ host, address: bound.address, port: bound.port });
  });
  return server;
}

function startBridge({ host = BRIDGE_HOST, port = BRIDGE_PORT, onListen, ...deps }) {
  const server = http.createServer(createBridgeHandler(deps));
  return wireServer(server, host, port, onListen);
}

// One server per host, all sharing a single handler instance. Returns a
// handle whose closeAll() closes every listener (dropping idle keep-alive
// sockets first) and resolves once all ports are released — main uses it
// to apply the remote-access setting live by rebinding.
function startBridgeSet({ hosts, port = BRIDGE_PORT, onListen, ...deps }) {
  const handler = createBridgeHandler(deps);
  const servers = hosts.map((host) => wireServer(http.createServer(handler), host, port, onListen));
  return {
    servers,
    closeAll() {
      return Promise.all(
        servers.map(
          (server) =>
            new Promise((resolve) => {
              if (!server.listening) return resolve();
              server.close(() => resolve());
              if (typeof server.closeIdleConnections === 'function') server.closeIdleConnections();
            }),
        ),
      );
    },
  };
}

module.exports = { startBridge, startBridgeSet, createBridgeHandler, BRIDGE_HOST, BRIDGE_PORT };
