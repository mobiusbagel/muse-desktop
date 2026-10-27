// Test suite — plain Node, no framework, no Electron.
// Phase 2 coverage: the permission gate (allow / deny / ask-grant /
// ask-deny / ask-timeout / always-allow persistence), scope enforcement
// (outside paths, traversal, approvedFolders), the storage cap on
// fs.write, the moving-state refusal, the 1 MB fs.read cap, real
// process.kill, and bridge-level token auth over HTTP.
// 0.2.1 coverage: parent-location folder choice (destinationForParent,
// first-run creation helper), the move flow against computed
// <parent>/Muse destinations, and startup subfolder normalization.
// 0.2.4 coverage: adaptive byte/percent formatting (formatBytes) — small
// usage must never render as "0.00 GB".
// 0.3.0 coverage: Tailscale interface selection + bridge status strings
// (bridgeNetwork), and multiple listeners sharing one bridge handler.
// 0.3.1 coverage: the unbound-status reasons (adapter / process / binary
// probes), and the tasklist-text matcher in tailscaleProbe.
// 0.4.0 coverage: shell.run (policy coercion — a stored "allow" still
// prompts and always-allow can never persist; prompt payload carries
// the exact command and no always-allow path; the real runner's
// streams / exit codes / timeout + tree kill / output truncation; the
// moving-state refusal; the capped command in the audit log) and the
// Bridge Activity parser/formatter (bridgeActivity).
// 0.5.0 coverage: the in-app updater (updater.js) — semver compare,
// release-JSON parsing, checksum verify, the Authenticode signer
// fingerprint pinned to the real signing cert, fail-closed composition
// (either check failing blocks the offer and leaves an audit line),
// the self-swap script, and non-portable apply refusal.
// 0.5.2 coverage: the updater apply fix — the swap script's step
// logging + ~60 s lock-aware copy + always-relaunch, the WMI
// (Win32_Process.Create) launch command and its spawn fallback
// (audited `via`), the apply log's boot-time outcome parsing
// (parseApplyLog / getLastApplyOutcome / applyOutcomeLabel), and
// cleanup keeping the log while removing the stale script.
// 0.5.1 coverage: screen.capture (screenCapture.js + the rpc wiring) —
// standard-family permission behavior (stored "allow" honored,
// always-allow persists — the shell.run contrast), pre-gate param
// validation, the prompt's one-line summary, capture flow against a
// fake capturer (downscale math, display selection, out-of-range /
// no-screens errors), the moving-state refusal, and an audit summary
// that carries dimensions but never image data.
// 0.5.3 coverage: screen.list (screenCapture.js + the rpc wiring) —
// the list shape from a fake display provider (primary not first,
// scaleFactor passthrough), index alignment with the capture source
// ordering as encoded in the module, shared-capability gating (the
// screen.capture key: ask prompts, stored "allow" honored), the
// moving-state refusal, the Activity describe line, and metadata-only
// audit summaries. Also 0.5.3: the version-free portable name (the
// updater's exe asset is the constant Muse-Portable.exe) and the
// tray left-click setting (dispatch, 'window' default incl. legacy
// settings files, settings.json round-trip, settings-window wiring).
// Run: npm test
'use strict';

const assert = require('node:assert');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { createRpcHandler, METHOD_CAPABILITY, _internals } = require('../src/rpc');
const {
  effectivePolicyMode,
  sanitizePromptAnswer,
  NEVER_ALLOW_CAPABILITIES,
  DEFAULT_POLICY,
  loadPolicy,
} = require('../src/permissions');
const {
  ScreenCaptureError,
  validateCaptureParams,
  describeCaptureRequest,
  computeScaledSize,
  createScreenCapture,
  describeListRequest,
  normalizeDisplays,
  createScreenList,
} = require('../src/screenCapture');
const {
  parseAuditLogText,
  formatActivity,
  formatLocalTime,
  describeEntry,
  readBridgeActivity,
} = require('../src/bridgeActivity');
const { ensureBridgeToken, tokenMatches } = require('../src/bridgeAuth');
const { startBridge, startBridgeSet } = require('../src/bridge');
const { findTailscaleAddress, hasTailscaleAdapter, getBridgeStatus, isTailscaleIPv4 } = require('../src/bridgeNetwork');
const { tasklistMentionsTailscale } = require('../src/tailscaleProbe');
const {
  ensureSettings,
  saveSettings,
  DEFAULT_SETTINGS: SETTINGS_DEFAULTS,
  normalizeTrayLeftClick,
} = require('../src/settings');
const { trayLeftClickTarget } = require('../src/tray');
const {
  getStorageInfo,
  ensureAssistantFolder,
  destinationForParent,
  createAssistantFolderAt,
  normalizeSubfolders,
} = require('../src/assistantFolder');
const { precheckMove, moveAssistantFolder } = require('../src/moveFolder');
const { formatBytes, formatPercent } = require('../src/formatBytes');
const {
  PINNED_SIGNER_FINGERPRINT256,
  EXE_ASSET_NAME,
  exeAssetName,
  parseVersion,
  compareVersions,
  isNewerVersion,
  parseLatestRelease,
  parseSha256Sums,
  verifyChecksum,
  verifyDownloadedUpdate,
  signerFingerprint256FromExe,
  fingerprint256OfCertDer,
  buildSwapScript,
  buildWmiLaunchCommand,
  parseApplyLog,
  applyOutcomeLabel,
  APPLY_LOG_NAME,
  MAX_COPY_ATTEMPTS,
  psQuote,
  createUpdater,
} = require('../src/updater');

const tests = [];
function test(name, fn) {
  tests.push({ name, fn });
}

// A fresh environment: temp userData + assistant folder + an "outside"
// folder, with the given capability modes written to permissions.json.
function makeEnv(capabilities = {}, { maxStorageGB = 10 } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'muse-p2-'));
  const userDataPath = path.join(root, 'userData');
  const assistantFolder = path.join(root, 'assistant');
  const outsideFolder = path.join(root, 'outside');
  fs.mkdirSync(path.join(assistantFolder, 'workspace'), { recursive: true });
  fs.mkdirSync(path.join(assistantFolder, 'shared'), { recursive: true });
  fs.mkdirSync(outsideFolder, { recursive: true });
  fs.mkdirSync(userDataPath, { recursive: true });
  const policy = {
    version: 1,
    capabilities: {
      'fs.read': 'allow',
      'fs.write': 'allow',
      'fs.list': 'allow',
      'app.launch': 'allow',
      'process.list': 'allow',
      'process.kill': 'allow',
      ...capabilities,
    },
    approvedFolders: [],
  };
  fs.writeFileSync(path.join(userDataPath, 'permissions.json'), JSON.stringify(policy, null, 2));
  const settings = { assistantFolder, maxStorageGB };
  return {
    root,
    userDataPath,
    assistantFolder,
    outsideFolder,
    settings,
    writePolicy(next) {
      fs.writeFileSync(path.join(userDataPath, 'permissions.json'), JSON.stringify(next, null, 2));
    },
    readPolicy() {
      return JSON.parse(fs.readFileSync(path.join(userDataPath, 'permissions.json'), 'utf8'));
    },
    auditEntries() {
      const file = path.join(userDataPath, 'bridge-audit.log');
      if (!fs.existsSync(file)) return [];
      return fs
        .readFileSync(file, 'utf8')
        .trim()
        .split('\n')
        .filter(Boolean)
        .map((line) => JSON.parse(line));
    },
  };
}

function makeHandler(env, extra = {}) {
  return createRpcHandler({
    userDataPath: env.userDataPath,
    getSettings: () => env.settings,
    isMoving: () => false,
    prompt: async () => ({ allowed: true }),
    ...extra,
  });
}

async function expectRpcError(promise, code) {
  try {
    await promise;
  } catch (err) {
    assert.strictEqual(err.code, code, `expected error code ${code}, got ${err.code}: ${err.message}`);
    return err;
  }
  assert.fail(`expected RpcError ${code}, but the call succeeded`);
}

// ---------------------------------------------------------------------------

test('bridge token: generated once, stable, matches constant-time', () => {
  const env = makeEnv();
  const t1 = ensureBridgeToken(env.userDataPath);
  const t2 = ensureBridgeToken(env.userDataPath);
  assert.strictEqual(t1, t2);
  assert.ok(t1.length >= 32);
  assert.ok(fs.existsSync(path.join(env.userDataPath, 'bridge-token.txt')));
  assert.strictEqual(tokenMatches(t1, t1), true);
  assert.strictEqual(tokenMatches('wrong-token-value-of-same-length-000000', t1), false);
  assert.strictEqual(tokenMatches(undefined, t1), false);
  assert.strictEqual(tokenMatches(t1, undefined), false);
});

test('policy allow: fs.write / fs.read / fs.list roundtrip', async () => {
  const env = makeEnv();
  const rpc = makeHandler(env);
  const target = path.join(env.assistantFolder, 'workspace', 'note.txt');
  const written = await rpc('fs.write', { path: target, content: 'hello bridge' });
  assert.strictEqual(written.bytes, 12);
  assert.strictEqual(fs.readFileSync(target, 'utf8'), 'hello bridge');
  const read = await rpc('fs.read', { path: target });
  assert.strictEqual(read.content, 'hello bridge');
  const list = await rpc('fs.list', { path: path.join(env.assistantFolder, 'workspace') });
  assert.deepStrictEqual(
    list.entries.map((e) => e.name),
    ['note.txt'],
  );
  assert.strictEqual(list.entries[0].type, 'file');
  assert.strictEqual(list.entries[0].size, 12);
});

test('fs.write creates parent dirs inside scope; fs.mkdir works', async () => {
  const env = makeEnv();
  const rpc = makeHandler(env);
  const nested = path.join(env.assistantFolder, 'shared', 'a', 'b', 'deep.txt');
  await rpc('fs.write', { path: nested, content: 'deep' });
  assert.strictEqual(fs.readFileSync(nested, 'utf8'), 'deep');
  const dir = path.join(env.assistantFolder, 'shared', 'made');
  await rpc('fs.mkdir', { path: dir });
  assert.ok(fs.statSync(dir).isDirectory());
});

test('policy deny: refuses without executing', async () => {
  const env = makeEnv({ 'fs.write': 'deny' });
  const rpc = makeHandler(env);
  const target = path.join(env.assistantFolder, 'workspace', 'nope.txt');
  await expectRpcError(rpc('fs.write', { path: target, content: 'x' }), 'permission_denied');
  assert.ok(!fs.existsSync(target), 'file must not be created when policy denies');
  const audit = env.auditEntries();
  assert.strictEqual(audit[audit.length - 1].decision, 'deny');
  assert.strictEqual(audit[audit.length - 1].outcome, 'refused');
});

test('policy ask + prompt grants: executes, audit says ask-granted', async () => {
  const env = makeEnv({ 'fs.read': 'ask' });
  const file = path.join(env.assistantFolder, 'shared', 'secret.txt');
  fs.writeFileSync(file, 'top secret');
  let seenRequest = null;
  const rpc = makeHandler(env, {
    prompt: async (req) => {
      seenRequest = req;
      return { allowed: true };
    },
  });
  const read = await rpc('fs.read', { path: file });
  assert.strictEqual(read.content, 'top secret');
  assert.strictEqual(seenRequest.capability, 'fs.read');
  assert.ok(seenRequest.detail.includes('secret.txt'), 'prompt detail names the exact path');
  assert.strictEqual(env.auditEntries().at(-1).decision, 'ask-granted');
});

test('policy ask + prompt denies: refuses without executing', async () => {
  const env = makeEnv({ 'fs.write': 'ask' });
  const rpc = makeHandler(env, { prompt: async () => ({ allowed: false }) });
  const target = path.join(env.assistantFolder, 'workspace', 'denied.txt');
  await expectRpcError(rpc('fs.write', { path: target, content: 'x' }), 'permission_denied');
  assert.ok(!fs.existsSync(target));
  assert.strictEqual(env.auditEntries().at(-1).decision, 'ask-denied');
});

test('policy ask + prompt timeout: no answer in time = deny', async () => {
  const env = makeEnv({ 'fs.list': 'ask' });
  const rpc = makeHandler(env, {
    prompt: () => new Promise(() => {}), // never answers
    promptTimeoutMs: 60,
  });
  await expectRpcError(rpc('fs.list', { path: env.assistantFolder }), 'permission_timeout');
  assert.strictEqual(env.auditEntries().at(-1).decision, 'ask-timeout');
});

test('policy ask with no prompt implementation: denied, never granted', async () => {
  const env = makeEnv({ 'fs.list': 'ask' });
  const rpc = createRpcHandler({
    userDataPath: env.userDataPath,
    getSettings: () => env.settings,
    isMoving: () => false,
    // no prompt dep at all
  });
  await expectRpcError(rpc('fs.list', { path: env.assistantFolder }), 'permission_denied');
});

test('always allow: flips the capability in permissions.json and stops prompting', async () => {
  const env = makeEnv({ 'fs.list': 'ask' });
  let prompts = 0;
  const rpc = makeHandler(env, {
    prompt: async () => {
      prompts += 1;
      return { allowed: true, alwaysAllow: true };
    },
  });
  await rpc('fs.list', { path: env.assistantFolder });
  assert.strictEqual(prompts, 1);
  assert.strictEqual(env.readPolicy().capabilities['fs.list'], 'allow', 'capability persisted as allow');
  await rpc('fs.list', { path: env.assistantFolder });
  assert.strictEqual(prompts, 1, 'second call must not prompt again');
  assert.strictEqual(env.auditEntries().at(-1).decision, 'allow');
});

test('scope: path outside the assistant folder is refused even when policy allows', async () => {
  const env = makeEnv();
  const rpc = makeHandler(env);
  const outsideFile = path.join(env.outsideFolder, 'loot.txt');
  fs.writeFileSync(outsideFile, 'loot');
  await expectRpcError(rpc('fs.read', { path: outsideFile }), 'scope_refused');
  assert.strictEqual(env.auditEntries().at(-1).decision, 'scope-refused');
});

test('scope: ../ traversal escaping the assistant folder is refused', async () => {
  const env = makeEnv();
  const rpc = makeHandler(env);
  const traversal = path.join(env.assistantFolder, 'workspace', '..', '..', 'outside', 'loot.txt');
  fs.writeFileSync(path.join(env.outsideFolder, 'loot.txt'), 'loot');
  await expectRpcError(rpc('fs.read', { path: traversal }), 'scope_refused');
  const traversalWrite = path.join(env.assistantFolder, 'workspace', '..', '..', 'outside', 'evil.txt');
  await expectRpcError(rpc('fs.write', { path: traversalWrite, content: 'evil' }), 'scope_refused');
  assert.ok(!fs.existsSync(path.join(env.outsideFolder, 'evil.txt')));
});

test('scope: approvedFolders entry makes an outside path readable', async () => {
  const env = makeEnv();
  const policy = env.readPolicy();
  policy.approvedFolders = [env.outsideFolder];
  env.writePolicy(policy);
  const rpc = makeHandler(env);
  const outsideFile = path.join(env.outsideFolder, 'ok.txt');
  fs.writeFileSync(outsideFile, 'approved');
  const read = await rpc('fs.read', { path: outsideFile });
  assert.strictEqual(read.content, 'approved');
});

test('storage cap: fs.write into the assistant folder refuses past maxStorageGB', async () => {
  const env = makeEnv({}, { maxStorageGB: 1e-6 }); // ~1073 bytes
  const rpc = makeHandler(env);
  const big = path.join(env.assistantFolder, 'workspace', 'big.txt');
  await expectRpcError(rpc('fs.write', { path: big, content: 'x'.repeat(2000) }), 'storage_cap');
  assert.ok(!fs.existsSync(big));
  const small = path.join(env.assistantFolder, 'workspace', 'small.txt');
  await rpc('fs.write', { path: small, content: 'x'.repeat(500) });
  assert.ok(fs.existsSync(small));
});

test('moving state: fs tools refuse while a folder move is in progress', async () => {
  const env = makeEnv();
  const rpc = makeHandler(env, { isMoving: () => true });
  await expectRpcError(rpc('fs.list', { path: env.assistantFolder }), 'storage_moving');
  assert.strictEqual(env.auditEntries().at(-1).decision, 'storage-moving');
});

test('fs.read: files over 1 MB are refused', async () => {
  const env = makeEnv();
  const rpc = makeHandler(env);
  const big = path.join(env.assistantFolder, 'workspace', 'big.bin');
  fs.writeFileSync(big, Buffer.alloc(1024 * 1024 + 1, 0x61));
  await expectRpcError(rpc('fs.read', { path: big }), 'too_large');
});

test('app.launch: gated, and the launcher receives the target', async () => {
  const env = makeEnv({ 'app.launch': 'ask' });
  const launched = [];
  const rpc = makeHandler(env, {
    prompt: async () => ({ allowed: true }),
    launchApp: async (target) => {
      launched.push(target);
      return { launched: target };
    },
  });
  const result = await rpc('app.launch', { target: 'notepad.exe' });
  assert.deepStrictEqual(launched, ['notepad.exe']);
  assert.strictEqual(result.launched, 'notepad.exe');
});

test('process.list: returns the injected process list', async () => {
  const env = makeEnv();
  const rpc = makeHandler(env, {
    listProcesses: async () => ({ processes: [{ name: 'muse.exe', pid: 42, memoryBytes: 2048 }] }),
  });
  const result = await rpc('process.list', {});
  assert.strictEqual(result.processes[0].pid, 42);
});

test('process.kill: actually terminates a spawned process', async () => {
  const env = makeEnv();
  const rpc = makeHandler(env);
  const child = spawn('sleep', ['60'], { stdio: 'ignore' });
  const exited = new Promise((resolve) => child.on('exit', (code, signal) => resolve({ code, signal })));
  try {
    const result = await rpc('process.kill', { pid: child.pid });
    assert.strictEqual(result.pid, child.pid);
    const outcome = await Promise.race([
      exited,
      new Promise((_, reject) => setTimeout(() => reject(new Error('child did not exit in time')), 5000)),
    ]);
    assert.ok(outcome.signal === 'SIGTERM' || outcome.code !== null);
  } finally {
    if (child.exitCode === null) child.kill('SIGKILL');
  }
});

test('unknown method: clean error', async () => {
  const env = makeEnv();
  const rpc = makeHandler(env);
  await expectRpcError(rpc('fs.delete', { path: env.assistantFolder }), 'unknown_method');
});

test('audit log: summaries carry paths but never file contents', async () => {
  const env = makeEnv();
  const rpc = makeHandler(env);
  await rpc('fs.write', { path: path.join(env.assistantFolder, 'workspace', 'a.txt'), content: 'DO-NOT-LOG-ME' });
  const raw = fs.readFileSync(path.join(env.userDataPath, 'bridge-audit.log'), 'utf8');
  assert.ok(!raw.includes('DO-NOT-LOG-ME'), 'audit log must never contain file contents');
  const entries = env.auditEntries();
  assert.strictEqual(entries.length, 1);
  assert.strictEqual(entries[0].method, 'fs.write');
  assert.strictEqual(entries[0].params.bytes, 13); // "DO-NOT-LOG-ME"
  assert.strictEqual(entries[0].decision, 'allow');
  assert.strictEqual(entries[0].outcome, 'ok');
});

test('bridge HTTP: token required for /rpc and /storage, /health stays open', async () => {
  const env = makeEnv();
  const token = ensureBridgeToken(env.userDataPath);
  const rpc = makeHandler(env);
  const server = startBridge({
    version: '0.2.0-test',
    getStorageInfo: () => getStorageInfo(env.settings),
    isMoving: () => false,
    getBridgeToken: () => token,
    handleRpc: rpc,
    host: '127.0.0.1',
    port: 0,
  });
  await new Promise((resolve) => server.on('listening', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    const health = await fetch(`${base}/health`);
    assert.strictEqual(health.status, 200);
    const healthBody = await health.json();
    assert.strictEqual(healthBody.bridge, 'live');
    assert.strictEqual(healthBody.storage, 'ok');

    const storageNoToken = await fetch(`${base}/storage`);
    assert.strictEqual(storageNoToken.status, 401);
    const storageToken = await fetch(`${base}/storage`, { headers: { 'X-Bridge-Token': token } });
    assert.strictEqual(storageToken.status, 200);

    const rpcNoToken = await fetch(`${base}/rpc`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ method: 'fs.list', params: { path: env.assistantFolder } }),
    });
    assert.strictEqual(rpcNoToken.status, 401);

    const rpcWrongToken = await fetch(`${base}/rpc`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Bridge-Token': 'deadbeef'.repeat(8) },
      body: JSON.stringify({ method: 'fs.list', params: { path: env.assistantFolder } }),
    });
    assert.strictEqual(rpcWrongToken.status, 401);

    const rpcOk = await fetch(`${base}/rpc`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Bridge-Token': token },
      body: JSON.stringify({ method: 'fs.list', params: { path: env.assistantFolder } }),
    });
    assert.strictEqual(rpcOk.status, 200);
    const rpcOkBody = await rpcOk.json();
    assert.strictEqual(rpcOkBody.ok, true);
    assert.ok(Array.isArray(rpcOkBody.result.entries));

    const rpcDeniedShape = await fetch(`${base}/rpc`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Bridge-Token': token },
      body: JSON.stringify({ method: 'fs.read', params: { path: path.join(env.outsideFolder, 'x.txt') } }),
    });
    const deniedBody = await rpcDeniedShape.json();
    assert.strictEqual(deniedBody.ok, false);
    assert.strictEqual(deniedBody.error.code, 'scope_refused');

    const badJson = await fetch(`${base}/rpc`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Bridge-Token': token },
      body: '{not json',
    });
    assert.strictEqual(badJson.status, 400);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

// --- 0.2.1: parent-location folder choice + subfolder normalization --------

// A 0.2.0-style assistant folder: lowercase workspace/shared, some files.
function makeLegacyAssistant(root) {
  const folder = path.join(root, 'current', 'Muse');
  fs.mkdirSync(path.join(folder, 'workspace'), { recursive: true });
  fs.mkdirSync(path.join(folder, 'shared'), { recursive: true });
  fs.writeFileSync(path.join(folder, 'workspace', 'note.txt'), 'work note');
  fs.writeFileSync(path.join(folder, 'shared', 'drop.txt'), 'shared drop');
  fs.writeFileSync(path.join(folder, 'top.txt'), 'top level');
  return folder;
}

test('0.2.1 destinationForParent: appends the Muse folder name', () => {
  assert.strictEqual(destinationForParent(path.join('some', 'parent')), path.join('some', 'parent', 'Muse'));
});

test('0.2.1 first-run helper: creates Muse + Workspace + Shared under the picked parent', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'muse-021-firstrun-'));
  const parent = path.join(root, 'picked', 'location'); // doesn't exist yet
  const created = createAssistantFolderAt(parent);
  assert.strictEqual(created, path.join(parent, 'Muse'));
  assert.ok(fs.statSync(path.join(created, 'Workspace')).isDirectory());
  assert.ok(fs.statSync(path.join(created, 'Shared')).isDirectory());
});

test('0.2.1 move: fresh parent creates Muse + Workspace/Shared, contents preserved', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'muse-021-move-fresh-'));
  const from = makeLegacyAssistant(root);
  const parent = path.join(root, 'Desktop');
  fs.mkdirSync(parent, { recursive: true });
  const dest = destinationForParent(parent);

  const pre = precheckMove(from, dest);
  assert.ok(pre.ok, pre.errors.join(' '));
  assert.strictEqual(pre.needsMergeConfirm, false);

  const result = await moveAssistantFolder({ from, to: dest });
  assert.strictEqual(result.fileCount, 3);
  normalizeSubfolders(dest); // what settings:start-move does after the flip

  assert.ok(!fs.existsSync(from), 'rename path consumed the old folder');
  assert.strictEqual(fs.readFileSync(path.join(dest, 'top.txt'), 'utf8'), 'top level');
  assert.strictEqual(fs.readFileSync(path.join(dest, 'Workspace', 'note.txt'), 'utf8'), 'work note');
  assert.strictEqual(fs.readFileSync(path.join(dest, 'Shared', 'drop.txt'), 'utf8'), 'shared drop');
  assert.ok(!fs.existsSync(path.join(dest, 'workspace')), 'lowercase workspace renamed away');
  assert.ok(!fs.existsSync(path.join(dest, 'shared')), 'lowercase shared renamed away');
});

test('0.2.1 move: parent already holding an empty Muse folder needs no merge confirm', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'muse-021-move-empty-'));
  const from = makeLegacyAssistant(root);
  const parent = path.join(root, 'Somewhere');
  const dest = destinationForParent(parent);
  fs.mkdirSync(dest, { recursive: true }); // exists, empty

  const pre = precheckMove(from, dest);
  assert.ok(pre.ok, pre.errors.join(' '));
  assert.strictEqual(pre.needsMergeConfirm, false);

  await moveAssistantFolder({ from, to: dest });
  normalizeSubfolders(dest);
  assert.strictEqual(fs.readFileSync(path.join(dest, 'Workspace', 'note.txt'), 'utf8'), 'work note');
  assert.strictEqual(fs.readFileSync(path.join(dest, 'Shared', 'drop.txt'), 'utf8'), 'shared drop');
});

test('0.2.1 move: non-empty Muse at destination requires merge confirm; assistant files win', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'muse-021-move-merge-'));
  const from = path.join(root, 'current', 'Muse');
  fs.mkdirSync(path.join(from, 'Workspace'), { recursive: true });
  fs.writeFileSync(path.join(from, 'Workspace', 'clash.txt'), 'assistant wins');
  const parent = path.join(root, 'Elsewhere');
  const dest = destinationForParent(parent);
  fs.mkdirSync(path.join(dest, 'Workspace'), { recursive: true });
  fs.writeFileSync(path.join(dest, 'Workspace', 'clash.txt'), 'destination loses');
  fs.writeFileSync(path.join(dest, 'dest-only.txt'), 'destination keeps this');

  const pre = precheckMove(from, dest);
  assert.ok(pre.ok, pre.errors.join(' '));
  assert.strictEqual(pre.needsMergeConfirm, true);

  await moveAssistantFolder({ from, to: dest, forceCopy: true });
  normalizeSubfolders(dest);
  assert.strictEqual(fs.readFileSync(path.join(dest, 'Workspace', 'clash.txt'), 'utf8'), 'assistant wins');
  assert.strictEqual(fs.readFileSync(path.join(dest, 'dest-only.txt'), 'utf8'), 'destination keeps this');
});

test('0.2.1 move: picking the parent of the current folder is a no-op rejection', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'muse-021-move-same-'));
  const from = makeLegacyAssistant(root); // <root>/current/Muse
  const parent = path.dirname(from); // destination resolves back to `from`
  const dest = destinationForParent(parent);
  assert.strictEqual(dest, from);
  const pre = precheckMove(from, dest);
  assert.strictEqual(pre.ok, false);
  assert.ok(pre.errors.some((e) => e.includes('current assistant folder')), pre.errors.join(' '));
  assert.ok(fs.existsSync(path.join(from, 'workspace', 'note.txt')), 'nothing was touched');
});

test('0.2.1 move: a parent inside the current folder is rejected', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'muse-021-move-inside-'));
  const from = makeLegacyAssistant(root);
  const parent = path.join(from, 'workspace', 'nested'); // inside current
  const dest = destinationForParent(parent);
  const pre = precheckMove(from, dest);
  assert.strictEqual(pre.ok, false);
  assert.ok(pre.errors.some((e) => e.includes('inside the current assistant folder')), pre.errors.join(' '));
});

test('0.2.1 normalization: lowercase pair is case-renamed, contents intact, then idempotent', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'muse-021-norm-'));
  const folder = path.join(root, 'Muse');
  fs.mkdirSync(path.join(folder, 'workspace'), { recursive: true });
  fs.mkdirSync(path.join(folder, 'shared'), { recursive: true });
  fs.writeFileSync(path.join(folder, 'workspace', 'a.txt'), 'aaa');

  const actions = normalizeSubfolders(folder);
  assert.deepStrictEqual(
    actions.renamed.map((r) => `${r.from}->${r.to}`).sort(),
    ['shared->Shared', 'workspace->Workspace'],
  );
  assert.deepStrictEqual(actions.created, []);
  assert.deepStrictEqual(actions.conflicts, []);
  assert.strictEqual(fs.readFileSync(path.join(folder, 'Workspace', 'a.txt'), 'utf8'), 'aaa');
  assert.ok(!fs.existsSync(path.join(folder, 'workspace')));

  const again = normalizeSubfolders(folder);
  assert.deepStrictEqual(again.renamed, []);
  assert.deepStrictEqual(again.created, []);
});

test('0.2.1 normalization: missing pair is created capitalized', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'muse-021-norm-missing-'));
  const folder = path.join(root, 'Muse');
  fs.mkdirSync(folder, { recursive: true });
  const actions = normalizeSubfolders(folder);
  assert.deepStrictEqual(actions.created.sort(), ['Shared', 'Workspace']);
  assert.ok(fs.statSync(path.join(folder, 'Workspace')).isDirectory());
  assert.ok(fs.statSync(path.join(folder, 'Shared')).isDirectory());
});

test('0.2.1 normalization: both casings present are left alone and flagged', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'muse-021-norm-both-'));
  const folder = path.join(root, 'Muse');
  fs.mkdirSync(path.join(folder, 'workspace'), { recursive: true });
  fs.mkdirSync(path.join(folder, 'Workspace'), { recursive: true });
  fs.mkdirSync(path.join(folder, 'Shared'), { recursive: true });
  const actions = normalizeSubfolders(folder);
  assert.ok(actions.conflicts.includes('Workspace'), 'conflict reported');
  assert.deepStrictEqual(actions.renamed, []);
  assert.ok(fs.existsSync(path.join(folder, 'workspace')), 'lowercase folder untouched');
  assert.ok(fs.existsSync(path.join(folder, 'Workspace')), 'capitalized folder untouched');
});

test('0.2.1 startup: ensureAssistantFolder normalizes a 0.2.0-style folder in place', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'muse-021-startup-'));
  const folder = path.join(root, 'Desktop', 'Muse');
  fs.mkdirSync(path.join(folder, 'workspace'), { recursive: true });
  fs.mkdirSync(path.join(folder, 'shared'), { recursive: true });
  ensureAssistantFolder({ assistantFolder: folder, maxStorageGB: 10 });
  assert.ok(fs.statSync(path.join(folder, 'Workspace')).isDirectory());
  assert.ok(fs.statSync(path.join(folder, 'Shared')).isDirectory());
  assert.ok(!fs.existsSync(path.join(folder, 'workspace')));
  assert.ok(!fs.existsSync(path.join(folder, 'shared')));
});

// --- 0.2.4: adaptive byte / percent formatting ----------------------------

const GiB = 1024 ** 3;
const CAP_10GB = 10 * GiB;

test('0.2.4 formatBytes: zero and sub-KB values are plain bytes', () => {
  assert.strictEqual(formatBytes(0), '0 B');
  assert.strictEqual(formatBytes(500), '500 B');
  assert.strictEqual(formatBytes(1023), '1023 B');
});

test('0.2.4 formatBytes: KB/MB with trimmed decimals', () => {
  assert.strictEqual(formatBytes(1024), '1 KB');
  assert.strictEqual(formatBytes(1536), '1.5 KB');
  assert.strictEqual(formatBytes(1024 ** 2), '1 MB');
  assert.strictEqual(formatBytes(2 * 1024 ** 2), '2 MB');
});

test('0.2.4 formatBytes: the screenshot case — ~2 MB never renders as 0.00 GB', () => {
  const out = formatBytes(2149581); // ≈2.05 MB, i.e. 0.02% of a 10 GB cap
  assert.strictEqual(out, '2.05 MB');
  assert.ok(!out.includes('GB'));
});

test('0.2.4 formatBytes: rounding at a unit edge steps up instead of showing 1024', () => {
  assert.strictEqual(formatBytes(1024 ** 2 - 1), '1 MB');
});

test('0.2.4 formatBytes: GB keeps 2–3 decimals, TB beyond', () => {
  assert.strictEqual(formatBytes(GiB), '1.00 GB');
  assert.strictEqual(formatBytes(Math.round(2.154 * GiB)), '2.154 GB');
  assert.strictEqual(formatBytes(10 * GiB), '10.00 GB');
  assert.strictEqual(formatBytes(1024 ** 4), '1.00 TB');
});

test('0.2.4 formatPercent: zero and full', () => {
  assert.strictEqual(formatPercent(0, CAP_10GB), '0%');
  assert.strictEqual(formatPercent(CAP_10GB, CAP_10GB), '100%');
  assert.strictEqual(formatPercent(123, 0), '0%');
});

test('0.2.4 formatPercent: tiny values stay truthful (2 significant figures)', () => {
  assert.strictEqual(formatPercent(2149581, CAP_10GB), '0.02%');
  assert.strictEqual(formatPercent(332860, CAP_10GB), '0.0031%');
});

test('0.2.4 formatPercent: larger values use up to 2 decimals; over 100% works', () => {
  assert.strictEqual(formatPercent(CAP_10GB / 8, CAP_10GB), '12.5%');
  assert.strictEqual(formatPercent(Math.round(0.47236 * CAP_10GB), CAP_10GB), '47.24%');
  assert.strictEqual(formatPercent(2.5 * CAP_10GB, CAP_10GB), '250%');
});

// --- 0.3.0: Tailscale interface selection + bridge status -----------------

const v4 = (address, internal = false) => ({ address, family: 'IPv4', internal, netmask: '255.255.255.0' });
const v6 = (address, internal = false) => ({ address, family: 'IPv6', internal, netmask: 'ffff::' });
const LOOPBACK_ONLY = { lo: [{ address: '127.0.0.1', family: 'IPv4', internal: true }] };
const LAN_ONLY = { eth0: [v4('192.168.1.10'), v4('10.0.0.5')] };
const WITH_TAILSCALE = {
  eth0: [v4('192.168.1.10')],
  tailscale0: [v4('100.100.100.100'), v6('fd7a:115c:a1e0::100')],
};

test('0.3.0 findTailscaleAddress: no interfaces → null', () => {
  assert.strictEqual(findTailscaleAddress(null), null);
  assert.strictEqual(findTailscaleAddress(undefined), null);
  assert.strictEqual(findTailscaleAddress({}), null);
  assert.strictEqual(findTailscaleAddress(LOOPBACK_ONLY), null);
});

test('0.3.0 findTailscaleAddress: LAN-only interfaces → null (never a LAN address)', () => {
  assert.strictEqual(findTailscaleAddress(LAN_ONLY), null);
});

test('0.3.0 findTailscaleAddress: picks the Tailscale IPv4 out of a mixed set', () => {
  assert.strictEqual(findTailscaleAddress(WITH_TAILSCALE), '100.100.100.100');
});

test('0.3.0 findTailscaleAddress: internal or IPv6 100.x entries are skipped', () => {
  assert.strictEqual(findTailscaleAddress({ ts0: [v4('100.100.100.100', true)] }), null);
  assert.strictEqual(findTailscaleAddress({ ts0: [v6('fd7a:115c:a1e0::1')] }), null);
  // A skipped internal entry does not hide a later usable one.
  assert.strictEqual(
    findTailscaleAddress({ ts0: [v4('100.100.100.100', true)], ts1: [v4('100.101.102.103')] }),
    '100.101.102.103',
  );
});

test('0.3.0 isTailscaleIPv4: CGNAT 100.64/10 boundaries are exact', () => {
  assert.strictEqual(isTailscaleIPv4('100.63.255.255'), false);
  assert.strictEqual(isTailscaleIPv4('100.64.0.0'), true);
  assert.strictEqual(isTailscaleIPv4('100.127.255.255'), true);
  assert.strictEqual(isTailscaleIPv4('100.128.0.0'), false);
  assert.strictEqual(isTailscaleIPv4('100.100.100.100'), true);
  assert.strictEqual(isTailscaleIPv4('192.168.100.100'), false);
  assert.strictEqual(isTailscaleIPv4('not-an-ip'), false);
  assert.strictEqual(isTailscaleIPv4(null), false);
});

test('0.3.0 getBridgeStatus: setting off → this PC only, whatever the interfaces', () => {
  assert.deepStrictEqual(getBridgeStatus(false, WITH_TAILSCALE), {
    mode: 'local',
    reason: null,
    address: null,
    label: 'Bridge: this PC only',
  });
  assert.strictEqual(getBridgeStatus(false, {}).label, 'Bridge: this PC only');
});

test('0.3.0 getBridgeStatus: setting on + Tailscale → tailnet label with the address', () => {
  assert.deepStrictEqual(getBridgeStatus(true, WITH_TAILSCALE), {
    mode: 'tailscale',
    reason: null,
    address: '100.100.100.100',
    label: 'Bridge: Tailscale — 100.100.100.100:47631',
  });
});

test('0.3.0 getBridgeStatus: setting on, no Tailscale, no probes → legacy not-detected', () => {
  assert.deepStrictEqual(getBridgeStatus(true, LAN_ONLY), {
    mode: 'tailscale-missing',
    reason: 'unknown',
    address: null,
    label: 'Bridge: Tailscale not detected',
  });
  assert.strictEqual(getBridgeStatus(true, {}).mode, 'tailscale-missing');
});

// --- 0.3.1: why is it unbound? (probes injected; the module stays pure) ---

const TS_ADAPTER_V6_ONLY = { Tailscale: [v6('fd7a:115c:a1e0::1')], eth0: [v4('192.168.1.10')] };
const TS_ADAPTER_LINK_LOCAL = { Tailscale: [v4('169.254.10.20')], 'Wi-Fi': [v4('192.168.1.10')] };

test('0.3.1 hasTailscaleAdapter: matches the adapter name, nothing else', () => {
  assert.strictEqual(hasTailscaleAdapter(TS_ADAPTER_V6_ONLY), true);
  assert.strictEqual(hasTailscaleAdapter({ tailscale0: [] }), true);
  assert.strictEqual(hasTailscaleAdapter(WITH_TAILSCALE), true); // 'tailscale0'
  assert.strictEqual(hasTailscaleAdapter(LAN_ONLY), false);
  assert.strictEqual(hasTailscaleAdapter(null), false);
  assert.strictEqual(hasTailscaleAdapter({}), false);
});

test('0.3.1 getBridgeStatus: Tailscale adapter but no tailnet IPv4 → not connected', () => {
  assert.deepStrictEqual(
    getBridgeStatus(true, TS_ADAPTER_V6_ONLY, 47631, { binaryPresent: true, processRunning: true }),
    { mode: 'tailscale-missing', reason: 'not-connected', address: null, label: 'Bridge: Tailscale not connected' },
  );
  // A link-local-only adapter is the same story — and the adapter signal
  // wins even when the other probes (wrongly) say nothing is installed.
  assert.strictEqual(
    getBridgeStatus(true, TS_ADAPTER_LINK_LOCAL, 47631, { binaryPresent: false, processRunning: false }).reason,
    'not-connected',
  );
});

test('0.3.1 getBridgeStatus: no adapter, client process running → not connected', () => {
  assert.deepStrictEqual(getBridgeStatus(true, LAN_ONLY, 47631, { binaryPresent: false, processRunning: true }), {
    mode: 'tailscale-missing',
    reason: 'not-connected',
    address: null,
    label: 'Bridge: Tailscale not connected',
  });
});

test('0.3.1 getBridgeStatus: no adapter, binary present, nothing running → not running', () => {
  assert.deepStrictEqual(getBridgeStatus(true, LAN_ONLY, 47631, { binaryPresent: true, processRunning: false }), {
    mode: 'tailscale-missing',
    reason: 'not-running',
    address: null,
    label: 'Bridge: Tailscale not running',
  });
});

test('0.3.1 getBridgeStatus: no adapter, no binary, no process → not installed', () => {
  assert.deepStrictEqual(getBridgeStatus(true, LAN_ONLY, 47631, { binaryPresent: false, processRunning: false }), {
    mode: 'tailscale-missing',
    reason: 'not-installed',
    address: null,
    label: 'Bridge: Tailscale not installed',
  });
});

test('0.3.1 getBridgeStatus: inconclusive probes → unknown (legacy wording)', () => {
  assert.strictEqual(
    getBridgeStatus(true, LAN_ONLY, 47631, { binaryPresent: null, processRunning: null }).label,
    'Bridge: Tailscale not detected',
  );
  // Binary unknown but process known-absent is still inconclusive.
  assert.strictEqual(
    getBridgeStatus(true, LAN_ONLY, 47631, { binaryPresent: null, processRunning: false }).reason,
    'unknown',
  );
});

test('0.3.1 tasklistMentionsTailscale: matches both client process names only', () => {
  const list = '"explorer.exe","1000","Console","1","80,000 K"\r\n"tailscale-ipn.exe","2000","Console","1","40,000 K"';
  assert.strictEqual(tasklistMentionsTailscale(list), true);
  assert.strictEqual(tasklistMentionsTailscale('"TAILSCALE.EXE","3000","Services","0","20,000 K"'), true);
  assert.strictEqual(tasklistMentionsTailscale('"explorer.exe","1000","Console","1","80,000 K"'), false);
  assert.strictEqual(tasklistMentionsTailscale(''), false);
  assert.strictEqual(tasklistMentionsTailscale(null), false);
});

test('0.3.0 settings: bridgeRemoteAccess defaults to false and persists', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'muse-p3-settings-'));
  const userDataPath = path.join(root, 'userData');
  fs.mkdirSync(userDataPath, { recursive: true });

  // Fresh install: default is OFF and lands in settings.json.
  const fresh = ensureSettings(userDataPath);
  assert.strictEqual(fresh.values.bridgeRemoteAccess, false);
  const onDisk = JSON.parse(fs.readFileSync(path.join(userDataPath, 'settings.json'), 'utf8'));
  assert.strictEqual(onDisk.bridgeRemoteAccess, false);

  // A pre-0.3.0 settings.json (key absent) gains the default on load…
  fs.writeFileSync(
    path.join(userDataPath, 'settings.json'),
    JSON.stringify({ assistantFolder: 'C:\\Users\\you\\Muse', maxStorageGB: 5 }),
  );
  const upgraded = ensureSettings(userDataPath);
  assert.strictEqual(upgraded.values.bridgeRemoteAccess, false);
  assert.strictEqual(upgraded.values.maxStorageGB, 5); // existing values kept

  // …and an explicit true survives the round trip.
  fs.writeFileSync(
    path.join(userDataPath, 'settings.json'),
    JSON.stringify({ assistantFolder: 'C:\\Users\\you\\Muse', maxStorageGB: 5, bridgeRemoteAccess: true }),
  );
  assert.strictEqual(ensureSettings(userDataPath).values.bridgeRemoteAccess, true);
});

test('0.3.0 bridge set: two listeners share one handler (auth enforced on both)', async () => {
  const env = makeEnv();
  const token = ensureBridgeToken(env.userDataPath);
  // Both listeners sit on loopback with distinct ephemeral ports: what is
  // being proven is "N servers, one shared handler, auth on each". The
  // second production host is the Tailscale IPv4 — its selection is
  // unit-tested above and the bind itself is verified on a real machine;
  // this sandbox's HTTP proxy makes non-127.0.0.1 loopback fetches hang.
  const set = startBridgeSet({
    hosts: ['127.0.0.1', '127.0.0.1'],
    port: 0,
    version: '0.3.0-test',
    getStorageInfo: () => getStorageInfo(env.settings),
    isMoving: () => false,
    getBridgeToken: () => token,
    handleRpc: makeHandler(env),
  });
  await Promise.all(set.servers.map((s) => new Promise((resolve) => s.on('listening', resolve))));
  try {
    assert.strictEqual(set.servers.length, 2);
    for (const server of set.servers) {
      const bound = server.address();
      const base = `http://${bound.address}:${bound.port}`;
      // Health is open on every listener…
      const health = await fetch(`${base}/health`);
      assert.strictEqual(health.status, 200);
      await health.text();
      // …but /storage demands the token on every listener, no exceptions.
      // (Bodies are consumed so undici releases the sockets and the
      // test process can exit.)
      const noToken = await fetch(`${base}/storage`);
      assert.strictEqual(noToken.status, 401);
      await noToken.text();
      const withToken = await fetch(`${base}/storage`, { headers: { 'X-Bridge-Token': token } });
      assert.strictEqual(withToken.status, 200);
      await withToken.text();
    }
  } finally {
    await set.closeAll();
  }
});

// --- 0.4.0: shell.run -----------------------------------------------------

const OK_SHELL_RESULT = { stdout: 'done\n', stderr: '', exitCode: 0, timedOut: false, truncated: false };

function shellPolicy(env, mode) {
  const policy = env.readPolicy();
  policy.capabilities = { ...policy.capabilities, 'shell.run': mode };
  env.writePolicy(policy);
}

test('0.4.0 permissions: effectivePolicyMode coerces a stored allow for shell.run only', () => {
  assert.ok(NEVER_ALLOW_CAPABILITIES.has('shell.run'));
  assert.strictEqual(effectivePolicyMode('shell.run', 'allow'), 'ask');
  assert.strictEqual(effectivePolicyMode('shell.run', 'ask'), 'ask');
  assert.strictEqual(effectivePolicyMode('shell.run', 'deny'), 'deny');
  assert.strictEqual(effectivePolicyMode('fs.read', 'allow'), 'allow');
});

test('0.4.0 permissions: sanitizePromptAnswer strips alwaysAllow for shell.run only', () => {
  assert.deepStrictEqual(sanitizePromptAnswer('shell.run', { allowed: true, alwaysAllow: true }), {
    allowed: true,
    alwaysAllow: false,
  });
  assert.deepStrictEqual(sanitizePromptAnswer('fs.read', { allowed: true, alwaysAllow: true }), {
    allowed: true,
    alwaysAllow: true,
  });
  assert.deepStrictEqual(sanitizePromptAnswer('shell.run', { allowed: false, timedOut: true }), {
    allowed: false,
    alwaysAllow: false,
    timedOut: true,
  });
});

test('0.4.0 shell.run: prompt payload carries the EXACT command and no always-allow path', async () => {
  const env = makeEnv(); // shell.run defaults to "ask" via the policy defaults
  const longCommand = 'Get-ChildItem -Recurse | Where-Object { $_.Length -gt 1MB } | ' + 'Sort-Object Length; '.repeat(120);
  let seen = null;
  const rpc = makeHandler(env, {
    prompt: async (req) => {
      seen = req;
      return { allowed: true };
    },
    runShell: async () => OK_SHELL_RESULT,
  });
  const result = await rpc('shell.run', { command: longCommand });
  assert.deepStrictEqual(result, OK_SHELL_RESULT);
  assert.strictEqual(seen.capability, 'shell.run');
  assert.strictEqual(seen.detail, longCommand, 'the prompt detail is the command byte-for-byte, untruncated');
  assert.strictEqual(seen.canAlwaysAllow, false, 'no always-allow path exists for shell.run');
});

test('0.4.0 shell.run: other capabilities still get canAlwaysAllow=true in the payload', async () => {
  const env = makeEnv({ 'fs.list': 'ask' });
  let seen = null;
  const rpc = makeHandler(env, {
    prompt: async (req) => {
      seen = req;
      return { allowed: true };
    },
  });
  await rpc('fs.list', { path: env.assistantFolder });
  assert.strictEqual(seen.canAlwaysAllow, true);
});

test('0.4.0 shell.run: a stored "allow" still prompts (coerced at decision time)', async () => {
  const env = makeEnv();
  shellPolicy(env, 'allow'); // hand-edited file tries to make shell.run silent
  let prompts = 0;
  const rpc = makeHandler(env, {
    prompt: async () => {
      prompts += 1;
      return { allowed: true };
    },
    runShell: async () => OK_SHELL_RESULT,
  });
  await rpc('shell.run', { command: 'echo hi' });
  assert.strictEqual(prompts, 1, 'stored allow must NOT skip the prompt for shell.run');
  assert.strictEqual(env.auditEntries().at(-1).decision, 'ask-granted');
});

test('0.4.0 shell.run: an alwaysAllow prompt answer is never persisted', async () => {
  const env = makeEnv();
  shellPolicy(env, 'ask');
  let prompts = 0;
  const rpc = makeHandler(env, {
    prompt: async () => {
      prompts += 1;
      return { allowed: true, alwaysAllow: true }; // even if a prompt returned this
    },
    runShell: async () => OK_SHELL_RESULT,
  });
  await rpc('shell.run', { command: 'echo one' });
  assert.strictEqual(env.readPolicy().capabilities['shell.run'], 'ask', 'shell.run must stay "ask" on disk');
  await rpc('shell.run', { command: 'echo two' });
  assert.strictEqual(prompts, 2, 'the second call prompts again — nothing was persisted');
});

test('0.4.0 shell.run: prompt denial refuses and the runner never runs', async () => {
  const env = makeEnv();
  let ran = false;
  const rpc = makeHandler(env, {
    prompt: async () => ({ allowed: false }),
    runShell: async () => {
      ran = true;
      return OK_SHELL_RESULT;
    },
  });
  await expectRpcError(rpc('shell.run', { command: 'echo hi' }), 'permission_denied');
  assert.strictEqual(ran, false);
  assert.strictEqual(env.auditEntries().at(-1).decision, 'ask-denied');
});

test('0.4.0 shell.run: policy deny refuses without prompting or running', async () => {
  const env = makeEnv();
  shellPolicy(env, 'deny');
  let prompts = 0;
  let ran = false;
  const rpc = makeHandler(env, {
    prompt: async () => {
      prompts += 1;
      return { allowed: true };
    },
    runShell: async () => {
      ran = true;
      return OK_SHELL_RESULT;
    },
  });
  await expectRpcError(rpc('shell.run', { command: 'echo hi' }), 'permission_denied');
  assert.strictEqual(prompts, 0);
  assert.strictEqual(ran, false);
  assert.strictEqual(env.auditEntries().at(-1).decision, 'deny');
});

test('0.4.0 shell.run: missing/empty command is invalid_params and never prompts', async () => {
  const env = makeEnv();
  let prompts = 0;
  const rpc = makeHandler(env, {
    prompt: async () => {
      prompts += 1;
      return { allowed: true };
    },
    runShell: async () => OK_SHELL_RESULT,
  });
  await expectRpcError(rpc('shell.run', {}), 'invalid_params');
  await expectRpcError(rpc('shell.run', { command: '   ' }), 'invalid_params');
  await expectRpcError(rpc('shell.run', { command: 42 }), 'invalid_params');
  assert.strictEqual(prompts, 0);
});

test('0.4.0 shell.run: runner receives the command, the assistant-folder cwd and the clamped timeout', async () => {
  const env = makeEnv();
  const calls = [];
  const rpc = makeHandler(env, {
    runShell: async (command, options) => {
      calls.push({ command, options });
      return OK_SHELL_RESULT;
    },
  });
  shellPolicy(env, 'allow'); // coerced to ask; default prompt in makeHandler grants
  await rpc('shell.run', { command: 'echo a' });
  assert.strictEqual(calls[0].options.timeoutMs, 30_000, 'default timeout is 30s');
  assert.strictEqual(calls[0].options.cwd, env.assistantFolder);
  await rpc('shell.run', { command: 'echo b', timeoutMs: 999_999 });
  assert.strictEqual(calls[1].options.timeoutMs, 120_000, 'timeout is clamped to the 120s hard cap');
  await rpc('shell.run', { command: 'echo c', timeoutMs: 5_000 });
  assert.strictEqual(calls[2].options.timeoutMs, 5_000, 'an in-range timeout passes through');
  assert.deepStrictEqual(
    calls.map((c) => c.command),
    ['echo a', 'echo b', 'echo c'],
  );
});

test('0.4.0 shell.run: a nonzero exit is a result, not an rpc error', async () => {
  const env = makeEnv();
  const rpc = makeHandler(env, {
    runShell: async () => ({ stdout: '', stderr: 'boom\n', exitCode: 3, timedOut: false, truncated: false }),
  });
  const result = await rpc('shell.run', { command: 'exit 3' });
  assert.strictEqual(result.exitCode, 3);
  assert.strictEqual(result.stderr, 'boom\n');
  const last = env.auditEntries().at(-1);
  assert.strictEqual(last.outcome, 'ok');
  assert.strictEqual(last.method, 'shell.run');
});

test('0.4.0 shell.run: moving state refuses with storage_moving', async () => {
  const env = makeEnv();
  let ran = false;
  const rpc = makeHandler(env, {
    isMoving: () => true,
    runShell: async () => {
      ran = true;
      return OK_SHELL_RESULT;
    },
  });
  await expectRpcError(rpc('shell.run', { command: 'echo hi' }), 'storage_moving');
  assert.strictEqual(ran, false);
  assert.strictEqual(env.auditEntries().at(-1).decision, 'storage-moving');
});

test('0.4.0 shell.run: audit summary is the command, capped at 500 chars + marker', async () => {
  const env = makeEnv();
  const rpc = makeHandler(env, { runShell: async () => OK_SHELL_RESULT });
  const longCommand = 'echo ' + 'y'.repeat(700);
  await rpc('shell.run', { command: longCommand });
  const summary = env.auditEntries().at(-1).params.summary;
  assert.strictEqual(summary.length, 501, '500 chars + the ellipsis marker');
  assert.ok(summary.endsWith('…'));
  assert.ok(longCommand.startsWith(summary.slice(0, 500)), 'summary is the command prefix verbatim');
  await rpc('shell.run', { command: 'echo short' });
  assert.strictEqual(env.auditEntries().at(-1).params.summary, 'echo short', 'short commands are logged verbatim');
});

// The real default runner (POSIX branch — the build machine is Linux;
// the win32 branch spawns powershell.exe with the same argv discipline).
if (process.platform !== 'win32') {
  const { defaultRunShell } = _internals;

  test('0.4.0 shell.run (real runner): stdout/stderr captured separately, exit code reported', async () => {
    const out = await defaultRunShell('echo hello-shell; echo oops >&2', { timeoutMs: 10_000, cwd: os.tmpdir() });
    assert.strictEqual(out.stdout, 'hello-shell\n');
    assert.strictEqual(out.stderr, 'oops\n');
    assert.strictEqual(out.exitCode, 0);
    assert.strictEqual(out.timedOut, false);
    assert.strictEqual(out.truncated, false);
  });

  test('0.4.0 shell.run (real runner): nonzero exit code passes through; cwd is honored', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'muse-shell-cwd-'));
    const out = await defaultRunShell('pwd; exit 3', { timeoutMs: 10_000, cwd: dir });
    assert.strictEqual(out.exitCode, 3);
    assert.strictEqual(out.stdout.trim(), fs.realpathSync(dir));
  });

  test('0.4.0 shell.run (real runner): output past 64 KB is clipped and flagged', async () => {
    const out = await defaultRunShell("head -c 100000 /dev/zero | tr '\\0' 'x'", {
      timeoutMs: 10_000,
      cwd: os.tmpdir(),
    });
    assert.strictEqual(out.truncated, true);
    assert.strictEqual(Buffer.byteLength(out.stdout, 'utf8'), 64 * 1024);
    assert.ok(/^x+$/.test(out.stdout));
    assert.strictEqual(out.exitCode, 0);
  });

  test('0.4.0 shell.run (real runner): timeout kills the whole process tree', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'muse-shell-timeout-'));
    const marker = path.join(dir, 'grandchild-survived.txt');
    const started = Date.now();
    const out = await defaultRunShell(`(sleep 2; touch '${marker}') & sleep 30`, {
      timeoutMs: 200,
      cwd: dir,
    });
    const elapsed = Date.now() - started;
    assert.strictEqual(out.timedOut, true);
    assert.ok(elapsed < 10_000, `timeout must cut the call short (took ${elapsed}ms)`);
    // If only the top shell had died, the backgrounded subshell would
    // still create the marker at t≈2s. Wait past that, then check.
    await new Promise((resolve) => setTimeout(resolve, 2600));
    assert.ok(!fs.existsSync(marker), 'the backgrounded grandchild must have been killed with the tree');
  });
}

// --- 0.4.0: Bridge Activity parsing / formatting --------------------------

function activityEntry(overrides = {}) {
  return {
    ts: '2026-10-26T20:15:03.000Z',
    method: 'fs.list',
    params: { path: 'C:\\Users\\you\\Muse' },
    decision: 'allow',
    outcome: 'ok',
    ...overrides,
  };
}

test('0.4.0 activity: parser skips malformed and non-object lines', () => {
  const text = [
    JSON.stringify(activityEntry()),
    '{not json',
    '',
    '42',
    '"just a string"',
    JSON.stringify(activityEntry({ method: 'process.list', params: {} })),
  ].join('\n');
  const entries = parseAuditLogText(text);
  assert.strictEqual(entries.length, 2);
  assert.strictEqual(entries[1].method, 'process.list');
  assert.deepStrictEqual(parseAuditLogText(''), []);
  assert.deepStrictEqual(parseAuditLogText(null), []);
});

test('0.4.0 activity: summaries use the plain-language descriptions', () => {
  assert.strictEqual(describeEntry(activityEntry()), 'List: C:\\Users\\you\\Muse');
  assert.strictEqual(describeEntry(activityEntry({ method: 'fs.read' })), 'Read: C:\\Users\\you\\Muse');
  assert.strictEqual(describeEntry(activityEntry({ method: 'fs.mkdir' })), 'Create folder: C:\\Users\\you\\Muse');
  assert.strictEqual(
    describeEntry(activityEntry({ method: 'app.launch', params: { target: 'notepad.exe' } })),
    'Launch: notepad.exe',
  );
  assert.strictEqual(describeEntry(activityEntry({ method: 'process.list', params: {} })), 'List running processes');
  assert.strictEqual(
    describeEntry(activityEntry({ method: 'process.kill', params: { pid: 42 } })),
    'Kill process pid 42',
  );
  assert.strictEqual(
    describeEntry(activityEntry({ method: 'shell.run', params: { summary: 'echo hi' } })),
    'Run command: echo hi',
  );
  assert.strictEqual(describeEntry(activityEntry({ method: null, params: {} })), 'Bridge call');
  assert.strictEqual(
    describeEntry({ ts: '2026-10-26T20:15:03.000Z', event: 'tailnet_listener_bound', address: '100.1.2.3:47631' }),
    'Remote access: Tailscale listener bound (100.1.2.3:47631)',
  );
});

test('0.4.0 activity: decision and outcome wording', () => {
  const lines = formatActivity([
    activityEntry({ decision: 'allow' }),
    activityEntry({ decision: 'ask-granted' }),
    activityEntry({ decision: 'ask-denied', outcome: 'refused', error: 'permission_denied' }),
    activityEntry({ decision: 'ask-timeout', outcome: 'refused', error: 'permission_timeout' }),
    activityEntry({ decision: 'deny', outcome: 'refused', error: 'permission_denied' }),
    activityEntry({ decision: 'auth-rejected', method: null, params: {}, outcome: 'refused', error: 'unauthorized' }),
    activityEntry({ decision: 'scope-refused', outcome: 'refused', error: 'scope_refused' }),
  ]);
  // Newest first: the array comes back reversed.
  assert.deepStrictEqual(
    lines.map((l) => l.decision),
    ['scope refused', 'auth rejected', 'denied by policy', 'timed out', 'denied', 'allowed', 'allowed by policy'],
  );
  assert.deepStrictEqual(
    lines.map((l) => l.outcome),
    ['scope_refused', 'unauthorized', 'permission_denied', 'permission_timeout', 'permission_denied', 'ok', 'ok'],
  );
});

test('0.4.0 activity: newest first, capped at the last 200 entries', () => {
  const entries = [];
  for (let i = 0; i < 250; i += 1) {
    entries.push(activityEntry({ params: { path: `folder-${i}` } }));
  }
  const lines = formatActivity(entries);
  assert.strictEqual(lines.length, 200);
  assert.strictEqual(lines[0].summary, 'List: folder-249', 'the newest entry leads');
  assert.strictEqual(lines[199].summary, 'List: folder-50', 'the oldest shown is #50 of 250');
  assert.strictEqual(formatActivity(entries, 3).length, 3, 'an explicit limit is honored');
  assert.deepStrictEqual(formatActivity([]), []);
});

test('0.4.0 activity: timestamps render as local time', () => {
  const ts = '2026-10-26T20:15:03.000Z';
  const d = new Date(ts);
  const pad = (n) => String(n).padStart(2, '0');
  const expected =
    `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ` +
    `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  assert.strictEqual(formatLocalTime(ts), expected);
  assert.strictEqual(formatActivity([activityEntry()])[0].time, expected);
});

test('0.4.0 activity: readBridgeActivity — missing file is empty; a real log round-trips', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'muse-activity-'));
  assert.deepStrictEqual(readBridgeActivity(root), [], 'no log file yet → no entries, no throw');
  const lines = [
    JSON.stringify(activityEntry({ method: 'fs.list' })),
    'garbage line',
    JSON.stringify(
      activityEntry({
        method: 'shell.run',
        params: { summary: 'echo hi' },
        decision: 'ask-granted',
        ts: '2026-10-26T21:00:00.000Z',
      }),
    ),
  ];
  fs.writeFileSync(path.join(root, 'bridge-audit.log'), lines.join('\n') + '\n');
  const formatted = readBridgeActivity(root);
  assert.strictEqual(formatted.length, 2, 'the garbage line is skipped');
  assert.strictEqual(formatted[0].summary, 'Run command: echo hi', 'newest first');
  assert.strictEqual(formatted[0].decision, 'allowed');
  assert.strictEqual(formatted[1].summary, 'List: C:\\Users\\you\\Muse');
});

// --- 0.5.0: the in-app updater ---------------------------------------------

const { execFileSync } = require('node:child_process');
const crypto = require('node:crypto');

function releaseJson(version, { withExe = true, withSums = true } = {}) {
  const assets = [];
  if (withExe) {
    assets.push({
      name: 'Muse-Portable.exe',
      browser_download_url: 'https://example.test/Muse-Portable.exe',
    });
  }
  if (withSums) {
    assets.push({ name: 'SHA256SUMS.txt', browser_download_url: 'https://example.test/SHA256SUMS.txt' });
  }
  return { tag_name: `v${version}`, assets };
}

const jsonFetch = (payload) => async () => ({ ok: true, status: 200, json: async () => payload });

// The signed portable in dist/ is the fixture for the real-cert
// tests (its name is version-free from 0.5.3: Muse-Portable.exe).
// Temp roots for updater runs live on the workspace disk (the
// fixture is ~109 MB; /tmp is a small tmpfs on the build VM).
const SIGNED_EXE_FIXTURE = path.join(__dirname, '..', 'dist', 'Muse-Portable.exe');
const REAL_CERT_DER = path.join(__dirname, '..', 'signing', 'muse-signing-cert.cer');
const haveUpdaterFixtures = fs.existsSync(SIGNED_EXE_FIXTURE) && fs.existsSync(REAL_CERT_DER);

function updaterTmpRoot(label) {
  return fs.mkdtempSync(path.join(__dirname, `updater-tmp-${label}-`));
}

test('0.5.0 semver: newer / equal / older', () => {
  assert.strictEqual(compareVersions('0.5.0', '0.4.0'), 1);
  assert.strictEqual(compareVersions('0.4.0', '0.5.0'), -1);
  assert.strictEqual(compareVersions('0.5.0', '0.5.0'), 0);
  assert.strictEqual(compareVersions('v1.0.0', '0.9.9'), 1, 'a leading v is accepted');
  assert.strictEqual(compareVersions('0.10.0', '0.9.0'), 1, 'numeric, not lexical');
  assert.strictEqual(isNewerVersion('0.5.1', '0.5.0'), true);
  assert.strictEqual(isNewerVersion('0.5.0', '0.5.0'), false, 'equal is not an update');
  assert.strictEqual(isNewerVersion('0.4.9', '0.5.0'), false, 'older is not an update');
  assert.strictEqual(isNewerVersion('garbage', '0.5.0'), false, 'unparseable is never newer');
});

test('0.5.0 semver: prerelease-ish tags', () => {
  assert.strictEqual(compareVersions('1.0.0-rc.1', '1.0.0'), -1, 'prerelease < release');
  assert.strictEqual(compareVersions('1.0.0', '1.0.0-rc.1'), 1);
  assert.strictEqual(compareVersions('1.0.0-alpha', '1.0.0-beta'), -1);
  assert.strictEqual(compareVersions('1.0.0-alpha.1', '1.0.0-alpha'), 1, 'longer prerelease list wins a prefix tie');
  assert.strictEqual(compareVersions('1.0.0-rc.2', '1.0.0-rc.10'), -1, 'numeric identifiers compare numerically');
  assert.strictEqual(compareVersions('1.0.0-rc.1', '1.0.0-rc.1'), 0);
  assert.deepStrictEqual(parseVersion('v2.3.4-beta.5'), { core: [2, 3, 4], pre: ['beta', '5'] });
  assert.strictEqual(parseVersion('1.0'), null);
  assert.strictEqual(parseVersion(''), null);
});

test('0.5.0 release parsing: a newer release with both assets is an offer', () => {
  const { offer, reason } = parseLatestRelease(releaseJson('0.6.0'), '0.5.0');
  assert.ok(offer, `expected an offer, got reason ${reason}`);
  assert.strictEqual(offer.version, '0.6.0');
  assert.strictEqual(offer.exeName, 'Muse-Portable.exe');
  assert.ok(offer.exeUrl.endsWith('Muse-Portable.exe'));
  assert.ok(offer.sumsUrl.endsWith('SHA256SUMS.txt'));
});

test('0.5.0 release parsing: not newer, missing asset, missing sums → no offer', () => {
  assert.strictEqual(parseLatestRelease(releaseJson('0.5.0'), '0.5.0').offer, null, 'same version');
  assert.strictEqual(parseLatestRelease(releaseJson('0.4.0'), '0.5.0').offer, null, 'older version');
  const noExe = parseLatestRelease(releaseJson('0.6.0', { withExe: false }), '0.5.0');
  assert.strictEqual(noExe.offer, null);
  assert.strictEqual(noExe.reason, 'missing-exe-asset');
  const noSums = parseLatestRelease(releaseJson('0.6.0', { withSums: false }), '0.5.0');
  assert.strictEqual(noSums.offer, null);
  assert.strictEqual(noSums.reason, 'missing-sums-asset');
  assert.strictEqual(parseLatestRelease({}, '0.5.0').offer, null, 'no tag at all');
  assert.strictEqual(parseLatestRelease(null, '0.5.0').offer, null);
});

test('0.5.0 sums parsing: plain and binary-marker lines', () => {
  const h1 = 'a'.repeat(64);
  const h2 = 'b'.repeat(64);
  const sums = parseSha256Sums(`${h1}  Muse-Portable.exe\n${h2} *Muse-win-unpacked-0.6.0.zip\r\n`);
  assert.strictEqual(sums.get('Muse-Portable.exe'), h1);
  assert.strictEqual(sums.get('Muse-win-unpacked-0.6.0.zip'), h2);
  assert.strictEqual(sums.get('nope.exe'), undefined);
});

test('0.5.0 checksum: a good file passes, a tampered file is rejected', async () => {
  const root = updaterTmpRoot('sum');
  try {
    const exePath = path.join(root, 'Muse-Portable.exe');
    const sumsPath = path.join(root, 'SHA256SUMS.txt');
    fs.writeFileSync(exePath, 'pretend exe bytes');
    const good = crypto.createHash('sha256').update('pretend exe bytes').digest('hex');
    fs.writeFileSync(sumsPath, `${good}  Muse-Portable.exe\n`);
    assert.strictEqual(await verifyChecksum(exePath, sumsPath, 'Muse-Portable.exe'), true);
    fs.writeFileSync(exePath, 'pretend exe bytes!');
    assert.strictEqual(await verifyChecksum(exePath, sumsPath, 'Muse-Portable.exe'), false, 'one byte flips the verdict');
    fs.writeFileSync(sumsPath, `${good}  some-other-name.exe\n`);
    assert.strictEqual(
      await verifyChecksum(exePath, sumsPath, 'Muse-Portable.exe'),
      false,
      'no line for this exe name → fail',
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('0.5.0 fingerprint: the pinned constant is the real signing cert', () => {
  if (!fs.existsSync(REAL_CERT_DER)) {
    console.log('     (skipped: signing/muse-signing-cert.cer not present)');
    return;
  }
  const der = fs.readFileSync(REAL_CERT_DER);
  assert.strictEqual(fingerprint256OfCertDer(der), PINNED_SIGNER_FINGERPRINT256);
});

test('0.5.0 fingerprint: a different cert does not match the pin', () => {
  let der;
  const root = updaterTmpRoot('cert');
  try {
    execFileSync(
      'openssl',
      ['req', '-x509', '-newkey', 'rsa:2048', '-keyout', path.join(root, 'k.pem'), '-out', path.join(root, 'c.pem'),
        '-days', '1', '-nodes', '-subj', '/CN=Definitely Not Muse'],
      { stdio: 'pipe' },
    );
    execFileSync('openssl', ['x509', '-in', path.join(root, 'c.pem'), '-outform', 'DER', '-out', path.join(root, 'c.der')], {
      stdio: 'pipe',
    });
    der = fs.readFileSync(path.join(root, 'c.der'));
  } catch {
    console.log('     (skipped: openssl unavailable)');
    return;
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
  assert.notStrictEqual(fingerprint256OfCertDer(der), PINNED_SIGNER_FINGERPRINT256);
});

test('0.5.0 fingerprint: extracted from the real signed exe; unsigned input → null', () => {
  if (!haveUpdaterFixtures) {
    console.log('     (skipped: signed dist fixture not present)');
    return;
  }
  const bytes = fs.readFileSync(SIGNED_EXE_FIXTURE);
  assert.strictEqual(signerFingerprint256FromExe(bytes), PINNED_SIGNER_FINGERPRINT256);
  assert.strictEqual(signerFingerprint256FromExe(Buffer.from('MZ not really an exe')), null);
  assert.strictEqual(signerFingerprint256FromExe(Buffer.alloc(0)), null);
});

test('0.5.0 verify composition: the real signed exe passes BOTH checks', async () => {
  if (!haveUpdaterFixtures) {
    console.log('     (skipped: signed dist fixture not present)');
    return;
  }
  const root = updaterTmpRoot('verify');
  try {
    const exePath = path.join(root, 'Muse-Portable.exe');
    fs.copyFileSync(SIGNED_EXE_FIXTURE, exePath);
    const hash = crypto.createHash('sha256').update(fs.readFileSync(exePath)).digest('hex');
    const sumsPath = path.join(root, 'SHA256SUMS.txt');
    fs.writeFileSync(sumsPath, `${hash}  Muse-Portable.exe\n`);
    const verdict = await verifyDownloadedUpdate({ exePath, sumsPath, exeName: 'Muse-Portable.exe' });
    assert.deepStrictEqual(verdict, { ok: true });
    // Tamper: flip a byte in the middle → checksum must catch it first.
    const buf = fs.readFileSync(exePath);
    buf[buf.length >> 1] ^= 0xff;
    fs.writeFileSync(exePath, buf);
    const tampered = await verifyDownloadedUpdate({ exePath, sumsPath, exeName: 'Muse-Portable.exe' });
    assert.deepStrictEqual(tampered, { ok: false, reason: 'checksum-mismatch' });
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('0.5.0 verify composition: a foreign signer is rejected even with a matching checksum', async () => {
  if (!haveUpdaterFixtures) {
    console.log('     (skipped: signed dist fixture not present)');
    return;
  }
  const root = updaterTmpRoot('foreign');
  try {
    // A throwaway cert + a re-signed copy of the fixture: its checksum
    // is honest (computed after signing), so only the fingerprint
    // check can — and must — refuse it.
    execFileSync(
      'openssl',
      ['req', '-x509', '-newkey', 'rsa:2048', '-keyout', path.join(root, 'k.pem'), '-out', path.join(root, 'c.pem'),
        '-days', '1', '-nodes', '-subj', '/CN=Foreign Signer'],
      { stdio: 'pipe' },
    );
    execFileSync(
      'openssl',
      ['pkcs12', '-export', '-out', path.join(root, 'other.pfx'), '-inkey', path.join(root, 'k.pem'),
        '-in', path.join(root, 'c.pem'), '-passout', 'pass:test'],
      { stdio: 'pipe' },
    );
    const exePath = path.join(root, 'Muse-Portable.exe');
    const rawCopy = path.join(root, 'raw.exe');
    fs.copyFileSync(SIGNED_EXE_FIXTURE, rawCopy);
    execFileSync(
      'osslsigncode',
      ['sign', '-pkcs12', path.join(root, 'other.pfx'), '-pass', 'test', '-in', rawCopy, '-out', exePath],
      { stdio: 'pipe' },
    );
    const hash = crypto.createHash('sha256').update(fs.readFileSync(exePath)).digest('hex');
    const sumsPath = path.join(root, 'SHA256SUMS.txt');
    fs.writeFileSync(sumsPath, `${hash}  Muse-Portable.exe\n`);
    const verdict = await verifyDownloadedUpdate({ exePath, sumsPath, exeName: 'Muse-Portable.exe' });
    assert.deepStrictEqual(verdict, { ok: false, reason: 'signer-mismatch' });
    assert.strictEqual(await verifyChecksum(exePath, sumsPath, 'Muse-Portable.exe'), true, 'the checksum alone would have passed');
  } catch (err) {
    if (err.code === 'ENOENT') {
      console.log('     (skipped: openssl/osslsigncode unavailable)');
      return;
    }
    throw err;
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

// A download stub: routes by URL suffix, writing canned content.
function stubDownload(writers) {
  return async (_fetchImpl, url, destPath) => {
    const write = writers.find(([suffix]) => url.endsWith(suffix));
    assert.ok(write, `unexpected download URL ${url}`);
    write[1](destPath);
  };
}

test('0.5.0 updater: fail-closed — a bad checksum blocks the offer, audits, deletes', async () => {
  const root = updaterTmpRoot('flow-badsum');
  const audits = [];
  let readyCalls = 0;
  try {
    const updater = createUpdater({
      currentVersion: '0.5.0',
      userDataPath: root,
      canApply: true,
      fetchImpl: jsonFetch(releaseJson('9.9.9')),
      downloadToFile: stubDownload([
        ['.exe', (dest) => fs.writeFileSync(dest, 'attacker bytes')],
        ['SHA256SUMS.txt', (dest) => fs.writeFileSync(dest, `${'0'.repeat(64)}  Muse-Portable.exe\n`)],
      ]),
      audit: (entry) => audits.push(entry),
      onReady: () => {
        readyCalls += 1;
      },
    });
    const state = await updater.check();
    assert.strictEqual(state.state, 'error');
    assert.strictEqual(state.error, 'checksum-mismatch');
    assert.strictEqual(readyCalls, 0, 'nothing is offered');
    assert.strictEqual(audits.length, 1, 'exactly one audit line');
    assert.strictEqual(audits[0].event, 'update_rejected');
    assert.strictEqual(audits[0].version, '9.9.9');
    assert.strictEqual(fs.existsSync(path.join(root, 'updates', '9.9.9')), false, 'the download is deleted');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('0.5.0 updater: fail-closed — an unsigned exe with an honest checksum is still blocked', async () => {
  const root = updaterTmpRoot('flow-unsigned');
  const audits = [];
  let readyCalls = 0;
  const body = Buffer.from('perfectly checksummed, totally unsigned');
  const honest = crypto.createHash('sha256').update(body).digest('hex');
  try {
    const updater = createUpdater({
      currentVersion: '0.5.0',
      userDataPath: root,
      canApply: true,
      fetchImpl: jsonFetch(releaseJson('9.9.9')),
      downloadToFile: stubDownload([
        ['.exe', (dest) => fs.writeFileSync(dest, body)],
        ['SHA256SUMS.txt', (dest) => fs.writeFileSync(dest, `${honest}  Muse-Portable.exe\n`)],
      ]),
      audit: (entry) => audits.push(entry),
      onReady: () => {
        readyCalls += 1;
      },
    });
    const state = await updater.check();
    assert.strictEqual(state.state, 'error');
    assert.strictEqual(state.error, 'no-valid-signature');
    assert.strictEqual(readyCalls, 0);
    assert.strictEqual(audits.length, 1);
    assert.strictEqual(audits[0].error, 'no-valid-signature');
    assert.strictEqual(fs.existsSync(path.join(root, 'updates', '9.9.9')), false);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('0.5.0 updater: not-newer release → up-to-date, no downloads', async () => {
  const root = updaterTmpRoot('flow-current');
  let downloads = 0;
  try {
    const updater = createUpdater({
      currentVersion: '0.5.0',
      userDataPath: root,
      fetchImpl: jsonFetch(releaseJson('0.5.0')),
      downloadToFile: async () => {
        downloads += 1;
      },
    });
    const state = await updater.check();
    assert.strictEqual(state.state, 'up-to-date');
    assert.strictEqual(downloads, 0);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('0.5.0 updater: verified download → ready; portable apply writes + launches the swap script (WMI, 0.5.2)', async () => {
  if (!haveUpdaterFixtures) {
    console.log('     (skipped: signed dist fixture not present)');
    return;
  }
  const root = updaterTmpRoot('flow-ready');
  const currentExe = path.join(root, 'Muse-Portable-0.5.0.exe');
  const readyInfos = [];
  const audits = [];
  let launchedScript = null;
  let spawnedScript = null;
  let applyStarted = false;
  try {
    const fixtureHash = crypto.createHash('sha256').update(fs.readFileSync(SIGNED_EXE_FIXTURE)).digest('hex');
    const updater = createUpdater({
      currentVersion: '0.5.0',
      userDataPath: root,
      canApply: true,
      getCurrentExePath: () => currentExe,
      getPid: () => 4242,
      fetchImpl: jsonFetch(releaseJson('9.9.9')),
      downloadToFile: stubDownload([
        ['.exe', (dest) => fs.copyFileSync(SIGNED_EXE_FIXTURE, dest)],
        ['SHA256SUMS.txt', (dest) => fs.writeFileSync(dest, `${fixtureHash}  Muse-Portable.exe\n`)],
      ]),
      audit: (entry) => audits.push(entry),
      onReady: (info) => readyInfos.push(info),
      launchSwapScript: (scriptPath) => {
        launchedScript = scriptPath;
      },
      spawnSwapScript: (scriptPath) => {
        spawnedScript = scriptPath;
      },
      onApplyStarted: () => {
        applyStarted = true;
      },
    });
    const state = await updater.check();
    assert.strictEqual(state.state, 'ready');
    assert.strictEqual(state.pendingVersion, '9.9.9');
    assert.strictEqual(readyInfos.length, 1, 'the prompt fires exactly once');
    assert.strictEqual(readyInfos[0].canApply, true);

    const applied = updater.apply();
    assert.deepStrictEqual(applied, { ok: true });
    assert.ok(launchedScript && fs.existsSync(launchedScript), 'the swap script was written and launched via WMI');
    assert.strictEqual(spawnedScript, null, 'the direct-spawn fallback is not used when WMI succeeds');
    const script = fs.readFileSync(launchedScript, 'utf8');
    assert.ok(script.includes('$targetPid = 4242'), 'the script waits for this PID');
    assert.ok(script.includes(`$targetExe = '${currentExe}'`), 'the target path is quoted');
    assert.ok(script.includes('Wait-Process'), 'waits for exit');
    assert.ok(script.includes('Copy-Item'), 'replaces the exe');
    assert.ok(script.includes('Start-Process'), 'relaunches');
    assert.strictEqual(applyStarted, true, 'the app is told to quit');
    const applyAudit = audits.find((a) => a.event === 'update_apply_started');
    assert.ok(applyAudit, 'the apply is audited');
    assert.strictEqual(applyAudit.version, '9.9.9');
    assert.strictEqual(applyAudit.via, 'wmi', 'the audit records the WMI launch path');
    assert.strictEqual(applyAudit.outcome, 'started');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('0.5.0 updater: non-portable runs verify but cannot apply', async () => {
  if (!haveUpdaterFixtures) {
    console.log('     (skipped: signed dist fixture not present)');
    return;
  }
  const root = updaterTmpRoot('flow-nonportable');
  const readyInfos = [];
  try {
    const fixtureHash = crypto.createHash('sha256').update(fs.readFileSync(SIGNED_EXE_FIXTURE)).digest('hex');
    const updater = createUpdater({
      currentVersion: '0.5.0',
      userDataPath: root,
      canApply: false,
      fetchImpl: jsonFetch(releaseJson('9.9.9')),
      downloadToFile: stubDownload([
        ['.exe', (dest) => fs.copyFileSync(SIGNED_EXE_FIXTURE, dest)],
        ['SHA256SUMS.txt', (dest) => fs.writeFileSync(dest, `${fixtureHash}  Muse-Portable.exe\n`)],
      ]),
      onReady: (info) => readyInfos.push(info),
    });
    const state = await updater.check();
    assert.strictEqual(state.state, 'ready', 'download + verify still work');
    assert.strictEqual(readyInfos[0].canApply, false, 'the prompt is told to disable the action');
    assert.deepStrictEqual(updater.apply(), { ok: false, reason: 'not-portable' });
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('0.5.0 swap script: quoting survives apostrophes and spaces', () => {
  assert.strictEqual(psQuote("C:\\a b\\it's.exe"), "'C:\\a b\\it''s.exe'");
  const script = buildSwapScript({
    pid: 7,
    currentExePath: "C:\\Users\\Some One\\Muse-Portable-0.5.0.exe",
    newExePath: "C:\\Users\\Some One\\AppData\\updates\\0.6.0\\Muse-Portable-0.6.0.exe",
  });
  assert.ok(script.includes("$targetExe = 'C:\\Users\\Some One\\Muse-Portable-0.5.0.exe'"));
  assert.ok(script.includes("$newExe = 'C:\\Users\\Some One\\AppData\\updates\\0.6.0\\Muse-Portable-0.6.0.exe'"));
  assert.ok(script.includes('Wait-Process -Id $targetPid'));
  assert.ok(script.includes('Remove-Item -LiteralPath $PSCommandPath'), 'the script cleans up after itself');
});

test('0.5.0 updater: cleanupStaleArtifacts removes a leftover swap script', () => {
  const root = updaterTmpRoot('flow-cleanup');
  try {
    const updatesDir = path.join(root, 'updates');
    fs.mkdirSync(updatesDir, { recursive: true });
    const script = path.join(updatesDir, 'apply-update.ps1');
    fs.writeFileSync(script, 'leftover');
    const updater = createUpdater({ currentVersion: '0.5.0', userDataPath: root });
    updater.cleanupStaleArtifacts();
    assert.strictEqual(fs.existsSync(script), false);
    updater.cleanupStaleArtifacts(); // idempotent — no throw when already gone
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

// --- 0.5.2: the updater apply fix ------------------------------------------

test('0.5.2 swap script: every stage is logged and the target always relaunches', () => {
  const script = buildSwapScript({
    pid: 99,
    currentExePath: 'E:\\Tools\\Muse Desktop\\Muse-Portable-0.5.1.exe',
    newExePath: 'C:\\Users\\Some One\\AppData\\Roaming\\Muse\\updates\\0.5.2\\Muse-Portable-0.5.2.exe',
    logPath: 'C:\\Users\\Some One\\AppData\\Roaming\\Muse\\updates\\apply-update.log',
    targetVersion: '0.5.2',
  });
  assert.ok(script.includes("$targetExe = 'E:\\Tools\\Muse Desktop\\Muse-Portable-0.5.1.exe'"), 'spaced target path quoted');
  assert.ok(script.includes("$logFile = 'C:\\Users\\Some One\\AppData\\Roaming\\Muse\\updates\\apply-update.log'"));
  assert.ok(script.includes("$targetVersion = '0.5.2'"));
  assert.ok(script.includes('Add-Content -LiteralPath $logFile'), 'the logger appends to the apply log');
  for (const step of [
    'started version=$targetVersion',
    'waited-pid-gone',
    'copy-attempt-failed attempt=$attempts error=',
    'copy-ok attempts=$attempts',
    'copy-failed attempts=$attempts',
    'relaunch-issued',
    'done result=success version=$targetVersion',
    'done result=failed version=$targetVersion',
  ]) {
    assert.ok(script.includes(step), `the script logs: ${step}`);
  }
  assert.ok(script.includes(`for ($i = 0; $i -lt ${MAX_COPY_ATTEMPTS}; $i++)`), 'the retry loop uses the shared attempt budget');
  assert.ok(MAX_COPY_ATTEMPTS >= 100, 'the copy window is ~60 s, not the old ~20 s');
  const copyFailedAt = script.indexOf('copy-failed attempts=');
  const relaunchAt = script.indexOf('Start-Process -FilePath $targetExe');
  assert.ok(relaunchAt > copyFailedAt, 'Start-Process sits after the copy loop — it runs even when the copy failed');
  const removeDownloadAt = script.indexOf('Remove-Item -LiteralPath $newExe');
  assert.ok(removeDownloadAt > relaunchAt, 'the verified download is removed only after the relaunch');
  assert.ok(script.indexOf('if ($copied) {', relaunchAt) > relaunchAt, '...and only inside the success branch');
  assert.ok(script.includes('Remove-Item -LiteralPath $PSCommandPath'), 'the script still cleans up after itself');
});

test('0.5.2 WMI launch command: exact quoting for paths with spaces (and apostrophes)', () => {
  const spaced = 'E:\\Tools\\Muse Desktop\\updates\\apply-update.ps1';
  assert.strictEqual(
    buildWmiLaunchCommand(spaced),
    "$r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = " +
      `'powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "E:\\Tools\\Muse Desktop\\updates\\apply-update.ps1"' }; ` +
      'if ($null -eq $r -or $r.ReturnValue -ne 0) { exit 1 }',
    'the script path is double-quoted inside the WMI command line, single-quoted outside',
  );
  const apostrophe = buildWmiLaunchCommand("C:\\Users\\It's Me\\updates\\apply-update.ps1");
  assert.ok(
    apostrophe.includes(`-File "C:\\Users\\It''s Me\\updates\\apply-update.ps1"`),
    "an apostrophe in the path is doubled for the PowerShell string literal",
  );
  assert.ok(apostrophe.includes('Win32_Process'), 'the process is created through WMI');
});

test('0.5.2 apply: a WMI launch failure falls back to the direct spawn and audits via', async () => {
  if (!haveUpdaterFixtures) {
    console.log('     (skipped: signed dist fixture not present)');
    return;
  }
  const root = updaterTmpRoot('flow-fallback');
  const audits = [];
  let spawnedScript = null;
  let applyStarted = false;
  try {
    const fixtureHash = crypto.createHash('sha256').update(fs.readFileSync(SIGNED_EXE_FIXTURE)).digest('hex');
    const updater = createUpdater({
      currentVersion: '0.5.1',
      userDataPath: root,
      canApply: true,
      getCurrentExePath: () => path.join(root, 'Muse-Portable-0.5.1.exe'),
      fetchImpl: jsonFetch(releaseJson('9.9.9')),
      downloadToFile: stubDownload([
        ['.exe', (dest) => fs.copyFileSync(SIGNED_EXE_FIXTURE, dest)],
        ['SHA256SUMS.txt', (dest) => fs.writeFileSync(dest, `${fixtureHash}  Muse-Portable.exe\n`)],
      ]),
      audit: (entry) => audits.push(entry),
      launchSwapScript: () => {
        throw new Error('WMI unavailable');
      },
      spawnSwapScript: (scriptPath) => {
        spawnedScript = scriptPath;
      },
      onApplyStarted: () => {
        applyStarted = true;
      },
    });
    const state = await updater.check();
    assert.strictEqual(state.state, 'ready');
    assert.deepStrictEqual(updater.apply(), { ok: true }, 'a failed WMI launch does not block the apply');
    assert.ok(spawnedScript && fs.existsSync(spawnedScript), 'the fallback spawn ran the script');
    const applyAudit = audits.find((a) => a.event === 'update_apply_started');
    assert.ok(applyAudit, 'the fallback apply is audited');
    assert.strictEqual(applyAudit.via, 'spawn-fallback', 'the audit names the fallback path');
    assert.strictEqual(applyStarted, true, 'the app is still told to quit');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('0.5.2 apply: refuses with no verified update pending', () => {
  const root = updaterTmpRoot('flow-nopending');
  try {
    const updater = createUpdater({ currentVersion: '0.5.2', userDataPath: root, canApply: true });
    assert.deepStrictEqual(updater.apply(), { ok: false, reason: 'no-verified-update' });
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

const APPLY_LOG_HEADER = '2026-10-27T03:00:00.0000000-05:00';
function applyLogLines(...steps) {
  return steps.map((s) => `${APPLY_LOG_HEADER} ${s}`).join('\r\n') + '\r\n';
}

test('0.5.2 apply log parsing: success counts only when the logged version is what runs now', () => {
  const success = applyLogLines(
    'started version=0.5.2 pid=4242',
    'waited-pid-gone',
    'copy-ok attempts=3',
    'relaunch-issued',
    'done result=success version=0.5.2',
  );
  assert.deepStrictEqual(parseApplyLog(success, '0.5.2'), { result: 'success', version: '0.5.2' });
  assert.strictEqual(parseApplyLog(success, '0.5.3'), null, 'a past success is stale news on a newer build');
  assert.strictEqual(parseApplyLog(success, '0.5.1'), null, '...and on an older one (manual revert)');
});

test('0.5.2 apply log parsing: failed counts only while the failed version is still ahead', () => {
  const failed = applyLogLines(
    'started version=0.5.2 pid=4242',
    'waited-pid-gone',
    'copy-attempt-failed attempt=1 error=The process cannot access the file',
    'copy-failed attempts=120',
    'relaunch-issued',
    'done result=failed version=0.5.2',
  );
  assert.deepStrictEqual(parseApplyLog(failed, '0.5.1'), { result: 'failed', version: '0.5.2' });
  assert.strictEqual(parseApplyLog(failed, '0.5.2'), null, 'already on the version (manual install) — no failure to report');
  const stalled = applyLogLines('started version=0.5.2 pid=4242', 'copy-failed attempts=120');
  assert.deepStrictEqual(
    parseApplyLog(stalled, '0.5.1'),
    { result: 'failed', version: '0.5.2' },
    'copy-failed without a done line still reads as failed',
  );
});

test('0.5.2 apply log parsing: a started-only run is unknown (the 0.5.1 failure shape)', () => {
  const killed = applyLogLines('started version=0.5.1 pid=4242');
  assert.deepStrictEqual(parseApplyLog(killed, '0.5.0'), { result: 'unknown', version: '0.5.1' });
  const killedMidCopy = applyLogLines(
    'started version=0.5.3 pid=4242',
    'waited-pid-gone',
    'copy-attempt-failed attempt=1 error=locked',
  );
  assert.deepStrictEqual(parseApplyLog(killedMidCopy, '0.5.2'), { result: 'unknown', version: '0.5.3' });
  assert.strictEqual(parseApplyLog(killed, '0.5.2'), null, 'an ancient killed run is stale once we are past its version');
});

test('0.5.2 apply log parsing: last run wins; garbage and truncation never throw', () => {
  const twoRuns =
    applyLogLines('started version=0.5.1 pid=1', 'copy-ok attempts=1', 'done result=success version=0.5.1') +
    applyLogLines('started version=0.5.2 pid=2', 'copy-failed attempts=120', 'done result=failed version=0.5.2');
  assert.deepStrictEqual(parseApplyLog(twoRuns, '0.5.1'), { result: 'failed', version: '0.5.2' }, 'the second run decides');
  assert.strictEqual(parseApplyLog('', '0.5.2'), null);
  assert.strictEqual(parseApplyLog(null, '0.5.2'), null);
  assert.strictEqual(parseApplyLog('not a log at all\n???\n', '0.5.2'), null);
  assert.deepStrictEqual(
    parseApplyLog('2026-10-27T03:00:00 started version=0.5.2 pid=4242\npartial line, no end', '0.5.1'),
    { result: 'unknown', version: '0.5.2' },
    'a log truncated mid-run parses as unknown, not a crash',
  );
});

test('0.5.2 apply outcome: getLastApplyOutcome reads the log; cleanup keeps the log, removes the script', () => {
  const root = updaterTmpRoot('outcome');
  try {
    const updatesDir = path.join(root, 'updates');
    fs.mkdirSync(updatesDir, { recursive: true });
    const logPath = path.join(updatesDir, APPLY_LOG_NAME);
    fs.writeFileSync(
      logPath,
      applyLogLines('started version=0.5.3 pid=7', 'copy-ok attempts=2', 'done result=success version=0.5.3'),
    );
    const scriptPath = path.join(updatesDir, 'apply-update.ps1');
    fs.writeFileSync(scriptPath, 'leftover');

    const updater = createUpdater({ currentVersion: '0.5.3', userDataPath: root });
    const outcome = updater.getLastApplyOutcome();
    assert.deepStrictEqual(outcome, { result: 'success', version: '0.5.3', logPath });
    assert.strictEqual(updater.getState().lastApplyOutcome.result, 'success', 'the outcome rides the state the settings row reads');

    updater.cleanupStaleArtifacts();
    assert.strictEqual(fs.existsSync(scriptPath), false, 'the stale script is removed');
    assert.strictEqual(fs.existsSync(logPath), true, 'the apply log is NOT removed — it is the diagnostic record');
    assert.strictEqual(updater.getLastApplyOutcome().result, 'success', 'the outcome is still readable after cleanup');

    const bareRoot = updaterTmpRoot('outcome-bare');
    try {
      const bare = createUpdater({ currentVersion: '0.5.2', userDataPath: bareRoot });
      assert.strictEqual(bare.getLastApplyOutcome(), null, 'no log → no outcome');
    } finally {
      fs.rmSync(bareRoot, { recursive: true, force: true });
    }
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('0.5.2 apply outcome label: one line, or silence', () => {
  assert.strictEqual(applyOutcomeLabel({ result: 'success', version: '0.5.2' }), 'Updated to 0.5.2');
  assert.strictEqual(applyOutcomeLabel({ result: 'failed', version: '0.5.2' }), 'Update failed');
  assert.strictEqual(applyOutcomeLabel({ result: 'unknown', version: '0.5.2' }), '');
  assert.strictEqual(applyOutcomeLabel(null), '');
  assert.strictEqual(applyOutcomeLabel(undefined), '');
});

test('0.5.2 activity: the apply-start audit entry renders as a plain line', () => {
  const lines = formatActivity([
    { ts: '2026-10-27T03:00:00.000Z', event: 'update_apply_started', version: '0.5.2', decision: 'update-apply', outcome: 'started' },
  ]);
  assert.strictEqual(lines.length, 1);
  assert.strictEqual(lines[0].summary, 'Update apply started: 0.5.2');
  assert.strictEqual(lines[0].outcome, 'started');
});

// --- 0.5.1: screen.capture -------------------------------------------------

// A NativeImage-shaped stub: getSize/isEmpty/resize/toPNG, with resize
// calls optionally recorded so tests can prove "never upscale".
function fakeImage(width, height, track) {
  const img = {
    width,
    height,
    getSize() {
      return { width: img.width, height: img.height };
    },
    isEmpty() {
      return img.width === 0 || img.height === 0;
    },
    resize({ width: w, height: h }) {
      if (track) track.push({ width: w, height: h });
      return fakeImage(w, h, track);
    },
    toPNG() {
      return Buffer.from(`PNG:${img.width}x${img.height}`);
    },
  };
  return img;
}

// A desktopCapturer.getSources-shaped stub over the given thumbnails.
function fakeGetSources(images, seenOptions) {
  return async (options) => {
    if (seenOptions) seenOptions.push(options);
    return images.map((thumbnail, i) => ({ id: `screen:${i}`, name: `Display ${i + 1}`, thumbnail }));
  };
}

async function expectCaptureError(promise, code) {
  try {
    await promise;
  } catch (err) {
    assert.ok(err instanceof ScreenCaptureError, `expected ScreenCaptureError, got: ${err && err.message}`);
    assert.strictEqual(err.code, code, `expected capture error ${code}, got ${err.code}`);
    return err;
  }
  assert.fail(`expected ScreenCaptureError ${code}, but the call succeeded`);
}

const CAPTURE_FIXTURE = { format: 'png', width: 2560, height: 1440, displayIndex: 0, dataBase64: 'AAAA' };

test('0.5.1 permissions: screen.capture defaults to ask and is standard-family (no never-allow)', () => {
  assert.strictEqual(DEFAULT_POLICY.capabilities['screen.capture'], 'ask');
  assert.strictEqual(NEVER_ALLOW_CAPABILITIES.has('screen.capture'), false);
  assert.strictEqual(effectivePolicyMode('screen.capture', 'allow'), 'allow', 'a stored allow is NOT coerced');
  assert.deepStrictEqual(sanitizePromptAnswer('screen.capture', { allowed: true, alwaysAllow: true }), {
    allowed: true,
    alwaysAllow: true,
  });
  // An existing policy file without the key gains the default via the
  // loadPolicy defaults-merge (makeEnv's file has no screen.capture).
  const env = makeEnv();
  assert.strictEqual(loadPolicy(env.userDataPath).capabilities['screen.capture'], 'ask');
});

test('0.5.1 screen.capture: a stored "allow" runs without prompting (contrast: shell.run)', async () => {
  const env = makeEnv({ 'screen.capture': 'allow' });
  let prompts = 0;
  const rpc = makeHandler(env, {
    prompt: async () => {
      prompts += 1;
      return { allowed: true };
    },
    captureScreen: async () => CAPTURE_FIXTURE,
  });
  const result = await rpc('screen.capture', {});
  assert.deepStrictEqual(result, CAPTURE_FIXTURE);
  assert.strictEqual(prompts, 0, 'stored allow must skip the prompt for screen.capture');
  const last = env.auditEntries().at(-1);
  assert.strictEqual(last.decision, 'allow');
  assert.strictEqual(last.params.width, 2560);
  assert.strictEqual(last.params.height, 1440);
});

test('0.5.1 screen.capture: ask + always-allow persists and stops prompting', async () => {
  const env = makeEnv(); // no screen.capture key on disk → default "ask"
  let prompts = 0;
  const rpc = makeHandler(env, {
    prompt: async () => {
      prompts += 1;
      return { allowed: true, alwaysAllow: true };
    },
    captureScreen: async () => CAPTURE_FIXTURE,
  });
  await rpc('screen.capture', {});
  assert.strictEqual(env.readPolicy().capabilities['screen.capture'], 'allow', 'always-allow persisted');
  await rpc('screen.capture', {});
  assert.strictEqual(prompts, 1, 'the second call runs on the stored allow');
  assert.deepStrictEqual(
    env.auditEntries().map((e) => e.decision),
    ['ask-granted', 'allow'],
  );
});

test('0.5.1 screen.capture: prompt payload is the one-line summary, always-allow offered', async () => {
  const env = makeEnv();
  const seen = [];
  const rpc = makeHandler(env, {
    prompt: async (req) => {
      seen.push(req);
      return { allowed: true };
    },
    captureScreen: async () => CAPTURE_FIXTURE,
  });
  await rpc('screen.capture', {});
  assert.strictEqual(seen[0].capability, 'screen.capture');
  assert.strictEqual(seen[0].detail, 'Take a screenshot — display 1, up to 2560px wide');
  assert.strictEqual(seen[0].canAlwaysAllow, true);
  await rpc('screen.capture', { displayIndex: 1, maxWidth: 1920 });
  assert.strictEqual(seen[1].detail, 'Take a screenshot — display 2, up to 1920px wide');
  assert.strictEqual(describeCaptureRequest({}), 'Take a screenshot — display 1, up to 2560px wide');
});

test('0.5.1 screen.capture: invalid params fail before the gate (no prompt, no capture)', async () => {
  const env = makeEnv({ 'screen.capture': 'ask' });
  let prompts = 0;
  let captures = 0;
  const rpc = makeHandler(env, {
    prompt: async () => {
      prompts += 1;
      return { allowed: true };
    },
    captureScreen: async () => {
      captures += 1;
      return CAPTURE_FIXTURE;
    },
  });
  for (const params of [
    { displayIndex: -1 },
    { displayIndex: 1.5 },
    { displayIndex: '0' },
    { maxWidth: 0 },
    { maxWidth: -100 },
    { maxWidth: 99999 },
    { maxWidth: 'wide' },
  ]) {
    await expectRpcError(rpc('screen.capture', params), 'invalid_params');
  }
  assert.strictEqual(prompts, 0, 'an invalid request must never reach the prompt');
  assert.strictEqual(captures, 0);
});

test('0.5.1 screen.capture: moving state refuses with storage_moving', async () => {
  const env = makeEnv({ 'screen.capture': 'allow' });
  let captures = 0;
  const rpc = makeHandler(env, {
    isMoving: () => true,
    captureScreen: async () => {
      captures += 1;
      return CAPTURE_FIXTURE;
    },
  });
  await expectRpcError(rpc('screen.capture', {}), 'storage_moving');
  assert.strictEqual(captures, 0);
  assert.strictEqual(env.auditEntries().at(-1).decision, 'storage-moving');
});

test('0.5.1 screen.capture: out-of-range display surfaces as invalid_params after the gate', async () => {
  const env = makeEnv({ 'screen.capture': 'allow' });
  const rpc = makeHandler(env, {
    captureScreen: createScreenCapture({ getSources: fakeGetSources([fakeImage(1920, 1080)]) }),
  });
  await expectRpcError(rpc('screen.capture', { displayIndex: 5 }), 'invalid_params');
  const last = env.auditEntries().at(-1);
  assert.strictEqual(last.outcome, 'error');
  assert.strictEqual(last.error, 'invalid_params');
});

test('0.5.1 screen.capture: audit carries dimensions and never image data', async () => {
  const env = makeEnv({ 'screen.capture': 'allow' });
  const rpc = makeHandler(env, {
    captureScreen: createScreenCapture({ getSources: fakeGetSources([fakeImage(4000, 2000)]) }),
  });
  const result = await rpc('screen.capture', {});
  assert.deepStrictEqual(
    { format: result.format, width: result.width, height: result.height, displayIndex: result.displayIndex },
    { format: 'png', width: 2560, height: 1280, displayIndex: 0 },
  );
  const rawLog = fs.readFileSync(path.join(env.userDataPath, 'bridge-audit.log'), 'utf8');
  assert.ok(!rawLog.includes(result.dataBase64), 'the base64 image must never reach the audit log');
  assert.ok(!rawLog.includes('dataBase64'), 'no image-data field in the audit entry');
  const entry = env.auditEntries().at(-1);
  assert.strictEqual(entry.params.width, 2560);
  assert.strictEqual(entry.params.height, 1280);
});

test('0.5.1 capture: a wide source is downscaled to maxWidth, proportionally', async () => {
  const capture = createScreenCapture({ getSources: fakeGetSources([fakeImage(5120, 2880)]) });
  const result = await capture({});
  assert.strictEqual(result.format, 'png');
  assert.strictEqual(result.width, 2560);
  assert.strictEqual(result.height, 1440);
  assert.strictEqual(result.displayIndex, 0);
  assert.strictEqual(Buffer.from(result.dataBase64, 'base64').toString(), 'PNG:2560x1440');
});

test('0.5.1 capture: a custom maxWidth is honored', async () => {
  const capture = createScreenCapture({ getSources: fakeGetSources([fakeImage(3000, 1500)]) });
  const result = await capture({ maxWidth: 1200 });
  assert.strictEqual(result.width, 1200);
  assert.strictEqual(result.height, 600);
});

test('0.5.1 capture: a narrower source is never upscaled (resize untouched)', async () => {
  const track = [];
  const capture = createScreenCapture({ getSources: fakeGetSources([fakeImage(1920, 1080, track)]) });
  const result = await capture({});
  assert.strictEqual(result.width, 1920);
  assert.strictEqual(result.height, 1080);
  assert.deepStrictEqual(track, [], 'no resize call when the source already fits');
  // Exactly maxWidth wide is also left alone.
  const exact = createScreenCapture({ getSources: fakeGetSources([fakeImage(2560, 1440, track)]) });
  await exact({});
  assert.deepStrictEqual(track, []);
});

test('0.5.1 capture: displayIndex selects the source; capturer asked for screens only', async () => {
  const seenOptions = [];
  const capture = createScreenCapture({
    getSources: fakeGetSources([fakeImage(1000, 500), fakeImage(2000, 1000)], seenOptions),
  });
  const result = await capture({ displayIndex: 1 });
  assert.strictEqual(result.displayIndex, 1);
  assert.strictEqual(result.width, 2000);
  assert.strictEqual(result.height, 1000);
  assert.deepStrictEqual(seenOptions[0].types, ['screen']);
  assert.deepStrictEqual(seenOptions[0].thumbnailSize, { width: 2560, height: 2560 });
});

test('0.5.1 capture: out-of-range display and no-screens are clean errors', async () => {
  const one = createScreenCapture({ getSources: fakeGetSources([fakeImage(1920, 1080)]) });
  await expectCaptureError(one({ displayIndex: 3 }), 'invalid_params');
  const none = createScreenCapture({ getSources: async () => [] });
  await expectCaptureError(none({}), 'no_screens');
  const broken = createScreenCapture({
    getSources: async () => {
      throw new Error('capturer exploded');
    },
  });
  await expectCaptureError(broken({}), 'tool_failed');
});

test('0.5.1 capture: module-level param validation (defaults, bounds, types)', async () => {
  assert.deepStrictEqual(validateCaptureParams({}), { displayIndex: 0, maxWidth: 2560 });
  assert.deepStrictEqual(validateCaptureParams({ displayIndex: 2, maxWidth: 800 }), { displayIndex: 2, maxWidth: 800 });
  const capture = createScreenCapture({ getSources: fakeGetSources([fakeImage(640, 480)]) });
  for (const params of [
    { displayIndex: -1 },
    { displayIndex: 0.5 },
    { displayIndex: '0' },
    { maxWidth: 0 },
    { maxWidth: 15 },
    { maxWidth: 16385 },
    { maxWidth: 2560.5 },
    { maxWidth: 'wide' },
  ]) {
    await expectCaptureError(capture(params), 'invalid_params');
  }
});

test('0.5.1 capture: scaling math', () => {
  assert.deepStrictEqual(computeScaledSize(5120, 2880, 2560), { width: 2560, height: 1440, scaled: true });
  assert.deepStrictEqual(computeScaledSize(1920, 1080, 2560), { width: 1920, height: 1080, scaled: false });
  assert.deepStrictEqual(computeScaledSize(2560, 1440, 2560), { width: 2560, height: 1440, scaled: false });
  assert.deepStrictEqual(computeScaledSize(1080, 1920, 800), { width: 800, height: 1422, scaled: true });
  assert.deepStrictEqual(computeScaledSize(3840, 2160, 1000), { width: 1000, height: 563, scaled: true });
});

test('0.5.1 activity: screenshot describe line', () => {
  assert.strictEqual(
    describeEntry({ method: 'screen.capture', params: { width: 2560, height: 1440 } }),
    'Screenshot: 2560x1440',
  );
  assert.strictEqual(describeEntry({ method: 'screen.capture', params: {} }), 'Screenshot');
});

// --- 0.5.3: screen.list ------------------------------------------------------

// A fake display provider: raw entries ({ width, height, scaleFactor,
// isPrimary }), already in capture-source order per the contract.
function fakeGetDisplays(rawDisplays) {
  return async () => rawDisplays;
}

// The shared fake monitor set: the primary is deliberately NOT first,
// and the scale factors differ per display.
const FAKE_MONITORS = [
  { width: 1920, height: 1080, scaleFactor: 1, isPrimary: false },
  { width: 2560, height: 1440, scaleFactor: 1.25, isPrimary: true },
  { width: 1080, height: 1920, scaleFactor: 2, isPrimary: false },
];

test('0.5.3 screen.list: shape from a fake provider (primary not first, scaleFactor passthrough)', async () => {
  const list = createScreenList({ getDisplays: fakeGetDisplays(FAKE_MONITORS) });
  const result = await list();
  assert.deepStrictEqual(result, {
    displays: [
      { index: 0, width: 1920, height: 1080, scaleFactor: 1, isPrimary: false },
      { index: 1, width: 2560, height: 1440, scaleFactor: 1.25, isPrimary: true },
      { index: 2, width: 1080, height: 1920, scaleFactor: 2, isPrimary: false },
    ],
    count: 3,
  });
});

test('0.5.3 screen.list: normalization defaults (scaleFactor 1, isPrimary coerced)', () => {
  assert.deepStrictEqual(
    normalizeDisplays([{ width: 800, height: 600 }, { width: 1024, height: 768, scaleFactor: 0, isPrimary: 1 }]),
    [
      { index: 0, width: 800, height: 600, scaleFactor: 1, isPrimary: false },
      { index: 1, width: 1024, height: 768, scaleFactor: 1, isPrimary: true },
    ],
  );
});

test('0.5.3 screen.list: provider failures are clean errors', async () => {
  const none = createScreenList({ getDisplays: fakeGetDisplays([]) });
  await expectCaptureError(none(), 'no_screens');
  const broken = createScreenList({
    getDisplays: async () => {
      throw new Error('screen module exploded');
    },
  });
  await expectCaptureError(broken(), 'tool_failed');
  const badSize = createScreenList({ getDisplays: fakeGetDisplays([{ width: 0, height: 1080 }]) });
  await expectCaptureError(badSize(), 'tool_failed');
  const notAList = createScreenList({ getDisplays: async () => null });
  await expectCaptureError(notAList(), 'tool_failed');
});

test('0.5.3 screen.list: indexes align with the capture source ordering', async () => {
  // One shared fake enumeration feeds both factories, in the same
  // order: that order IS the alignment contract the module encodes
  // (and main.js enforces against the real enumerations by id).
  const list = createScreenList({ getDisplays: fakeGetDisplays(FAKE_MONITORS) });
  const capture = createScreenCapture({
    getSources: fakeGetSources(FAKE_MONITORS.map((m) => fakeImage(m.width, m.height))),
  });
  const { displays } = await list();
  for (const display of displays) {
    const shot = await capture({ displayIndex: display.index });
    assert.strictEqual(shot.displayIndex, display.index);
    assert.strictEqual(shot.width, display.width, `display ${display.index} width lines up`);
    assert.strictEqual(shot.height, display.height, `display ${display.index} height lines up`);
  }
});

test('0.5.3 screen.list: shares the screen.capture capability (no new policy key)', () => {
  assert.strictEqual(METHOD_CAPABILITY['screen.list'], 'screen.capture');
  assert.strictEqual('screen.list' in DEFAULT_POLICY.capabilities, false, 'no screen.list key in the policy');
  assert.strictEqual(describeListRequest(), 'List displays');
});

test('0.5.3 screen.list: a stored "allow" for screen.capture runs without prompting', async () => {
  const env = makeEnv({ 'screen.capture': 'allow' });
  let prompts = 0;
  const rpc = makeHandler(env, {
    prompt: async () => {
      prompts += 1;
      return { allowed: true };
    },
    listScreens: createScreenList({ getDisplays: fakeGetDisplays(FAKE_MONITORS) }),
  });
  const result = await rpc('screen.list', {});
  assert.strictEqual(result.count, 3);
  assert.strictEqual(result.displays[1].isPrimary, true);
  assert.strictEqual(prompts, 0, 'stored allow must skip the prompt for screen.list too');
  const last = env.auditEntries().at(-1);
  assert.strictEqual(last.method, 'screen.list');
  assert.strictEqual(last.decision, 'allow');
  assert.strictEqual(last.params.count, 3);
});

test('0.5.3 screen.list: ask prompts once with the one-line summary; denial refuses', async () => {
  const env = makeEnv(); // screen.capture defaults to "ask"
  const seen = [];
  const rpc = makeHandler(env, {
    prompt: async (req) => {
      seen.push(req);
      return { allowed: true };
    },
    listScreens: createScreenList({ getDisplays: fakeGetDisplays(FAKE_MONITORS) }),
  });
  await rpc('screen.list', {});
  assert.strictEqual(seen.length, 1);
  assert.strictEqual(seen[0].capability, 'screen.capture');
  assert.strictEqual(seen[0].method, 'screen.list');
  assert.strictEqual(seen[0].detail, 'List displays');
  assert.strictEqual(seen[0].canAlwaysAllow, true);
  assert.strictEqual(env.auditEntries().at(-1).decision, 'ask-granted');

  const denyEnv = makeEnv();
  const denyRpc = makeHandler(denyEnv, {
    prompt: async () => ({ allowed: false }),
    listScreens: createScreenList({ getDisplays: fakeGetDisplays(FAKE_MONITORS) }),
  });
  await expectRpcError(denyRpc('screen.list', {}), 'permission_denied');
});

test('0.5.3 screen.list: moving state refuses with storage_moving', async () => {
  const env = makeEnv({ 'screen.capture': 'allow' });
  let listed = 0;
  const rpc = makeHandler(env, {
    isMoving: () => true,
    listScreens: async () => {
      listed += 1;
      return { displays: [], count: 0 };
    },
  });
  await expectRpcError(rpc('screen.list', {}), 'storage_moving');
  assert.strictEqual(listed, 0);
  assert.strictEqual(env.auditEntries().at(-1).decision, 'storage-moving');
});

test('0.5.3 screen.list: audit stays metadata-only (count, never image data)', async () => {
  const env = makeEnv({ 'screen.capture': 'allow' });
  const rpc = makeHandler(env, {
    listScreens: createScreenList({ getDisplays: fakeGetDisplays(FAKE_MONITORS) }),
  });
  await rpc('screen.list', {});
  const rawLog = fs.readFileSync(path.join(env.userDataPath, 'bridge-audit.log'), 'utf8');
  assert.ok(!rawLog.includes('dataBase64'), 'no image-data field in the audit entry');
  assert.ok(!rawLog.includes('thumbnail'), 'no capture payload in the audit entry');
  const entry = env.auditEntries().at(-1);
  assert.deepStrictEqual(entry.params, { count: 3 });
});

test('0.5.3 screen.list: without a provider the method fails cleanly', async () => {
  const env = makeEnv({ 'screen.capture': 'allow' });
  const rpc = makeHandler(env, {});
  await expectRpcError(rpc('screen.list', {}), 'tool_failed');
});

test('0.5.3 activity: list-displays describe line', () => {
  assert.strictEqual(describeEntry({ method: 'screen.list', params: { count: 2 } }), 'List displays: 2');
  assert.strictEqual(describeEntry({ method: 'screen.list', params: {} }), 'List displays');
});

// --- 0.5.3: version-free portable name + tray left-click setting -------------

test('0.5.3 rename: the updater expects the version-free asset name for every release', () => {
  assert.strictEqual(EXE_ASSET_NAME, 'Muse-Portable.exe');
  assert.strictEqual(exeAssetName(), 'Muse-Portable.exe');
  assert.strictEqual(exeAssetName('9.9.9'), 'Muse-Portable.exe', 'no version interpolation remains');
  // A release whose exe asset still carries a versioned name is NOT
  // an offer to a 0.5.3 updater — the constant name is the contract.
  const versioned = {
    tag_name: 'v9.9.9',
    assets: [
      { name: 'Muse-Portable-9.9.9.exe', browser_download_url: 'https://example.test/Muse-Portable-9.9.9.exe' },
      { name: 'SHA256SUMS.txt', browser_download_url: 'https://example.test/SHA256SUMS.txt' },
    ],
  };
  const parsed = parseLatestRelease(versioned, '0.5.2');
  assert.strictEqual(parsed.offer, null);
  assert.strictEqual(parsed.reason, 'missing-exe-asset');
});

test('0.5.3 tray: left-click dispatch honors the current setting value', () => {
  assert.strictEqual(trayLeftClickTarget('settings'), 'settings');
  assert.strictEqual(trayLeftClickTarget('window'), 'window');
  assert.strictEqual(trayLeftClickTarget(undefined), 'window', 'unset reads as the default');
  assert.strictEqual(trayLeftClickTarget('bogus'), 'window', 'unknown values fall back to window');
  assert.strictEqual(normalizeTrayLeftClick('settings'), 'settings');
  assert.strictEqual(normalizeTrayLeftClick('window'), 'window');
  assert.strictEqual(normalizeTrayLeftClick('bogus'), 'window');
});

function settingsTmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'muse-settings-'));
}

test('0.5.3 tray: trayLeftClick defaults to window — fresh, and for a pre-existing file without the key', () => {
  assert.strictEqual(SETTINGS_DEFAULTS.trayLeftClick, 'window');
  const freshDir = settingsTmpDir();
  try {
    const fresh = ensureSettings(freshDir);
    assert.strictEqual(fresh.created, true);
    assert.strictEqual(fresh.values.trayLeftClick, 'window');
  } finally {
    fs.rmSync(freshDir, { recursive: true, force: true });
  }
  const legacyDir = settingsTmpDir();
  try {
    // A settings.json written by an older build: no trayLeftClick key.
    fs.writeFileSync(
      path.join(legacyDir, 'settings.json'),
      JSON.stringify({ assistantFolder: 'C:\\Users\\you\\Muse', maxStorageGB: 10 }),
    );
    const upgraded = ensureSettings(legacyDir);
    assert.strictEqual(upgraded.values.trayLeftClick, 'window');
    const onDisk = JSON.parse(fs.readFileSync(path.join(legacyDir, 'settings.json'), 'utf8'));
    assert.strictEqual(onDisk.trayLeftClick, 'window', 'the merged default is persisted');
  } finally {
    fs.rmSync(legacyDir, { recursive: true, force: true });
  }
});

test('0.5.3 tray: the setting round-trips through settings.json; a bogus value normalizes', () => {
  const dir = settingsTmpDir();
  try {
    const first = ensureSettings(dir);
    saveSettings(dir, { ...first.values, trayLeftClick: 'settings' });
    assert.strictEqual(ensureSettings(dir).values.trayLeftClick, 'settings');
    saveSettings(dir, { ...first.values, trayLeftClick: 'sideways' });
    assert.strictEqual(ensureSettings(dir).values.trayLeftClick, 'window');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('0.5.3 tray: the settings-window wiring (handler, preload, page, renderer)', () => {
  const read = (rel) => fs.readFileSync(path.join(__dirname, '..', rel), 'utf8');
  const handlers = read('src/settingsHandlers.js');
  assert.ok(handlers.includes("ipcMain.handle('settings:set-tray-left-click'"), 'the IPC handler exists');
  assert.ok(handlers.includes('trayLeftClick:'), 'the state payload carries trayLeftClick');
  const preload = read('src/settings/preload.js');
  assert.ok(
    preload.includes("setTrayLeftClick: (action) => ipcRenderer.invoke('settings:set-tray-left-click', action)"),
    'the preload exposes setTrayLeftClick on the same channel',
  );
  const page = read('src/settings/index.html');
  assert.ok(page.includes('id="trayLeftClickSelect"'), 'the page has the control');
  assert.ok(page.includes('Tray left-click'), 'the row label');
  assert.ok(page.includes('<option value="window">Show/hide window</option>'), 'the window option');
  assert.ok(page.includes('<option value="settings">Open settings</option>'), 'the settings option');
  const renderer = read('src/settings/renderer.js');
  assert.ok(
    renderer.includes('window.museSettings.setTrayLeftClick(event.target.value)'),
    'the renderer saves through the bridge',
  );
  assert.ok(
    renderer.includes("$('trayLeftClickSelect').value = state.trayLeftClick"),
    'render() reflects the saved value into the control',
  );
});

// ---------------------------------------------------------------------------

(async () => {
  let passed = 0;
  const failures = [];
  for (const { name, fn } of tests) {
    try {
      await fn();
      passed += 1;
      console.log(`ok   ${name}`);
    } catch (err) {
      failures.push({ name, err });
      console.error(`FAIL ${name}\n     ${err.message}`);
    }
  }
  console.log(`\n${passed}/${tests.length} tests passed`);
  if (failures.length > 0) process.exit(1);
})();
