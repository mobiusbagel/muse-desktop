// Local Bridge tool dispatcher (Phase 2).
// Every POST /rpc call flows through here:
//
//   method -> capability -> scope check (fs tools) -> permission gate
//   ("allow" runs, "deny" refuses, "ask" prompts on the PC) -> tool
//
// shell.run (0.4.0) is the deliberate exception to path scoping: a shell
// command has no single path to scope. Its controls are the permission
// prompt (always shown — the capability can never run on a stored
// "allow") displaying the exact command, plus the audit log.
//
// screen.capture (0.5.1) is the opposite case: a standard-family
// capability (a stored "allow" is honored, "always allow" can be
// granted on the prompt), no path to scope, gated + audited like the
// rest. Its audit summary carries the captured dimensions — never
// image data. screen.list (0.5.3) is capture's read-only companion:
// it shares the screen.capture capability and its audit summary
// carries the display count only.
//
// fs.delete / fs.move (0.5.9) complete the fs family. Each is its own
// capability, defaulted to "ask"; a permissions.json written before
// 0.5.9 has no key for them, and the policy loader defaults missing
// keys to "ask" — never a crash, never a silent allow. fs.move jails
// BOTH endpoints and refuses before the prompt when the source is
// missing, the destination already exists, or a folder would move
// into its own subtree. fs.delete's prompt names the blast radius
// (file, or folder + recursive item count) computed pre-approval, and
// its audit summary carries the kind/count from the result. fs.list
// entries carry createdAt / modifiedAt timestamps since 0.5.9.
//
// One audit line is appended per call (see bridgeAudit.js).
//
// This module is deliberately Electron-free: the permission prompt and
// the OS-level operations are injected dependencies, so the whole gate
// can be unit-tested in plain Node with stubs.
'use strict';

const { execFile, spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const {
  loadPolicy,
  setCapability,
  NEVER_ALLOW_CAPABILITIES,
  effectivePolicyMode,
  sanitizePromptAnswer,
} = require('./permissions');
const { folderSizeBytes } = require('./assistantFolder');
const { appendAuditLog } = require('./bridgeAudit');
const {
  ScreenCaptureError,
  validateCaptureParams,
  describeCaptureRequest,
  describeListRequest,
} = require('./screenCapture');

const MAX_READ_BYTES = 1024 * 1024; // fs.read hard cap: 1 MB
const BYTES_PER_GB = 1024 ** 3;
const DEFAULT_PROMPT_TIMEOUT_MS = 60_000;
// shell.run limits (0.4.0): a command gets 30 s by default and never
// more than 120 s; each output stream is captured up to 64 KB.
const DEFAULT_SHELL_TIMEOUT_MS = 30_000;
const MAX_SHELL_TIMEOUT_MS = 120_000;
const SHELL_OUTPUT_CAP_BYTES = 64 * 1024;
// shell.run's audit summary is the command itself, capped for the log.
const AUDIT_COMMAND_CAP_CHARS = 500;

class RpcError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

const METHOD_CAPABILITY = {
  'fs.list': 'fs.list',
  'fs.read': 'fs.read',
  'fs.write': 'fs.write',
  'fs.mkdir': 'fs.write',
  'fs.delete': 'fs.delete',
  'fs.move': 'fs.move',
  'app.launch': 'app.launch',
  'process.list': 'process.list',
  'process.kill': 'process.kill',
  'shell.run': 'shell.run',
  'screen.capture': 'screen.capture',
  // screen.list shares the capture capability by design (0.5.3): one
  // permissions.json key governs the whole screen family.
  'screen.list': 'screen.capture',
};

const FS_METHODS = new Set(['fs.list', 'fs.read', 'fs.write', 'fs.mkdir', 'fs.delete', 'fs.move']);
// Methods refused with storage_moving while an assistant-folder move
// runs: the fs tools (their scope is in flux), shell.run (its
// working directory is the assistant folder being moved), and the
// screen family — the read-side methods all pause during a move,
// and screen.capture / screen.list follow their nearest siblings.
const MOVING_REFUSED_METHODS = new Set([...FS_METHODS, 'shell.run', 'screen.capture', 'screen.list']);
const REFUSAL_CODES = new Set(['permission_denied', 'permission_timeout', 'scope_refused', 'storage_moving']);

// ---------------------------------------------------------------------------
// Path scope
// ---------------------------------------------------------------------------

// True when `child` is `dir` itself or lives underneath it.
function isInsideDir(child, dir) {
  const rel = path.relative(dir, child);
  return rel === '' || (rel !== '..' && !rel.startsWith('..' + path.sep) && !path.isAbsolute(rel));
}

// Canonical form for comparison: absolute, with symlinks resolved for the
// deepest existing ancestor (a not-yet-created file's parent still counts).
// Case-folded on Windows, where the filesystem is case-insensitive.
function canonicalPath(p) {
  let candidate = path.resolve(p);
  const suffix = [];
  while (!fs.existsSync(candidate)) {
    const parent = path.dirname(candidate);
    if (parent === candidate) break;
    suffix.unshift(path.basename(candidate));
    candidate = parent;
  }
  let real = candidate;
  try {
    real = fs.realpathSync(candidate);
  } catch {
    // Keep the resolved form if realpath fails.
  }
  const joined = suffix.length > 0 ? path.join(real, ...suffix) : real;
  return process.platform === 'win32' ? joined.toLowerCase() : joined;
}

// Resolve an RPC path parameter. Relative paths are taken relative to the
// assistant folder (the bridge has no meaningful working directory).
function resolveRequestedPath(requested, settings) {
  if (typeof requested !== 'string' || requested.trim() === '') {
    throw new RpcError('invalid_params', 'A non-empty "path" parameter is required.');
  }
  const absolute = path.isAbsolute(requested)
    ? path.resolve(requested)
    : path.resolve(settings.assistantFolder, requested);
  return canonicalPath(absolute);
}

function assertInScope(canonicalTarget, settings, policy) {
  const roots = [settings.assistantFolder, ...(policy.approvedFolders || [])].map(canonicalPath);
  if (roots.some((root) => isInsideDir(canonicalTarget, root))) return;
  throw new RpcError(
    'scope_refused',
    `Path is outside the assistant folder and approved folders: ${canonicalTarget}`,
  );
}

// Recursive item count under a directory (files + folders) — the
// blast radius an fs.delete prompt shows BEFORE approval. Unreadable
// subfolders are skipped rather than failing the count: the same
// mid-flight tolerance fs.list applies to vanishing entries.
function countDirectoryItems(dir) {
  let count = 0;
  const pending = [dir];
  while (pending.length > 0) {
    const current = pending.pop();
    let entries;
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      count += 1;
      if (entry.isDirectory()) pending.push(path.join(current, entry.name));
    }
  }
  return count;
}

// The fs.delete prompt description: what exactly is about to be
// deleted — a file, or a folder with its recursive item count. A
// missing target falls back to the bare path; execute() then refuses
// it cleanly if the call is approved anyway.
function describeDeleteTarget(canonicalTarget) {
  let stat;
  try {
    stat = fs.statSync(canonicalTarget);
  } catch {
    return canonicalTarget;
  }
  if (!stat.isDirectory()) return `Delete file: ${canonicalTarget}`;
  const count = countDirectoryItems(canonicalTarget);
  return `Delete folder: ${canonicalTarget} (${count} item${count === 1 ? '' : 's'})`;
}

// fs.move's pre-gate refusals, checked after scoping and BEFORE the
// prompt — the user is never asked to approve a move that cannot run:
// the source must exist, the destination must not (no silent
// overwrite), and a folder may not move into its own subtree.
function assertMovable(canonicalSource, canonicalDestination) {
  let stat;
  try {
    stat = fs.statSync(canonicalSource);
  } catch {
    throw new RpcError('invalid_params', `Source does not exist: ${canonicalSource}`);
  }
  if (fs.existsSync(canonicalDestination)) {
    throw new RpcError('invalid_params', `Destination already exists: ${canonicalDestination}`);
  }
  if (stat.isDirectory() && isInsideDir(canonicalDestination, canonicalSource)) {
    throw new RpcError('invalid_params', `Cannot move a folder into its own subtree: ${canonicalSource}`);
  }
}

// ---------------------------------------------------------------------------
// Default OS operations (overridable in tests)
// ---------------------------------------------------------------------------

function defaultLaunchApp(target) {
  return new Promise((resolve, reject) => {
    let child;
    const options = { detached: true, stdio: 'ignore' };
    if (process.platform === 'win32') {
      // `start` handles exe paths, folders, documents and URLs uniformly.
      child = spawn('cmd.exe', ['/c', 'start', '', target], { ...options, windowsHide: true });
    } else if (process.platform === 'darwin') {
      child = spawn('open', [target], options);
    } else {
      child = spawn(target, [], options);
    }
    child.on('error', reject);
    child.unref();
    resolve({ launched: target });
  });
}

function parseTasklistCsv(text) {
  const processes = [];
  for (const line of text.split(/\r?\n/)) {
    const match = line.match(/^"((?:[^"]|"")*)","(\d+)","[^"]*","[^"]*","([\d,]+) K"/);
    if (!match) continue;
    processes.push({
      name: match[1].replace(/""/g, '"'),
      pid: Number(match[2]),
      memoryBytes: Number(match[3].replace(/,/g, '')) * 1024,
    });
  }
  return processes;
}

function parsePs(text) {
  const processes = [];
  for (const line of text.split(/\r?\n/)) {
    const match = line.trim().match(/^(\d+)\s+(.+?)\s+(\d+)$/);
    if (!match) continue;
    processes.push({ pid: Number(match[1]), name: match[2], memoryBytes: Number(match[3]) * 1024 });
  }
  return processes;
}

function defaultListProcesses() {
  return new Promise((resolve, reject) => {
    const done = (err, stdout) => {
      if (err) return reject(new RpcError('tool_failed', `Could not list processes: ${err.message}`));
      resolve({ processes: process.platform === 'win32' ? parseTasklistCsv(stdout) : parsePs(stdout) });
    };
    if (process.platform === 'win32') {
      execFile('tasklist', ['/fo', 'csv', '/nh'], { maxBuffer: 16 * 1024 * 1024 }, done);
    } else {
      execFile('ps', ['-eo', 'pid=,comm=,rss='], { maxBuffer: 16 * 1024 * 1024 }, done);
    }
  });
}

function defaultKillProcess(pid) {
  if (pid === process.pid) {
    throw new RpcError('invalid_params', 'Refusing to kill the Muse app itself.');
  }
  try {
    process.kill(pid, 'SIGTERM');
  } catch (err) {
    throw new RpcError('tool_failed', `Could not kill pid ${pid}: ${err.message}`);
  }
  return { pid, signal: 'SIGTERM' };
}

// Kill a spawned command and everything it spawned. Windows: taskkill's
// /t takes the whole tree. POSIX: the child was spawned detached (its
// own process group), so a group SIGKILL reaches the tree.
function killProcessTree(child) {
  if (!child || child.pid === undefined) return;
  if (process.platform === 'win32') {
    try {
      execFile('taskkill', ['/pid', String(child.pid), '/t', '/f'], () => {});
    } catch {
      // Best effort — the close event still resolves the call.
    }
    return;
  }
  try {
    process.kill(-child.pid, 'SIGKILL');
  } catch {
    try {
      child.kill('SIGKILL');
    } catch {
      // Already gone.
    }
  }
}

// Default shell.run implementation. The command travels as ONE argv
// element to the platform shell — powershell.exe on Windows (the app's
// target platform), /bin/sh elsewhere for development — never
// concatenated into another command string. stdout/stderr are captured
// separately, each capped at SHELL_OUTPUT_CAP_BYTES; past the timeout
// the process tree is killed and the result reports timedOut.
function defaultRunShell(command, { timeoutMs = DEFAULT_SHELL_TIMEOUT_MS, cwd } = {}) {
  return new Promise((resolve, reject) => {
    const isWin = process.platform === 'win32';
    let child;
    try {
      child = isWin
        ? spawn('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', command], {
            cwd,
            windowsHide: true,
          })
        : spawn('/bin/sh', ['-c', command], { cwd, detached: true });
    } catch (err) {
      reject(new RpcError('tool_failed', `Could not start the shell: ${err.message}`));
      return;
    }

    const streams = {
      stdout: { chunks: [], bytes: 0 },
      stderr: { chunks: [], bytes: 0 },
    };
    let truncated = false;
    const collect = (stream) => (chunk) => {
      const s = streams[stream];
      if (s.bytes >= SHELL_OUTPUT_CAP_BYTES) {
        truncated = true;
        return;
      }
      const room = SHELL_OUTPUT_CAP_BYTES - s.bytes;
      if (chunk.length > room) {
        s.chunks.push(chunk.subarray(0, room));
        s.bytes += room;
        truncated = true;
      } else {
        s.chunks.push(chunk);
        s.bytes += chunk.length;
      }
    };
    if (child.stdout) child.stdout.on('data', collect('stdout'));
    if (child.stderr) child.stderr.on('data', collect('stderr'));

    let timedOut = false;
    let settled = false;
    const timer = setTimeout(() => {
      timedOut = true;
      killProcessTree(child);
    }, timeoutMs);

    child.on('error', (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(new RpcError('tool_failed', `Could not run the command: ${err.message}`));
    });
    child.on('close', (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({
        stdout: Buffer.concat(streams.stdout.chunks).toString('utf8'),
        stderr: Buffer.concat(streams.stderr.chunks).toString('utf8'),
        exitCode: code,
        timedOut,
        truncated,
      });
    });
  });
}

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------

// shell.run's audit summary is the command itself (the user reviewing
// the log should see what ran), capped so a pasted script can't bloat
// the log: first 500 chars + an ellipsis marker when clipped.
function capCommandForAudit(command) {
  if (typeof command !== 'string') return '';
  if (command.length <= AUDIT_COMMAND_CAP_CHARS) return command;
  return command.slice(0, AUDIT_COMMAND_CAP_CHARS) + '…';
}

function paramsSummary(method, params, result) {
  // Paths / targets / pids only — never file contents. shell.run is the
  // one deliberate exception: its "content" IS the action, so the
  // (capped) command is the summary. screen.capture's summary is the
  // request plus, on success, the captured dimensions from the result
  // — never the image data itself.
  switch (method) {
    case 'fs.list':
    case 'fs.read':
    case 'fs.mkdir':
      return { path: params && params.path };
    case 'fs.write':
      return {
        path: params && params.path,
        bytes: params && typeof params.content === 'string' ? Buffer.byteLength(params.content, 'utf8') : 0,
      };
    case 'fs.delete':
      // Kind/count from the result, on success only (the
      // screen.capture pattern) — a refused delete logs the bare path.
      return {
        path: params && params.path,
        ...(result && typeof result.kind === 'string' ? { kind: result.kind } : {}),
        ...(result && Number.isInteger(result.count) ? { count: result.count } : {}),
      };
    case 'fs.move':
      return { path: params && params.path, newPath: params && params.newPath };
    case 'app.launch':
      return { target: params && params.target };
    case 'process.kill':
      return { pid: params && params.pid };
    case 'shell.run':
      return { summary: capCommandForAudit(params && params.command) };
    case 'screen.capture':
      return {
        displayIndex: params && params.displayIndex,
        ...(result && Number.isInteger(result.width) && Number.isInteger(result.height)
          ? { width: result.width, height: result.height }
          : {}),
      };
    case 'screen.list':
      // The count from the result, on success only — the Activity
      // window renders "List displays: <count>" from it.
      return result && Number.isInteger(result.count) ? { count: result.count } : {};
    default:
      return {};
  }
}

function promptDetail(method, params, resolvedPath, canonicalNewTarget) {
  switch (method) {
    case 'app.launch':
      return `Launch: ${params.target}`;
    case 'fs.delete':
      // Name + file-vs-folder + recursive count, computed now — the
      // user approves the blast radius, not just a path.
      return describeDeleteTarget(resolvedPath);
    case 'fs.move':
      return `Move: ${resolvedPath} → ${canonicalNewTarget}`;
    case 'process.kill':
      return `Kill process pid ${params.pid}`;
    case 'process.list':
      return 'List running processes';
    case 'shell.run':
      // The prompt shows the EXACT command string, untruncated — the
      // user approves precisely what will run.
      return params.command;
    case 'screen.capture':
      // One-line summary: which display, how wide at most. Params were
      // validated before the gate, so the numbers shown are the
      // numbers that will run.
      return describeCaptureRequest(params);
    case 'screen.list':
      return describeListRequest();
    default:
      return resolvedPath || String(params && params.path);
  }
}

// Default screen.capture implementation: none. Capture needs an OS
// capturer, which only main.js can provide (Electron's
// desktopCapturer via screenCapture.js); a handler built without one
// fails cleanly instead of pretending.
function defaultCaptureScreen() {
  return Promise.reject(
    new RpcError('tool_failed', 'Screen capture is not available in this run.'),
  );
}

// Same for screen.list: the display provider lives in main.js
// (Electron's screen module via screenCapture.js).
function defaultListScreens() {
  return Promise.reject(
    new RpcError('tool_failed', 'Display listing is not available in this run.'),
  );
}

function createRpcHandler(deps) {
  const {
    userDataPath,
    getSettings,
    isMoving,
    prompt,
    promptTimeoutMs = DEFAULT_PROMPT_TIMEOUT_MS,
    launchApp = defaultLaunchApp,
    listProcesses = defaultListProcesses,
    killProcess = defaultKillProcess,
    runShell = defaultRunShell,
    captureScreen = defaultCaptureScreen,
    listScreens = defaultListScreens,
  } = deps;

  function audit(method, params, decision, outcome, errorCode, result) {
    appendAuditLog(userDataPath, {
      ts: new Date().toISOString(),
      method,
      params: paramsSummary(method, params, result),
      decision,
      outcome,
      ...(errorCode ? { error: errorCode } : {}),
    });
  }

  // Race the injected prompt against the timeout. A missing prompt
  // implementation (headless run) counts as a denial — never a grant.
  function askPermission(request) {
    if (typeof prompt !== 'function') return Promise.resolve({ allowed: false, noPrompt: true });
    return new Promise((resolve) => {
      let settled = false;
      const timer = setTimeout(() => {
        if (!settled) {
          settled = true;
          resolve({ allowed: false, timedOut: true });
        }
      }, promptTimeoutMs);
      Promise.resolve()
        .then(() => prompt(request))
        .then(
          (answer) => {
            if (!settled) {
              settled = true;
              clearTimeout(timer);
              resolve({ allowed: Boolean(answer && answer.allowed), alwaysAllow: Boolean(answer && answer.alwaysAllow) });
            }
          },
          () => {
            if (!settled) {
              settled = true;
              clearTimeout(timer);
              resolve({ allowed: false });
            }
          },
        );
    });
  }

  function assertWriteWithinCap(settings, canonicalTarget, content) {
    // The cap applies to the assistant folder only.
    if (!isInsideDir(canonicalTarget, canonicalPath(settings.assistantFolder))) return;
    let existingBytes = 0;
    try {
      existingBytes = fs.statSync(canonicalTarget).size;
    } catch {
      // New file — nothing to subtract.
    }
    const projected = folderSizeBytes(settings.assistantFolder) - existingBytes + Buffer.byteLength(content, 'utf8');
    const capBytes = settings.maxStorageGB * BYTES_PER_GB;
    if (projected > capBytes) {
      throw new RpcError(
        'storage_cap',
        `Write refused: it would push the assistant folder to ${projected} bytes, past the ${capBytes}-byte cap.`,
      );
    }
  }

  async function execute(method, params, canonicalTarget, settings, canonicalNewTarget) {
    switch (method) {
      case 'fs.list': {
        const entries = fs.readdirSync(canonicalTarget, { withFileTypes: true });
        const list = entries.map((entry) => {
          const item = {
            name: entry.name,
            type: entry.isDirectory() ? 'directory' : entry.isFile() ? 'file' : 'other',
            size: null,
            createdAt: null,
            modifiedAt: null,
          };
          try {
            const stat = fs.statSync(path.join(canonicalTarget, entry.name));
            // Size stays files-only; timestamps are stat'd for every
            // entry (0.5.9), directories included.
            if (entry.isFile()) item.size = stat.size;
            item.createdAt = stat.birthtime.toISOString();
            item.modifiedAt = stat.mtime.toISOString();
          } catch {
            // Vanished mid-listing; size and timestamps stay null.
          }
          return item;
        });
        list.sort((a, b) => a.name.localeCompare(b.name));
        return { path: canonicalTarget, entries: list };
      }
      case 'fs.read': {
        const stat = fs.statSync(canonicalTarget);
        if (!stat.isFile()) throw new RpcError('invalid_params', `Not a file: ${canonicalTarget}`);
        if (stat.size > MAX_READ_BYTES) {
          throw new RpcError(
            'too_large',
            `File is ${stat.size} bytes; fs.read is capped at ${MAX_READ_BYTES} bytes (1 MB).`,
          );
        }
        return { path: canonicalTarget, size: stat.size, content: fs.readFileSync(canonicalTarget, 'utf8') };
      }
      case 'fs.write': {
        if (typeof params.content !== 'string') {
          throw new RpcError('invalid_params', 'fs.write requires a string "content" parameter.');
        }
        assertWriteWithinCap(settings, canonicalTarget, params.content);
        fs.mkdirSync(path.dirname(canonicalTarget), { recursive: true });
        fs.writeFileSync(canonicalTarget, params.content, 'utf8');
        return { path: canonicalTarget, bytes: Buffer.byteLength(params.content, 'utf8') };
      }
      case 'fs.mkdir': {
        fs.mkdirSync(canonicalTarget, { recursive: true });
        return { path: canonicalTarget };
      }
      case 'fs.delete': {
        let stat;
        try {
          stat = fs.statSync(canonicalTarget);
        } catch {
          throw new RpcError('invalid_params', `Path does not exist: ${canonicalTarget}`);
        }
        if (stat.isDirectory()) {
          // Count BEFORE deleting: the result (and the audit line
          // built from it) reports the recursive blast radius.
          const count = countDirectoryItems(canonicalTarget);
          fs.rmSync(canonicalTarget, { recursive: true });
          return { path: canonicalTarget, kind: 'directory', count };
        }
        fs.unlinkSync(canonicalTarget);
        return { path: canonicalTarget, kind: 'file' };
      }
      case 'fs.move': {
        // Source/destination were validated before the gate
        // (assertMovable). renameSync is the whole operation: both
        // endpoints sit inside the same scoped roots, so this is a
        // same-volume rename by construction — an EXDEV surprise is
        // surfaced as-is, never papered over with copy+delete.
        fs.renameSync(canonicalTarget, canonicalNewTarget);
        return { path: canonicalTarget, newPath: canonicalNewTarget };
      }
      case 'app.launch': {
        if (typeof params.target !== 'string' || params.target.trim() === '') {
          throw new RpcError('invalid_params', 'app.launch requires a non-empty "target" parameter.');
        }
        return launchApp(params.target);
      }
      case 'process.list': {
        return listProcesses();
      }
      case 'process.kill': {
        if (!Number.isInteger(params.pid) || params.pid <= 0) {
          throw new RpcError('invalid_params', 'process.kill requires a positive integer "pid".');
        }
        return killProcess(params.pid);
      }
      case 'shell.run': {
        // The command itself was validated before the permission gate
        // (the prompt must show exactly what will run); re-check here so
        // execute() is safe on its own.
        if (typeof params.command !== 'string' || params.command.trim() === '') {
          throw new RpcError('invalid_params', 'shell.run requires a non-empty string "command" parameter.');
        }
        const requested = Number(params.timeoutMs);
        const timeoutMs =
          Number.isFinite(requested) && requested > 0
            ? Math.min(Math.floor(requested), MAX_SHELL_TIMEOUT_MS)
            : DEFAULT_SHELL_TIMEOUT_MS;
        return runShell(params.command, { timeoutMs, cwd: settings.assistantFolder });
      }
      case 'screen.capture': {
        // Param validation + capture live in screenCapture.js; its
        // ScreenCaptureError codes map straight onto RpcError so the
        // client sees the usual shape (invalid_params included).
        try {
          return await captureScreen(params);
        } catch (err) {
          if (err instanceof ScreenCaptureError) throw new RpcError(err.code, err.message);
          throw err;
        }
      }
      case 'screen.list': {
        // Enumeration + normalization live in screenCapture.js, with
        // the same error mapping as the capture.
        try {
          return await listScreens(params);
        } catch (err) {
          if (err instanceof ScreenCaptureError) throw new RpcError(err.code, err.message);
          throw err;
        }
      }
      default:
        throw new RpcError('unknown_method', `Unknown method: ${method}`);
    }
  }

  async function handleRpc(method, params = {}) {
    const capability = METHOD_CAPABILITY[method];
    let decision = 'none';
    try {
      if (!capability) {
        decision = 'unknown-method';
        throw new RpcError('unknown_method', `Unknown method: ${method}`);
      }

      const settings = getSettings();
      const policy = loadPolicy(userDataPath);

      if (MOVING_REFUSED_METHODS.has(method) && typeof isMoving === 'function' && isMoving()) {
        decision = 'storage-moving';
        throw new RpcError('storage_moving', 'The assistant folder is being moved; retry shortly.');
      }

      // shell.run validates its command BEFORE the gate: the prompt
      // displays the exact command, so a missing/empty one must never
      // reach it.
      if (method === 'shell.run' && (typeof params.command !== 'string' || params.command.trim() === '')) {
        throw new RpcError('invalid_params', 'shell.run requires a non-empty string "command" parameter.');
      }

      // screen.capture validates BEFORE the gate for the same reason:
      // the prompt displays the effective display + max width, so an
      // invalid pair must never reach it. (An out-of-range display
      // INDEX can only be discovered by enumerating screens, which
      // happens after the gate, inside the capture itself.)
      if (method === 'screen.capture') {
        try {
          validateCaptureParams(params);
        } catch (err) {
          if (err instanceof ScreenCaptureError) throw new RpcError(err.code, err.message);
          throw err;
        }
      }

      // Scope first: never prompt for a path that will be refused anyway.
      let canonicalTarget = null;
      let canonicalNewTarget = null;
      if (FS_METHODS.has(method)) {
        const rawPath = method === 'fs.list' && (params.path === undefined || params.path === '') ? '.' : params.path;
        canonicalTarget = resolveRequestedPath(rawPath, settings);
        try {
          assertInScope(canonicalTarget, settings, policy);
        } catch (err) {
          decision = 'scope-refused';
          throw err;
        }
        if (method === 'fs.move') {
          // The destination is jailed with the same rules as the
          // source: an out-of-scope newPath is scope_refused here,
          // before any prompt, exactly like a bad source path.
          if (typeof params.newPath !== 'string' || params.newPath.trim() === '') {
            throw new RpcError('invalid_params', 'fs.move requires a non-empty string "newPath" parameter.');
          }
          canonicalNewTarget = resolveRequestedPath(params.newPath, settings);
          try {
            assertInScope(canonicalNewTarget, settings, policy);
          } catch (err) {
            decision = 'scope-refused';
            throw err;
          }
          // Missing source / existing destination / folder into its
          // own subtree: refused BEFORE the gate too (see
          // assertMovable) — no prompt for a move that cannot run.
          assertMovable(canonicalTarget, canonicalNewTarget);
        }
      }

      // Effective mode: a stored "allow" for a never-allow capability
      // (shell.run) is coerced to "ask" HERE, at decision time — the
      // file on disk is never trusted to make shell.run silent.
      const mode = effectivePolicyMode(capability, policy.capabilities[capability] || 'ask');
      if (mode === 'deny') {
        decision = 'deny';
        throw new RpcError('permission_denied', `Capability "${capability}" is set to "deny" in permissions.json.`);
      }
      if (mode === 'ask') {
        const answer = sanitizePromptAnswer(
          capability,
          await askPermission({
            capability,
            method,
            detail: promptDetail(method, params, canonicalTarget, canonicalNewTarget),
            // The prompt renders an "always allow" affordance only when
            // this is true; for shell.run it never is.
            canAlwaysAllow: !NEVER_ALLOW_CAPABILITIES.has(capability),
          }),
        );
        if (!answer.allowed) {
          decision = answer.timedOut ? 'ask-timeout' : 'ask-denied';
          throw new RpcError(
            answer.timedOut ? 'permission_timeout' : 'permission_denied',
            answer.timedOut
              ? `No response to the permission prompt for "${capability}" within ${Math.round(promptTimeoutMs / 1000)}s; denied.`
              : `Permission for "${capability}" was denied on this PC.`,
          );
        }
        decision = 'ask-granted';
        if (answer.alwaysAllow) {
          try {
            setCapability(userDataPath, capability, 'allow');
          } catch (err) {
            console.error('[rpc] could not persist "always allow":', err.message);
          }
        }
      } else {
        decision = 'allow';
      }

      const result = await execute(method, params, canonicalTarget, settings, canonicalNewTarget);
      audit(method, params, decision, 'ok', undefined, result);
      return result;
    } catch (err) {
      const rpcErr =
        err instanceof RpcError ? err : new RpcError('tool_failed', err && err.message ? err.message : String(err));
      audit(method, params, decision, REFUSAL_CODES.has(rpcErr.code) ? 'refused' : 'error', rpcErr.code);
      throw rpcErr;
    }
  }

  return handleRpc;
}

module.exports = {
  createRpcHandler,
  RpcError,
  METHOD_CAPABILITY,
  MAX_READ_BYTES,
  DEFAULT_SHELL_TIMEOUT_MS,
  MAX_SHELL_TIMEOUT_MS,
  SHELL_OUTPUT_CAP_BYTES,
  _internals: {
    isInsideDir,
    canonicalPath,
    parseTasklistCsv,
    parsePs,
    defaultKillProcess,
    defaultRunShell,
    capCommandForAudit,
    promptDetail,
    paramsSummary,
  },
};
