// Permission policy for the Local Bridge (Phase 2 groundwork).
// On first run, writes permissions.json into userData with every capability
// defaulted to "ask" and no approved folders. Phase 2 will read this file
// before serving any tool endpoint and prompt on "ask".
'use strict';

const fs = require('fs');
const path = require('path');

const DEFAULT_POLICY = {
  version: 1,
  _note:
    "The assistant folder (see settings.json: assistantFolder, default " +
    '%USERPROFILE%\\Muse) is Muse\'s home turf: Phase 2 filesystem tools ' +
    'will treat paths inside it as pre-approved scope. Anything outside it ' +
    'needs the ask flow and an approvedFolders entry.',
  capabilities: {
    'fs.read': 'ask',
    'fs.write': 'ask',
    'fs.list': 'ask',
    'fs.delete': 'ask',
    'fs.move': 'ask',
    'app.launch': 'ask',
    'process.list': 'ask',
    'process.kill': 'ask',
    'shell.run': 'ask',
    'screen.capture': 'ask',
  },
  approvedFolders: [],
  // Exact shell command strings the user chose to remember (0.6.1).
  // shell.run has NO capability-level "allow" — this list is the only
  // way a command runs without a prompt, and only when the incoming
  // command is byte-identical to an entry.
  shellAllowlist: [],
};

// Capabilities that can NEVER run on a stored capability-level "allow"
// (0.4.0). A shell command is arbitrary code, so the CAPABILITY is never
// silent: the dispatcher coerces a stored "allow" for these to "ask" at
// decision time (effectivePolicyMode), and prompt answers for them are
// stripped of any capability-level "always allow"
// (sanitizePromptAnswer) — so even a hand-edited permissions.json or a
// prompt bug cannot make the capability silent. The one exception,
// added in 0.6.1, is per-command: an exact command string the user
// explicitly remembered (shellAllowlist) runs without a prompt. That is
// a list of individual commands, not a capability grant.
const NEVER_ALLOW_CAPABILITIES = new Set(['shell.run']);

// The mode a call actually runs under: a stored "allow" for a
// never-allow capability is treated as "ask". Anything else passes
// through untouched.
function effectivePolicyMode(capability, mode) {
  if (mode === 'allow' && NEVER_ALLOW_CAPABILITIES.has(capability)) return 'ask';
  return mode;
}

// Normalize a permission-prompt answer (0.6.1 "remember my choice").
// The prompt's single checkbox arrives as `remember` (older answers may
// carry it as `alwaysAllow`; both mean the same intent). What it buys
// differs by capability:
//   - normal capability: remember -> capability-level "allow"
//     (alwaysAllow=true, persisted via setCapability);
//   - never-allow capability (shell.run): the capability-level half is
//     forced OFF, always — remember survives only as a per-command
//     intent, which the dispatcher turns into a shellAllowlist entry
//     for the exact command that was just approved.
function sanitizePromptAnswer(capability, answer) {
  // (Either flag counts: the prompt layer materializes both fields, so
  // a legacy alwaysAllow-only answer must not be shadowed by a
  // present-but-false remember.)
  const remember = Boolean(answer && (answer.remember || answer.alwaysAllow));
  return {
    allowed: Boolean(answer && answer.allowed),
    alwaysAllow: remember && !NEVER_ALLOW_CAPABILITIES.has(capability),
    remember,
    ...(answer && answer.timedOut ? { timedOut: true } : {}),
  };
}

// Is this exact command string on the remembered list? Byte-identical
// comparison — any difference at all (whitespace, quoting, one char)
// is a different command and prompts again.
function isShellCommandAllowed(policy, command) {
  return (
    typeof command === 'string' &&
    Array.isArray(policy && policy.shellAllowlist) &&
    policy.shellAllowlist.includes(command)
  );
}

function policyFilePath(userDataPath) {
  return path.join(userDataPath, 'permissions.json');
}

function ensurePermissionsPolicy(userDataPath) {
  const file = policyFilePath(userDataPath);
  if (fs.existsSync(file)) {
    console.log('[permissions] policy file exists:', file);
    return file;
  }
  fs.mkdirSync(userDataPath, { recursive: true });
  fs.writeFileSync(file, JSON.stringify(DEFAULT_POLICY, null, 2) + '\n');
  console.log('[permissions] wrote default policy:', file);
  return file;
}

// Read the current policy from disk. Read fresh on every call so edits the
// user makes by hand — and "always allow" flips from the prompt flow —
// take effect without an app restart. A missing or corrupt file falls back
// to the defaults in memory (the file itself is left untouched).
function loadPolicy(userDataPath) {
  const file = policyFilePath(userDataPath);
  try {
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
    return {
      ...parsed,
      capabilities: { ...DEFAULT_POLICY.capabilities, ...(parsed.capabilities || {}) },
      approvedFolders: Array.isArray(parsed.approvedFolders) ? parsed.approvedFolders : [],
      shellAllowlist: Array.isArray(parsed.shellAllowlist)
        ? parsed.shellAllowlist.filter((entry) => typeof entry === 'string')
        : [],
    };
  } catch {
    return JSON.parse(JSON.stringify(DEFAULT_POLICY));
  }
}

// Persist one capability change (used when the user checks "always allow"
// on a permission prompt). Other fields of the file are preserved.
function setCapability(userDataPath, capability, value) {
  const file = policyFilePath(userDataPath);
  let parsed = {};
  try {
    parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    parsed = JSON.parse(JSON.stringify(DEFAULT_POLICY));
  }
  parsed.capabilities = { ...DEFAULT_POLICY.capabilities, ...(parsed.capabilities || {}) };
  parsed.capabilities[capability] = value;
  if (!Array.isArray(parsed.approvedFolders)) parsed.approvedFolders = [];
  if (!Array.isArray(parsed.shellAllowlist)) parsed.shellAllowlist = [];
  fs.mkdirSync(userDataPath, { recursive: true });
  fs.writeFileSync(file, JSON.stringify(parsed, null, 2) + '\n');
  console.log(`[permissions] capability ${capability} set to "${value}"`);
}

// Persist one remembered shell command (used when the user checks
// "remember" on a shell.run prompt and allows). The exact string is
// stored as-is; duplicates are not added twice. Other fields of the
// file are preserved.
function addShellCommand(userDataPath, command) {
  if (typeof command !== 'string' || command === '') return;
  const file = policyFilePath(userDataPath);
  let parsed = {};
  try {
    parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    parsed = JSON.parse(JSON.stringify(DEFAULT_POLICY));
  }
  parsed.capabilities = { ...DEFAULT_POLICY.capabilities, ...(parsed.capabilities || {}) };
  if (!Array.isArray(parsed.approvedFolders)) parsed.approvedFolders = [];
  if (!Array.isArray(parsed.shellAllowlist)) parsed.shellAllowlist = [];
  if (parsed.shellAllowlist.includes(command)) return;
  parsed.shellAllowlist.push(command);
  fs.mkdirSync(userDataPath, { recursive: true });
  fs.writeFileSync(file, JSON.stringify(parsed, null, 2) + '\n');
  console.log('[permissions] shell command added to allowlist');
}

module.exports = {
  ensurePermissionsPolicy,
  loadPolicy,
  setCapability,
  addShellCommand,
  isShellCommandAllowed,
  policyFilePath,
  DEFAULT_POLICY,
  NEVER_ALLOW_CAPABILITIES,
  effectivePolicyMode,
  sanitizePromptAnswer,
};
