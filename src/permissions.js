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
    'app.launch': 'ask',
    'process.list': 'ask',
    'process.kill': 'ask',
    'shell.run': 'ask',
    'screen.capture': 'ask',
  },
  approvedFolders: [],
};

// Capabilities that can NEVER run on a stored "allow" (0.4.0). A shell
// command is arbitrary code: every single one must be seen and approved
// on the PC. The dispatcher coerces a stored "allow" for these to "ask"
// at decision time (effectivePolicyMode), and prompt answers for them
// are stripped of any "always allow" (sanitizePromptAnswer) — so even a
// hand-edited permissions.json or a prompt bug cannot make them silent.
const NEVER_ALLOW_CAPABILITIES = new Set(['shell.run']);

// The mode a call actually runs under: a stored "allow" for a
// never-allow capability is treated as "ask". Anything else passes
// through untouched.
function effectivePolicyMode(capability, mode) {
  if (mode === 'allow' && NEVER_ALLOW_CAPABILITIES.has(capability)) return 'ask';
  return mode;
}

// Normalize a permission-prompt answer: for a never-allow capability the
// "always allow" half is forced off, whatever the prompt returned.
function sanitizePromptAnswer(capability, answer) {
  return {
    allowed: Boolean(answer && answer.allowed),
    alwaysAllow: Boolean(answer && answer.alwaysAllow) && !NEVER_ALLOW_CAPABILITIES.has(capability),
    ...(answer && answer.timedOut ? { timedOut: true } : {}),
  };
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
  fs.mkdirSync(userDataPath, { recursive: true });
  fs.writeFileSync(file, JSON.stringify(parsed, null, 2) + '\n');
  console.log(`[permissions] capability ${capability} set to "${value}"`);
}

module.exports = {
  ensurePermissionsPolicy,
  loadPolicy,
  setCapability,
  policyFilePath,
  DEFAULT_POLICY,
  NEVER_ALLOW_CAPABILITIES,
  effectivePolicyMode,
  sanitizePromptAnswer,
};
