// Bridge Activity (0.4.0): turns bridge-audit.log into plain-language
// lines for the tray's Bridge Activity window. Electron-free and
// tolerant by design — the log is append-only JSONL, but a truncated
// or hand-edited line must never break the viewer: malformed lines are
// skipped, a missing file is an empty list.
//
// Entry shape in the log (see bridgeAudit.js / rpc.js):
//   { ts, method, params: {summary}, decision, outcome, error? }
// plus app-internal events such as { ts, event: 'tailnet_listener_bound',
// address } and token rejections with method: null.
'use strict';

const fs = require('fs');
const path = require('path');
const { AUDIT_FILENAME } = require('./bridgeAudit');

const DEFAULT_ACTIVITY_LIMIT = 200;

// Parse JSONL audit text. Returns the entries in file order (oldest
// first); anything that isn't a JSON object is skipped.
function parseAuditLogText(text) {
  const entries = [];
  if (typeof text !== 'string') return entries;
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const parsed = JSON.parse(trimmed);
      if (parsed && typeof parsed === 'object') entries.push(parsed);
    } catch {
      // Malformed line — skip it, keep the rest of the log readable.
    }
  }
  return entries;
}

// Local time as "2026-10-26 20:15:03" (the machine the user is sitting
// at — the log's ISO timestamps are UTC).
function formatLocalTime(ts) {
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return typeof ts === 'string' ? ts : '';
  const pad = (n) => String(n).padStart(2, '0');
  return (
    `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ` +
    `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
  );
}

// A one-line human summary of what was called. Phrasing follows the rpc
// layer's prompt descriptions where they exist ("Launch: …",
// "Kill process pid …", "List running processes").
function describeEntry(entry) {
  const params = entry.params && typeof entry.params === 'object' ? entry.params : {};
  switch (entry.method) {
    case 'fs.list':
      return `List: ${params.path ?? ''}`;
    case 'fs.read':
      return `Read: ${params.path ?? ''}`;
    case 'fs.write':
      return `Write: ${params.path ?? ''}`;
    case 'fs.mkdir':
      return `Create folder: ${params.path ?? ''}`;
    case 'app.launch':
      return `Launch: ${params.target ?? ''}`;
    case 'process.list':
      return 'List running processes';
    case 'process.kill':
      return `Kill process pid ${params.pid ?? ''}`;
    case 'shell.run':
      return `Run command: ${params.summary ?? ''}`;
    case 'screen.capture':
      // Dimensions ride in the audit summary (never image data).
      return params.width && params.height ? `Screenshot: ${params.width}x${params.height}` : 'Screenshot';
    case 'screen.list':
      // The display count rides in the audit summary.
      return Number.isInteger(params.count) ? `List displays: ${params.count}` : 'List displays';
    case null:
    case undefined:
      if (entry.event === 'tailnet_listener_bound') {
        return `Remote access: Tailscale listener bound (${entry.address ?? ''})`;
      }
      if (entry.event === 'update_rejected') {
        return `Update rejected: ${entry.version ?? ''}`.trim();
      }
      if (entry.event === 'update_apply_started') {
        return `Update apply started: ${entry.version ?? ''}`.trim();
      }
      if (entry.event === 'update_restore_started') {
        return `Update restore started: ${entry.version ?? ''}`.trim();
      }
      return 'Bridge call';
    default:
      return String(entry.method);
  }
}

// The decision in plain words.
function decisionText(entry) {
  switch (entry.decision) {
    case 'allow':
      return 'allowed by policy';
    case 'ask-granted':
      return 'allowed';
    case 'ask-denied':
      return 'denied';
    case 'ask-timeout':
      return 'timed out';
    case 'deny':
      return 'denied by policy';
    case 'auth-rejected':
      return 'auth rejected';
    case 'update-apply':
      return 'applying';
    case 'update-restore':
      return 'restoring';
    case 'scope-refused':
      return 'scope refused';
    case 'storage-moving':
      return 'refused — folder moving';
    case 'unknown-method':
      return 'unknown method';
    default:
      return entry.decision ? String(entry.decision) : '';
  }
}

// The outcome: "ok", or the error code when the call failed/refused.
function outcomeText(entry) {
  if (entry.outcome === 'ok') return 'ok';
  if (entry.error) return String(entry.error);
  return entry.outcome ? String(entry.outcome) : '';
}

function formatActivityEntry(entry) {
  return {
    time: formatLocalTime(entry.ts),
    summary: describeEntry(entry),
    decision: decisionText(entry),
    outcome: outcomeText(entry),
  };
}

// Formatted lines, newest first, capped at `limit` (default: last 200).
function formatActivity(entries, limit = DEFAULT_ACTIVITY_LIMIT) {
  const list = Array.isArray(entries) ? entries : [];
  return list.slice(-limit).reverse().map(formatActivityEntry);
}

// Read + parse + format the audit log under userDataPath. A missing
// file is an empty activity list, never an error.
function readBridgeActivity(userDataPath, limit = DEFAULT_ACTIVITY_LIMIT) {
  let text = '';
  try {
    text = fs.readFileSync(path.join(userDataPath, AUDIT_FILENAME), 'utf8');
  } catch {
    return [];
  }
  return formatActivity(parseAuditLogText(text), limit);
}

module.exports = {
  parseAuditLogText,
  formatLocalTime,
  describeEntry,
  decisionText,
  outcomeText,
  formatActivityEntry,
  formatActivity,
  readBridgeActivity,
  DEFAULT_ACTIVITY_LIMIT,
};
