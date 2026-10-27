// Bridge audit log (Phase 2).
// One JSON line per /rpc call appended to userData/bridge-audit.log:
// timestamp, method, a summary of params (paths / targets / pids — never
// file contents), the policy decision, and the outcome. Best effort: a
// failed audit write must never break a tool call, so errors are logged
// to the console and swallowed.
'use strict';

const fs = require('fs');
const path = require('path');

const AUDIT_FILENAME = 'bridge-audit.log';

function appendAuditLog(userDataPath, entry) {
  try {
    const file = path.join(userDataPath, AUDIT_FILENAME);
    fs.mkdirSync(userDataPath, { recursive: true });
    fs.appendFileSync(file, JSON.stringify(entry) + '\n');
  } catch (err) {
    console.error('[bridge-audit] could not append audit entry:', err.message);
  }
}

module.exports = { appendAuditLog, AUDIT_FILENAME };
