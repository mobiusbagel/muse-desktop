// Tailscale client probes (0.3.1) — the OS-touching half of the smarter
// bridge status. Kept out of bridgeNetwork.js so that module stays pure:
// this file only *gathers facts* ({ binaryPresent, processRunning },
// tri-state true / false / null = unknown) and bridgeNetwork decides
// what they mean for the status line.
//
// Windows only. On any other platform both facts are null (unknown),
// which lands the status on the legacy "not detected" wording. Probed
// fresh on every call — the settings window calls this when it shows /
// refreshes its state, never on a hot path.
'use strict';

const fs = require('fs');
const { execFileSync } = require('child_process');

// Default install location of the official Windows client. A client
// installed somewhere else is a known blind spot (see BUILD_NOTES
// 0.3.1) — the process probe below can still catch it while it runs.
const TAILSCALE_BINARIES = [
  'C:\\Program Files\\Tailscale\\tailscale.exe',
  'C:\\Program Files\\Tailscale\\tailscale-ipn.exe',
];

function tasklistMentionsTailscale(text) {
  if (typeof text !== 'string') return false;
  const lower = text.toLowerCase();
  return lower.includes('tailscale.exe') || lower.includes('tailscale-ipn.exe');
}

function probeTailscaleClient() {
  if (process.platform !== 'win32') {
    return { binaryPresent: null, processRunning: null };
  }
  let binaryPresent = false;
  for (const candidate of TAILSCALE_BINARIES) {
    try {
      if (fs.existsSync(candidate)) {
        binaryPresent = true;
        break;
      }
    } catch {
      // An unreadable path is treated as absent, not as a crash.
    }
  }
  let processRunning = null;
  try {
    const out = execFileSync('tasklist', ['/fo', 'csv', '/nh'], {
      timeout: 2000,
      encoding: 'utf8',
      windowsHide: true,
    });
    processRunning = tasklistMentionsTailscale(out);
  } catch {
    processRunning = null; // tasklist failed — unknown, not "not running"
  }
  return { binaryPresent, processRunning };
}

module.exports = { probeTailscaleClient, tasklistMentionsTailscale };
