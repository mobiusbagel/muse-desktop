// Bridge authentication groundwork (Phase 2).
// On first run a random per-install token is generated and stored in
// userData/bridge-token.txt. The bridge's /rpc endpoint (and /storage)
// require it in the X-Bridge-Token header, so a random local process or
// web page cannot drive the tools just by finding the port. Phase 3 will
// hand this token to the Muse connector over Tailscale.
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const TOKEN_FILENAME = 'bridge-token.txt';

function tokenFilePath(userDataPath) {
  return path.join(userDataPath, TOKEN_FILENAME);
}

// Returns the existing token, or generates and stores a new one.
function ensureBridgeToken(userDataPath) {
  const file = tokenFilePath(userDataPath);
  try {
    const existing = fs.readFileSync(file, 'utf8').trim();
    if (existing.length >= 32) {
      console.log('[bridge-auth] token loaded from:', file);
      return existing;
    }
  } catch {
    // No token yet — fall through and generate one.
  }
  const token = crypto.randomBytes(32).toString('hex');
  fs.mkdirSync(userDataPath, { recursive: true });
  // 0600: only the owning user can read it (best effort on Windows).
  fs.writeFileSync(file, token + '\n', { mode: 0o600 });
  console.log('[bridge-auth] generated new token:', file);
  return token;
}

// Constant-time comparison; non-strings never match.
function tokenMatches(provided, expected) {
  if (typeof provided !== 'string' || typeof expected !== 'string') return false;
  const a = Buffer.from(provided);
  const b = Buffer.from(expected);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

module.exports = { ensureBridgeToken, tokenMatches, tokenFilePath };
