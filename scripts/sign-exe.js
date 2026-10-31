#!/usr/bin/env node
// sign-exe.js — Authenticode-sign a built Windows exe with the project's
// self-signed code-signing certificate (CN "Muse Desktop", codeSigning
// EKU; public half published with every release as muse-signing-cert.cer).
// The CN is deliberately neutral — no personal name — because the repo
// is public while the private key itself is never published. Being
// self-signed, the signature only becomes *trusted* on a PC where the
// public cert has been installed into Trusted Root / Trusted
// Publishers — see README "Code signing".
//
// Two toolchains, chosen by platform:
//   - Linux build VM: osslsigncode (no Wine, no Windows SDK here — the
//     same constraint that produced scripts/stamp-exe.js).
//   - Windows (the GitHub Actions release runner): signtool.exe from
//     the Windows SDK, which the runner image carries. Verification
//     there does NOT use `signtool verify`: /pa needs the self-signed
//     cert in a trust store, and importing it into the user Root
//     store raises a consent dialog that hangs a non-interactive
//     session indefinitely (release run #3, 2026-10-30 — the run had
//     to be cancelled). Instead the signed file is verified exactly
//     the way the in-app updater verifies a download: the signer
//     certificate is extracted from the file and its SHA-256
//     fingerprint compared with the constant pinned in
//     src/updater.js.
//
// Certificate + password resolution, first hit wins:
//   pfx:      $MUSE_SIGN_PFX          else signing/muse-signing.pfx
//   password: $MUSE_SIGN_PASSWORD     else signing/pfx-password.txt
//   cert PEM: $MUSE_SIGN_CERT_PEM     else signing/muse-signing-cert.pem
//             (osslsigncode verify anchor only)
// The password is never printed. On the osslsigncode path it is handed
// over via -readpass (a file), so it never appears in argv either; when
// it came from the environment it is staged through a short-lived temp
// file that this script deletes again. On the signtool path it goes to
// /p (GitHub masks secret values in logs; the runner is ephemeral).
//
// Signing happens AFTER scripts/stamp-exe.js (a resource edit would
// invalidate the signature) and in this order in the release chain:
//   pack → stamp → sign inner → dist:portable → verify:portable →
//   sign outer → dist:setup → sign setup
// The inner dist/win-unpacked/Muse.exe is signed before the portable
// and the installer are packed from it (both payloads carry the signed
// exe byte-for-byte); the portable stub and the Setup exe are signed
// last because they are the files Windows SmartScreen evaluates.
//
// Each signature gets an RFC 3161 timestamp from DigiCert
// (http://timestamp.digicert.com) so it stays valid after the cert
// expires. If the timestamp request fails, the script retries WITHOUT
// a timestamp and says so loudly; the BUILD_NOTES/release reporter
// must record that (see `timestamped:` in the per-file result line).
//
// Usage:
//   node scripts/sign-exe.js            sign inner + outer (whichever exist)
//   node scripts/sign-exe.js inner      sign dist/win-unpacked/Muse.exe only
//   node scripts/sign-exe.js outer      sign dist/Muse-Portable.exe only
//   node scripts/sign-exe.js setup      sign dist/Muse-Setup-<version>.exe
//   node scripts/sign-exe.js <exe>      sign that file
// Every file is verified right after signing; any failure exits
// non-zero.
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const projectRoot = path.resolve(__dirname, '..');
const signingDir = path.join(projectRoot, 'signing');
const pfxPath = process.env.MUSE_SIGN_PFX || path.join(signingDir, 'muse-signing.pfx');
const passwordFile = path.join(signingDir, 'pfx-password.txt');
const certPemPath = process.env.MUSE_SIGN_CERT_PEM || path.join(signingDir, 'muse-signing-cert.pem');
const TIMESTAMP_URL = 'http://timestamp.digicert.com';
const IS_WINDOWS = process.platform === 'win32';

function fail(message) {
  console.error(`[sign-exe] ERROR: ${message}`);
  process.exit(1);
}

// Resolve the pfx password once. Returns { value, passFile } where
// passFile is a path osslsigncode can -readpass: the project's own
// password file when the password came from disk, otherwise a temp
// file the caller deletes via cleanup().
function resolvePassword() {
  if (process.env.MUSE_SIGN_PASSWORD) {
    const tmp = path.join(os.tmpdir(), `muse-sign-pass-${process.pid}.txt`);
    fs.writeFileSync(tmp, process.env.MUSE_SIGN_PASSWORD, { mode: 0o600 });
    return {
      value: process.env.MUSE_SIGN_PASSWORD,
      passFile: tmp,
      cleanup() {
        fs.rmSync(tmp, { force: true });
      },
    };
  }
  if (fs.existsSync(passwordFile)) {
    return {
      value: fs.readFileSync(passwordFile, 'utf8').trim(),
      passFile: passwordFile,
      cleanup() {},
    };
  }
  fail('no pfx password available: set MUSE_SIGN_PASSWORD or provide signing/pfx-password.txt');
  return null; // unreachable
}

function runOsslsigncode(args) {
  return execFileSync('osslsigncode', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
}

function signOneOssl(filePath, password) {
  const tmpPath = `${filePath}.sign-tmp`;
  fs.rmSync(tmpPath, { force: true });

  const baseArgs = [
    'sign',
    '-pkcs12', pfxPath,
    '-readpass', password.passFile,
    '-n', 'Muse',
    '-h', 'sha256',
  ];
  let timestamped = true;
  try {
    runOsslsigncode([...baseArgs, '-ts', TIMESTAMP_URL, '-in', filePath, '-out', tmpPath]);
  } catch (err) {
    const detail = `${err.stdout || ''}${err.stderr || ''}`.trim().split('\n').pop() || err.message;
    console.error(`[sign-exe] timestamped signing failed for ${path.basename(filePath)} (${detail}); retrying WITHOUT a timestamp`);
    fs.rmSync(tmpPath, { force: true });
    timestamped = false;
    try {
      runOsslsigncode([...baseArgs, '-in', filePath, '-out', tmpPath]);
    } catch (err2) {
      fail(`osslsigncode sign failed for ${filePath}: ${`${err2.stdout || ''}${err2.stderr || ''}`.trim() || err2.message}`);
    }
  }
  fs.renameSync(tmpPath, filePath);

  // Verify with our own cert as the trust anchor (-CAfile): the cert is
  // self-signed, so chain verification against the system store fails by
  // definition ("Verify error: self-signed certificate") even when the
  // signature is cryptographically sound. The proof that matters — the
  // message digest osslsigncode recomputes from the file matching the
  // signed digest — is printed either way; with the anchor supplied, a
  // good signature ends in "Succeeded".
  let verifyOut;
  try {
    verifyOut = runOsslsigncode(['verify', '-CAfile', certPemPath, '-in', filePath]);
  } catch (err) {
    fail(`osslsigncode verify failed for ${filePath}: ${`${err.stdout || ''}${err.stderr || ''}`.trim() || err.message}`);
  }
  const verdict = verifyOut
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => /signer|timestamp|Succeeded|Failed/i.test(line));
  for (const line of verdict) console.log(`[sign-exe] verify ${path.basename(filePath)}: ${line}`);
  return timestamped;
}

function findSigntool() {
  if (process.env.SIGNTOOL_PATH && fs.existsSync(process.env.SIGNTOOL_PATH)) return process.env.SIGNTOOL_PATH;
  const kitsBin = 'C:\\Program Files (x86)\\Windows Kits\\10\\bin';
  try {
    const versions = fs
      .readdirSync(kitsBin, { withFileTypes: true })
      .filter((e) => e.isDirectory() && /^\d/.test(e.name))
      .map((e) => e.name)
      .sort()
      .reverse();
    for (const version of versions) {
      const candidate = path.join(kitsBin, version, 'x64', 'signtool.exe');
      if (fs.existsSync(candidate)) return candidate;
    }
  } catch {
    // Kits folder absent — fall through to PATH.
  }
  try {
    const where = execFileSync('where', ['signtool'], { encoding: 'utf8' });
    const first = where.split(/\r?\n/)[0].trim();
    if (first) return first;
  } catch {
    // Not on PATH either.
  }
  fail('signtool.exe not found (looked in the Windows Kits bin folders and on PATH)');
  return null; // unreachable
}

function runSigntool(signtool, args) {
  return execFileSync(signtool, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
}

function signOneSigntool(filePath, password) {
  const signtool = findSigntool();
  const baseArgs = ['sign', '/fd', 'sha256', '/f', pfxPath, '/p', password.value, '/d', 'Muse'];
  let timestamped = true;
  try {
    runSigntool(signtool, [...baseArgs, '/tr', TIMESTAMP_URL, '/td', 'sha256', filePath]);
  } catch (err) {
    const detail = `${err.stdout || ''}${err.stderr || ''}`.trim().split('\n').pop() || err.message;
    console.error(`[sign-exe] timestamped signing failed for ${path.basename(filePath)} (${detail}); retrying WITHOUT a timestamp`);
    timestamped = false;
    try {
      runSigntool(signtool, [...baseArgs, filePath]);
    } catch (err2) {
      fail(`signtool sign failed for ${filePath}: ${`${err2.stdout || ''}${err2.stderr || ''}`.trim() || err2.message}`);
    }
  }

  // Verify with the updater's own test (see the header): signer
  // fingerprint extracted from the signed file must equal the pinned
  // constant. No trust store is consulted, so nothing here can hang
  // on a consent dialog.
  const { signerFingerprint256FromExe, PINNED_SIGNER_FINGERPRINT256 } = require('../src/updater');
  const fingerprint = signerFingerprint256FromExe(fs.readFileSync(filePath));
  if (!fingerprint) fail(`no valid signature found in ${filePath} after signing`);
  if (fingerprint !== PINNED_SIGNER_FINGERPRINT256) {
    fail(`signer fingerprint mismatch for ${filePath}: got ${fingerprint}, pinned is ${PINNED_SIGNER_FINGERPRINT256}`);
  }
  console.log(`[sign-exe] verify ${path.basename(filePath)}: signer fingerprint matches the pinned Muse Desktop cert`);
  return timestamped;
}

function signOne(filePath, password) {
  if (!fs.existsSync(filePath)) fail(`exe not found: ${filePath}`);
  if (!fs.existsSync(pfxPath)) fail(`signing certificate not found: ${pfxPath}`);
  const timestamped = IS_WINDOWS ? signOneSigntool(filePath, password) : signOneOssl(filePath, password);
  console.log(
    `[sign-exe] signed ${path.relative(projectRoot, filePath)} (${fs.statSync(filePath).size} bytes), timestamped: ${timestamped}`,
  );
  return { filePath, timestamped };
}

function findSetupExe() {
  const distDir = path.join(projectRoot, 'dist');
  const matches = fs
    .readdirSync(distDir)
    .filter((name) => /^Muse-Setup-.+\.exe$/.test(name))
    .map((name) => path.join(distDir, name));
  if (matches.length === 0) fail('no Muse-Setup-*.exe in dist/ (run npm run dist:setup first)');
  if (matches.length > 1) fail(`multiple Muse-Setup-*.exe in dist/ (${matches.map((m) => path.basename(m)).join(', ')}); sign one explicitly by path`);
  return matches[0];
}

function main() {
  const inner = path.join(projectRoot, 'dist', 'win-unpacked', 'Muse.exe');
  const outer = path.join(projectRoot, 'dist', 'Muse-Portable.exe');
  const arg = process.argv[2];

  let targets;
  if (!arg) {
    targets = [inner, outer].filter((p) => fs.existsSync(p));
    if (targets.length === 0) fail('nothing to sign: neither the inner exe nor the portable artifact exists (run a build first)');
  } else if (arg === 'inner') {
    targets = [inner];
  } else if (arg === 'outer') {
    targets = [outer];
  } else if (arg === 'setup') {
    targets = [findSetupExe()];
  } else {
    targets = [path.resolve(arg)];
  }
  const password = resolvePassword();
  try {
    for (const target of targets) signOne(target, password);
  } finally {
    password.cleanup();
  }
}

main();
