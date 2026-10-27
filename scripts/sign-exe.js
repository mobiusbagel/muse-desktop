#!/usr/bin/env node
// sign-exe.js — Authenticode-sign a built Windows exe with the project's
// self-signed code-signing certificate, using osslsigncode (no Wine, no
// Windows SDK on this build machine — same constraint that produced
// scripts/stamp-exe.js).
//
// The certificate is the project's self-signed code-signing cert
// (signing/muse-signing.pfx, CN "Muse Desktop", codeSigning EKU;
// public half in signing/muse-signing-cert.cer). The CN is deliberately
// neutral — no personal name — because the repo may be public while
// signing/ itself is never published. Being self-signed, the
// signature only becomes *trusted* on a PC where the public cert has
// been installed into Trusted Root / Trusted Publishers — see README
// "Code signing". The .pfx password is read from
// signing/pfx-password.txt at run time and is never printed here (it is
// handed to osslsigncode via -readpass, so it never appears in argv
// either).
//
// Signing happens AFTER scripts/stamp-exe.js (a resource edit would
// invalidate the signature) and in two places in the release order:
//   pack → stamp → sign inner → dist:portable → verify:portable → sign outer
// The inner dist/win-unpacked/Muse.exe is signed before the portable is
// packed from it (the portable payload carries the signed exe
// byte-for-byte), and the portable stub itself is signed last because
// it is the file Windows SmartScreen evaluates.
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
//   node scripts/sign-exe.js <exe>      sign that file
// Every file is verified with `osslsigncode verify` right after signing;
// any failure exits non-zero.
'use strict';

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const projectRoot = path.resolve(__dirname, '..');
const signingDir = path.join(projectRoot, 'signing');
const pfxPath = path.join(signingDir, 'muse-signing.pfx');
const passwordFile = path.join(signingDir, 'pfx-password.txt');
const certPemPath = path.join(signingDir, 'muse-signing-cert.pem');
const TIMESTAMP_URL = 'http://timestamp.digicert.com';

function fail(message) {
  console.error(`[sign-exe] ERROR: ${message}`);
  process.exit(1);
}

function runOsslsigncode(args) {
  return execFileSync('osslsigncode', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
}

function signOne(filePath) {
  if (!fs.existsSync(filePath)) fail(`exe not found: ${filePath}`);
  if (!fs.existsSync(pfxPath)) fail(`signing certificate not found: ${pfxPath}`);
  if (!fs.existsSync(passwordFile)) fail(`pfx password file not found: ${passwordFile}`);
  const tmpPath = `${filePath}.sign-tmp`;
  fs.rmSync(tmpPath, { force: true });

  const baseArgs = [
    'sign',
    '-pkcs12', pfxPath,
    '-readpass', passwordFile,
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
  console.log(
    `[sign-exe] signed ${path.relative(projectRoot, filePath)} (${fs.statSync(filePath).size} bytes), timestamped: ${timestamped}`,
  );
  return { filePath, timestamped };
}

function main() {
  const pkg = JSON.parse(fs.readFileSync(path.join(projectRoot, 'package.json'), 'utf8'));
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
  } else {
    targets = [path.resolve(arg)];
  }
  for (const target of targets) signOne(target);
}

main();
