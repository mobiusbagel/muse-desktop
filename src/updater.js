// In-app updater (0.5.0).
//
// Source of truth: GitHub Releases of the public repo
// (mobiusbagel/muse-desktop). A check reads the latest release,
// downloads the portable exe + SHA256SUMS.txt into userData/updates/,
// and verifies BOTH of these before anything is offered:
//
//   1. the exe's SHA-256 matches its line in SHA256SUMS.txt, and
//   2. the exe's Authenticode signer certificate SHA-256 fingerprint
//      equals PINNED_SIGNER_FINGERPRINT256 (the Muse Desktop
//      code-signing cert — see signing/muse-signing-cert.cer and the
//      README "Code signing" section).
//
// Verification is fail-closed: any failure deletes the download,
// writes an audit-log line, and offers nothing. Only a verified
// download produces the "ready" prompt, and applying it is a
// self-swap that only works in portable runs
// (process.env.PORTABLE_EXECUTABLE_FILE) — the app replaces its own
// exe file, which is also why this kills the SmartScreen prompt for
// updates: a file the app writes itself carries no Mark of the Web,
// unlike a browser download.
//
// Electron-free by design (same pattern as rpc.js): every outside
// dependency — fetch, audit sink, the ready prompt, process spawn —
// is injected, so the whole flow is unit-testable in plain Node.
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const { Readable } = require('stream');
const { pipeline } = require('stream/promises');

// The one and only place the trusted signer is pinned. This is the
// SHA-256 fingerprint (DER) of signing/muse-signing-cert.cer — the
// Muse Desktop code-signing certificate every release build is
// signed with (see scripts/sign-exe.js and README "Code signing").
const PINNED_SIGNER_FINGERPRINT256 =
  '0E:C7:DE:56:5D:F4:D6:70:32:07:47:5F:84:09:26:12:3D:03:BE:1B:8F:3D:38:C5:88:5F:22:D6:22:14:3B:DF';

const GITHUB_REPO = 'mobiusbagel/muse-desktop';
const LATEST_RELEASE_URL = `https://api.github.com/repos/${GITHUB_REPO}/releases/latest`;
const SUMS_ASSET_NAME = 'SHA256SUMS.txt';
const USER_AGENT = 'Muse-Desktop-Updater';
const SWAP_SCRIPT_NAME = 'apply-update.ps1';

// ---------------------------------------------------------------------------
// Versions (tiny semver: numeric core + optional prerelease)
// ---------------------------------------------------------------------------

function parseVersion(input) {
  if (typeof input !== 'string') return null;
  const m = /^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/.exec(input.trim());
  if (!m) return null;
  return {
    core: [Number(m[1]), Number(m[2]), Number(m[3])],
    pre: m[4] ? m[4].split('.') : [],
  };
}

function comparePrerelease(a, b) {
  if (a.length === 0 && b.length === 0) return 0;
  if (a.length === 0) return 1; // a release outranks any prerelease
  if (b.length === 0) return -1;
  for (let i = 0; i < Math.max(a.length, b.length); i += 1) {
    if (i >= a.length) return -1; // prefix-equal: the shorter list is smaller
    if (i >= b.length) return 1;
    const x = a[i];
    const y = b[i];
    if (x === y) continue;
    const xNum = /^\d+$/.test(x);
    const yNum = /^\d+$/.test(y);
    if (xNum && yNum) return Number(x) < Number(y) ? -1 : 1;
    if (xNum) return -1; // numeric identifiers rank below alphanumeric
    if (yNum) return 1;
    return x < y ? -1 : 1;
  }
  return 0;
}

// -1 / 0 / 1, or null when either side is unparseable.
function compareVersions(a, b) {
  const pa = typeof a === 'string' ? parseVersion(a) : a;
  const pb = typeof b === 'string' ? parseVersion(b) : b;
  if (!pa || !pb) return null;
  for (let i = 0; i < 3; i += 1) {
    if (pa.core[i] !== pb.core[i]) return pa.core[i] < pb.core[i] ? -1 : 1;
  }
  return comparePrerelease(pa.pre, pb.pre);
}

function isNewerVersion(candidate, current) {
  const cmp = compareVersions(candidate, current);
  return cmp !== null && cmp > 0;
}

// ---------------------------------------------------------------------------
// Release JSON
// ---------------------------------------------------------------------------

function exeAssetName(version) {
  return `Muse-Portable-${version}.exe`;
}

// Turns a GitHub "latest release" payload into an offer, or explains
// why there is none. No offer unless the tag is strictly newer AND
// both the exe asset and SHA256SUMS.txt are present.
function parseLatestRelease(json, currentVersion) {
  if (!json || typeof json !== 'object' || typeof json.tag_name !== 'string') {
    return { offer: null, reason: 'no-tag' };
  }
  const version = json.tag_name.replace(/^v/, '');
  if (!parseVersion(version)) return { offer: null, reason: 'bad-tag' };
  if (!isNewerVersion(version, currentVersion)) return { offer: null, reason: 'not-newer' };
  const assets = Array.isArray(json.assets) ? json.assets : [];
  const exeName = exeAssetName(version);
  const exe = assets.find((a) => a && a.name === exeName);
  if (!exe || typeof exe.browser_download_url !== 'string') {
    return { offer: null, reason: 'missing-exe-asset' };
  }
  const sums = assets.find((a) => a && a.name === SUMS_ASSET_NAME);
  if (!sums || typeof sums.browser_download_url !== 'string') {
    return { offer: null, reason: 'missing-sums-asset' };
  }
  return {
    offer: {
      version,
      tag: json.tag_name,
      exeName,
      exeUrl: exe.browser_download_url,
      sumsUrl: sums.browser_download_url,
    },
  };
}

// ---------------------------------------------------------------------------
// SHA-256 checksums
// ---------------------------------------------------------------------------

function sha256File(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);
    stream.on('error', reject);
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
  });
}

// "<hex>  <name>" or "<hex> *<name>" lines → Map(name → lowercase hex).
function parseSha256Sums(text) {
  const map = new Map();
  if (typeof text !== 'string') return map;
  for (const line of text.split(/\r?\n/)) {
    const m = /^([0-9a-fA-F]{64})[ \t]+\*?(.+?)\s*$/.exec(line.trim());
    if (m) map.set(m[2], m[1].toLowerCase());
  }
  return map;
}

async function verifyChecksum(exePath, sumsPath, exeName) {
  let sumsText;
  try {
    sumsText = fs.readFileSync(sumsPath, 'utf8');
  } catch {
    return false;
  }
  const expected = parseSha256Sums(sumsText).get(exeName);
  if (!expected) return false;
  let actual;
  try {
    actual = await sha256File(exePath);
  } catch {
    return false;
  }
  return actual.toLowerCase() === expected;
}

// ---------------------------------------------------------------------------
// Authenticode signer fingerprint (PE certificate table → PKCS#7 → cert)
// ---------------------------------------------------------------------------

function formatFingerprint256(hex) {
  return hex
    .toUpperCase()
    .match(/../g)
    .join(':');
}

function fingerprint256OfCertDer(der) {
  return formatFingerprint256(crypto.createHash('sha256').update(der).digest('hex'));
}

// Reads the PE security directory (data directory 4). Its "virtual
// address" field is a file offset for this one directory. Returns the
// first PKCS#7 (WIN_CERT_TYPE_PKCS_SIGNED_DATA) blob, or null.
function readCertificateTable(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 0x40 + 4) return null;
  if (buf[0] !== 0x4d || buf[1] !== 0x5a) return null; // "MZ"
  const peOffset = buf.readUInt32LE(0x3c);
  if (peOffset + 24 > buf.length) return null;
  if (buf.readUInt32LE(peOffset) !== 0x4550) return null; // "PE\0\0"
  const coff = peOffset + 4;
  const optionalSize = buf.readUInt16LE(coff + 16);
  const optional = coff + 20;
  if (optional + optionalSize > buf.length || optionalSize < 2) return null;
  const magic = buf.readUInt16LE(optional);
  const dataDirs = optional + (magic === 0x20b ? 112 : magic === 0x10b ? 96 : -1);
  if (dataDirs < 0) return null;
  const securityEntry = dataDirs + 4 * 8;
  if (securityEntry + 8 > optional + optionalSize) return null;
  const tableOffset = buf.readUInt32LE(securityEntry);
  const tableSize = buf.readUInt32LE(securityEntry + 4);
  if (!tableOffset || !tableSize || tableOffset + tableSize > buf.length) return null;
  let offset = tableOffset;
  const end = tableOffset + tableSize;
  while (offset + 8 <= end) {
    const length = buf.readUInt32LE(offset);
    const type = buf.readUInt16LE(offset + 6);
    if (length < 8 || offset + length > buf.length) return null;
    if (type === 0x0002) return buf.subarray(offset + 8, offset + length);
    offset += Math.ceil(length / 8) * 8; // entries are 8-byte aligned
  }
  return null;
}

// --- minimal DER walker (single-byte tags, definite lengths) ---------------

function readTlv(buf, offset) {
  if (offset + 2 > buf.length) return null;
  const tag = buf[offset];
  if ((tag & 0x1f) === 0x1f) return null; // multi-byte tags: not in these structures
  let p = offset + 1;
  let length = buf[p];
  p += 1;
  if (length & 0x80) {
    const count = length & 0x7f;
    if (count === 0 || count > 4 || p + count > buf.length) return null;
    length = 0;
    for (let i = 0; i < count; i += 1) length = length * 256 + buf[p + i];
    p += count;
  }
  if (p + length > buf.length) return null;
  return { tag, headerLength: p - offset, length, contentStart: p, total: p - offset + length };
}

function tlvChildren(buf, tlv) {
  const children = [];
  let offset = tlv.contentStart;
  const end = tlv.contentStart + tlv.length;
  while (offset < end) {
    const child = readTlv(buf, offset);
    if (!child) return null;
    children.push({ tlv: child, start: offset });
    offset += child.total;
  }
  return offset === end ? children : null;
}

function stripLeadingZeros(buf) {
  let i = 0;
  while (i < buf.length - 1 && buf[i] === 0) i += 1;
  return buf.subarray(i);
}

const SIGNED_DATA_OID = Buffer.from([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02]);

// Extracts the signer certificate's SHA-256 fingerprint from a PKCS#7
// SignedData blob: the certificate in the bag whose issuer + serial
// match the first SignerInfo. Returns null on any structural surprise
// (fail-closed — callers treat null as "not our signer").
function signerFingerprint256FromPkcs7(pkcs7) {
  if (!Buffer.isBuffer(pkcs7)) return null;
  const outer = readTlv(pkcs7, 0);
  if (!outer || outer.tag !== 0x30) return null;
  const contentInfo = tlvChildren(pkcs7, outer);
  if (!contentInfo || contentInfo.length < 2) return null;
  const oidTlv = contentInfo[0].tlv;
  const oidBytes = pkcs7.subarray(oidTlv.contentStart, oidTlv.contentStart + oidTlv.length);
  if (!oidBytes.equals(SIGNED_DATA_OID)) return null;
  const explicit = contentInfo[1].tlv;
  if (explicit.tag !== 0xa0) return null;
  const signedData = readTlv(pkcs7, explicit.contentStart);
  if (!signedData || signedData.tag !== 0x30) return null;
  const parts = tlvChildren(pkcs7, signedData);
  if (!parts) return null;

  const certBag = parts.find((c) => c.tlv.tag === 0xa0);
  if (!certBag) return null;
  const certElements = tlvChildren(pkcs7, certBag.tlv);
  if (!certElements) return null;
  const certs = [];
  for (const el of certElements) {
    if (el.tlv.tag !== 0x30) continue;
    const der = pkcs7.subarray(el.start, el.start + el.tlv.total);
    const fields = tlvChildren(pkcs7, el.tlv);
    if (!fields || fields.length === 0) continue;
    const tbs = fields[0];
    const tbsFields = tlvChildren(pkcs7, tbs.tlv);
    if (!tbsFields || tbsFields.length < 4) continue;
    let idx = 0;
    if (tbsFields[0].tlv.tag === 0xa0) idx = 1; // optional [0] version
    const serialTlv = tbsFields[idx].tlv;
    const issuerEl = tbsFields[idx + 2];
    if (!serialTlv || !issuerEl) continue;
    certs.push({
      der,
      serial: pkcs7.subarray(serialTlv.contentStart, serialTlv.contentStart + serialTlv.length),
      issuerDer: pkcs7.subarray(issuerEl.start, issuerEl.start + issuerEl.tlv.total),
    });
  }
  if (certs.length === 0) return null;

  const signerInfosEl = parts[parts.length - 1];
  if (!signerInfosEl || signerInfosEl.tlv.tag !== 0x31) return null;
  const signerInfos = tlvChildren(pkcs7, signerInfosEl.tlv);
  if (!signerInfos || signerInfos.length === 0) return null;
  const signerInfo = tlvChildren(pkcs7, signerInfos[0].tlv);
  if (!signerInfo || signerInfo.length < 2) return null;
  const issuerAndSerial = tlvChildren(pkcs7, signerInfo[1].tlv);
  if (!issuerAndSerial || issuerAndSerial.length < 2) return null;
  const refIssuerDer = pkcs7.subarray(
    issuerAndSerial[0].start,
    issuerAndSerial[0].start + issuerAndSerial[0].tlv.total,
  );
  const refSerialTlv = issuerAndSerial[1].tlv;
  const refSerial = pkcs7.subarray(refSerialTlv.contentStart, refSerialTlv.contentStart + refSerialTlv.length);

  for (const cert of certs) {
    if (stripLeadingZeros(cert.serial).equals(stripLeadingZeros(refSerial)) && cert.issuerDer.equals(refIssuerDer)) {
      return fingerprint256OfCertDer(cert.der);
    }
  }
  return null;
}

// The signer fingerprint of a signed exe file's bytes — null when the
// file is unsigned or the signature doesn't parse.
function signerFingerprint256FromExe(exeBytes) {
  const pkcs7 = readCertificateTable(exeBytes);
  if (!pkcs7) return null;
  return signerFingerprint256FromPkcs7(pkcs7);
}

// ---------------------------------------------------------------------------
// Fail-closed verification of a downloaded update
// ---------------------------------------------------------------------------

// BOTH checks must pass; the result names the first failure so the
// audit line (and a human) can tell a tampered checksum from a
// foreign signer.
async function verifyDownloadedUpdate({ exePath, sumsPath, exeName, pinnedFingerprint = PINNED_SIGNER_FINGERPRINT256 }) {
  if (!(await verifyChecksum(exePath, sumsPath, exeName))) {
    return { ok: false, reason: 'checksum-mismatch' };
  }
  let exeBytes;
  try {
    exeBytes = fs.readFileSync(exePath);
  } catch {
    return { ok: false, reason: 'exe-unreadable' };
  }
  const fingerprint = signerFingerprint256FromExe(exeBytes);
  if (!fingerprint) return { ok: false, reason: 'no-valid-signature' };
  if (fingerprint !== pinnedFingerprint) return { ok: false, reason: 'signer-mismatch' };
  return { ok: true };
}

// ---------------------------------------------------------------------------
// The self-swap script (portable runs only)
// ---------------------------------------------------------------------------

function psQuote(value) {
  return `'${String(value).replace(/'/g, "''")}'`;
}

// PowerShell run detached after the app quits: waits for this process
// to exit, replaces the portable exe with the verified download,
// relaunches it, and removes the downloaded copy + itself.
function buildSwapScript({ pid, currentExePath, newExePath }) {
  return [
    "$ErrorActionPreference = 'SilentlyContinue'",
    `$targetPid = ${Number(pid) || 0}`,
    `$newExe = ${psQuote(newExePath)}`,
    `$targetExe = ${psQuote(currentExePath)}`,
    'if ($targetPid -gt 0) { Wait-Process -Id $targetPid -Timeout 60 -ErrorAction SilentlyContinue }',
    'Start-Sleep -Milliseconds 400',
    'for ($i = 0; $i -lt 40; $i++) {',
    '  try { Copy-Item -LiteralPath $newExe -Destination $targetExe -Force -ErrorAction Stop; break }',
    '  catch { Start-Sleep -Milliseconds 500 }',
    '}',
    'Start-Process -FilePath $targetExe',
    'Remove-Item -LiteralPath $newExe -Force -ErrorAction SilentlyContinue',
    'Remove-Item -LiteralPath $PSCommandPath -Force -ErrorAction SilentlyContinue',
    '',
  ].join('\r\n');
}

function defaultSpawnSwapScript(scriptPath) {
  const child = spawn(
    'powershell.exe',
    ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden', '-File', scriptPath],
    { detached: true, stdio: 'ignore', windowsHide: true },
  );
  child.unref();
  return child;
}

// ---------------------------------------------------------------------------
// Downloads
// ---------------------------------------------------------------------------

async function defaultDownloadToFile(fetchImpl, url, destPath) {
  const res = await fetchImpl(url, {
    headers: { 'User-Agent': USER_AGENT, Accept: 'application/octet-stream' },
    redirect: 'follow',
  });
  if (!res || !res.ok) throw new Error(`download failed: HTTP ${res ? res.status : 'no response'}`);
  if (!res.body) throw new Error('download failed: empty body');
  await pipeline(Readable.fromWeb(res.body), fs.createWriteStream(destPath));
}

// ---------------------------------------------------------------------------
// The updater
// ---------------------------------------------------------------------------

function createUpdater(deps) {
  const {
    currentVersion,
    userDataPath,
    canApply = false,
    getCurrentExePath = () => process.env.PORTABLE_EXECUTABLE_FILE,
    fetchImpl = (...args) => globalThis.fetch(...args),
    downloadToFile = defaultDownloadToFile,
    audit = () => {},
    onReady = () => {},
    onApplyStarted = () => {},
    spawnSwapScript = defaultSpawnSwapScript,
    getPid = () => process.pid,
  } = deps;

  const updatesRoot = path.join(userDataPath, 'updates');
  let state = {
    state: 'idle', // idle | checking | up-to-date | ready | error
    pendingVersion: null,
    pendingExePath: null,
    error: null,
  };
  let inFlight = null;

  function getState() {
    return { ...state, currentVersion, canApply };
  }

  function versionDir(version) {
    return path.join(updatesRoot, version);
  }

  // A leftover swap script from an applied update removes itself; if
  // it couldn't (killed mid-run), main calls this at startup.
  function cleanupStaleArtifacts() {
    try {
      fs.rmSync(path.join(updatesRoot, SWAP_SCRIPT_NAME), { force: true });
    } catch {
      // best effort only
    }
  }

  async function runCheck() {
    state = { ...state, state: 'checking', error: null };
    let json;
    try {
      const res = await fetchImpl(LATEST_RELEASE_URL, {
        headers: { 'User-Agent': USER_AGENT, Accept: 'application/vnd.github+json' },
        redirect: 'follow',
        signal: typeof AbortSignal !== 'undefined' && AbortSignal.timeout ? AbortSignal.timeout(30_000) : undefined,
      });
      if (!res || !res.ok) throw new Error(`release check failed: HTTP ${res ? res.status : 'no response'}`);
      json = await res.json();
    } catch (err) {
      state = { ...state, state: 'error', error: err.message };
      return getState();
    }

    const { offer, reason } = parseLatestRelease(json, currentVersion);
    if (!offer) {
      state = {
        ...state,
        state: reason === 'not-newer' || reason === 'no-tag' || reason === 'bad-tag' ? 'up-to-date' : 'error',
        error: reason === 'not-newer' || reason === 'no-tag' || reason === 'bad-tag' ? null : reason,
        pendingVersion: null,
        pendingExePath: null,
      };
      return getState();
    }

    const dir = versionDir(offer.version);
    const exePath = path.join(dir, offer.exeName);
    const sumsPath = path.join(dir, SUMS_ASSET_NAME);
    try {
      const alreadyDownloaded = fs.existsSync(exePath) && fs.existsSync(sumsPath);
      if (!alreadyDownloaded) {
        // One pending version at a time: other version dirs go away.
        fs.mkdirSync(updatesRoot, { recursive: true });
        for (const entry of fs.readdirSync(updatesRoot, { withFileTypes: true })) {
          if (entry.isDirectory() && entry.name !== offer.version) {
            fs.rmSync(path.join(updatesRoot, entry.name), { recursive: true, force: true });
          }
        }
        fs.mkdirSync(dir, { recursive: true });
        await downloadToFile(fetchImpl, offer.exeUrl, exePath);
        await downloadToFile(fetchImpl, offer.sumsUrl, sumsPath);
      }
    } catch (err) {
      fs.rmSync(dir, { recursive: true, force: true });
      state = { ...state, state: 'error', error: err.message, pendingVersion: null, pendingExePath: null };
      return getState();
    }

    // Fail-closed: BOTH the checksum and the signer fingerprint must
    // verify before the update is offered. Any failure deletes the
    // download and leaves an audit line.
    const verdict = await verifyDownloadedUpdate({ exePath, sumsPath, exeName: offer.exeName });
    if (!verdict.ok) {
      fs.rmSync(dir, { recursive: true, force: true });
      audit({
        ts: new Date().toISOString(),
        event: 'update_rejected',
        version: offer.version,
        decision: 'update-rejected',
        outcome: 'refused',
        error: verdict.reason,
      });
      state = { ...state, state: 'error', error: verdict.reason, pendingVersion: null, pendingExePath: null };
      return getState();
    }

    state = { ...state, state: 'ready', pendingVersion: offer.version, pendingExePath: exePath, error: null };
    onReady({ version: offer.version, exePath, canApply });
    return getState();
  }

  function check() {
    if (inFlight) return inFlight;
    inFlight = runCheck().finally(() => {
      inFlight = null;
    });
    return inFlight;
  }

  // Applies the verified pending update. Only portable runs can
  // replace their own exe; anything else is refused here (the UI
  // disables the action with a one-line reason before this).
  function apply() {
    if (state.state !== 'ready' || !state.pendingExePath) {
      return { ok: false, reason: 'no-verified-update' };
    }
    if (!canApply) return { ok: false, reason: 'not-portable' };
    const currentExePath = getCurrentExePath();
    if (!currentExePath) return { ok: false, reason: 'not-portable' };
    const scriptPath = path.join(updatesRoot, SWAP_SCRIPT_NAME);
    const script = buildSwapScript({ pid: getPid(), currentExePath, newExePath: state.pendingExePath });
    fs.writeFileSync(scriptPath, script);
    spawnSwapScript(scriptPath);
    onApplyStarted();
    return { ok: true };
  }

  return { check, apply, getState, cleanupStaleArtifacts, updatesRoot };
}

module.exports = {
  PINNED_SIGNER_FINGERPRINT256,
  GITHUB_REPO,
  LATEST_RELEASE_URL,
  SUMS_ASSET_NAME,
  parseVersion,
  compareVersions,
  isNewerVersion,
  exeAssetName,
  parseLatestRelease,
  sha256File,
  parseSha256Sums,
  verifyChecksum,
  readCertificateTable,
  signerFingerprint256FromPkcs7,
  signerFingerprint256FromExe,
  fingerprint256OfCertDer,
  verifyDownloadedUpdate,
  psQuote,
  buildSwapScript,
  defaultDownloadToFile,
  createUpdater,
};
