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
// 0.5.2 reworked the apply mechanism (see "The self-swap" below):
// in 0.5.0/0.5.1 the swap script was spawned as a child of the app
// and died with the portable stub's process-tree teardown — the
// app closed and nothing else happened. The swap is now launched
// through WMI so it survives the app, and it logs every step to
// updates/apply-update.log, whose tail the app reads at boot to
// report the last apply's outcome in the settings Updates row.
//
// Electron-free by design (same pattern as rpc.js): every outside
// dependency — fetch, audit sink, the ready prompt, process spawn —
// is injected, so the whole flow is unit-testable in plain Node.
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { spawn, spawnSync } = require('child_process');
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
const APPLY_LOG_NAME = 'apply-update.log';
// Copy retries in the swap script: ~60 s at a 500 ms cadence. The
// portable stub can hold the exe image briefly after the app exits,
// so the copy has to out-wait it rather than give up in seconds.
const MAX_COPY_ATTEMPTS = 120;

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

// From 0.5.3 the portable's name is version-free: the release asset
// is ALWAYS Muse-Portable.exe, for every future release. The
// version lives in the release tag and in the app's Settings window,
// not in the filename — and an in-app apply replaces the running
// file's contents under whatever name it already has.
const EXE_ASSET_NAME = 'Muse-Portable.exe';

function exeAssetName() {
  return EXE_ASSET_NAME;
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
  const exeName = exeAssetName();
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
// The self-swap (portable runs only) — reworked in 0.5.2
// ---------------------------------------------------------------------------
//
// The 0.5.0/0.5.1 mechanism spawned the swap script as a detached
// child of the app — and in the field it produced zero observable
// effects: the app closed, no copy, no relaunch, no trace. The
// consistent explanation is that the NSIS portable stub tears down
// its whole process tree/job on exit and the "detached" child dies
// with it (detached + unref does not escape a job object). 0.5.2
// therefore launches the script through WMI (Win32_Process.Create),
// which parents it to the WMI service — outside the app's tree —
// and the script itself logs every step to apply-update.log so no
// future failure is silent.

function psQuote(value) {
  return `'${String(value).replace(/'/g, "''")}'`;
}

// The swap script: waits for the app process to exit, replaces the
// portable exe with the verified download (retrying for ~60 s while
// the stub lets go of the image), ALWAYS relaunches the target
// afterwards — old exe or new, the user is never left with a closed
// app and nothing running — and appends a timestamped line per step
// to the apply log. The downloaded copy is removed only on success;
// on failure it stays, verified, for the next attempt.
function buildSwapScript({ pid, currentExePath, newExePath, logPath, targetVersion }) {
  return [
    "$ErrorActionPreference = 'SilentlyContinue'",
    `$targetPid = ${Number(pid) || 0}`,
    `$newExe = ${psQuote(newExePath)}`,
    `$targetExe = ${psQuote(currentExePath)}`,
    `$logFile = ${psQuote(logPath || '')}`,
    `$targetVersion = ${psQuote(targetVersion || '')}`,
    'function Write-SwapLog([string]$step) {',
    '  try { Add-Content -LiteralPath $logFile -Value ("{0} {1}" -f (Get-Date).ToString("o"), $step) -Encoding UTF8 -ErrorAction Stop } catch { }',
    '}',
    "Write-SwapLog \"started version=$targetVersion pid=$targetPid\"",
    'if ($targetPid -gt 0) { Wait-Process -Id $targetPid -Timeout 60 -ErrorAction SilentlyContinue; Write-SwapLog \'waited-pid-gone\' }',
    'Start-Sleep -Milliseconds 400',
    '$copied = $false',
    '$attempts = 0',
    `for ($i = 0; $i -lt ${MAX_COPY_ATTEMPTS}; $i++) {`,
    '  $attempts = $i + 1',
    '  try { Copy-Item -LiteralPath $newExe -Destination $targetExe -Force -ErrorAction Stop; $copied = $true; break }',
    '  catch { Write-SwapLog "copy-attempt-failed attempt=$attempts error=$($_.Exception.Message)"; Start-Sleep -Milliseconds 500 }',
    '}',
    'if ($copied) { Write-SwapLog "copy-ok attempts=$attempts" } else { Write-SwapLog "copy-failed attempts=$attempts" }',
    'Start-Process -FilePath $targetExe',
    "Write-SwapLog 'relaunch-issued'",
    'if ($copied) {',
    '  Remove-Item -LiteralPath $newExe -Force -ErrorAction SilentlyContinue',
    '  Write-SwapLog "done result=success version=$targetVersion"',
    '} else {',
    '  Write-SwapLog "done result=failed version=$targetVersion"',
    '}',
    'Remove-Item -LiteralPath $PSCommandPath -Force -ErrorAction SilentlyContinue',
    '',
  ].join('\r\n');
}

// Fallback launcher (the 0.5.0 mechanism): a detached child of the
// app. Only used when the WMI launch errors — a chance beats none.
function defaultSpawnSwapScript(scriptPath) {
  const child = spawn(
    'powershell.exe',
    ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden', '-File', scriptPath],
    { detached: true, stdio: 'ignore', windowsHide: true },
  );
  child.unref();
  return child;
}

// The PowerShell -Command that asks WMI (Win32_Process.Create) to
// start an arbitrary command line, parented to the WMI service —
// outside this app's process tree. Exits non-zero unless WMI
// reports the process was created. The command line is
// single-quoted for the outer script via psQuote.
function buildWmiCreateCommand(commandLine) {
  return (
    `$r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = ${psQuote(commandLine)} }; ` +
    'if ($null -eq $r -or $r.ReturnValue -ne 0) { exit 1 }'
  );
}

// The WMI launch command for the swap script. The inner command
// line double-quotes the script path (it lives under %APPDATA% and
// the target path may contain spaces — a real install's does).
function buildWmiLaunchCommand(scriptPath) {
  const inner = `powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "${scriptPath}"`;
  return buildWmiCreateCommand(inner);
}

// Synchronously runs a WMI-create -Command via powershell.exe, so
// by the time this returns the request is fully issued and the app
// may quit safely. Throws on any failure.
function defaultLaunchViaWmi(commandLine) {
  const result = spawnSync(
    'powershell.exe',
    ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', buildWmiCreateCommand(commandLine)],
    { stdio: 'ignore', windowsHide: true, timeout: 30_000 },
  );
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`WMI launch failed (exit ${result.status === null ? 'killed' : result.status})`);
  }
}

// Primary swap launcher: the WMI request for the swap script.
// Throws on any failure; apply() catches and falls back to the
// direct spawn.
function defaultLaunchSwapScript(scriptPath) {
  const inner = `powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "${scriptPath}"`;
  defaultLaunchViaWmi(inner);
}

// ---------------------------------------------------------------------------
// The apply log's verdict (boot-time status)
// ---------------------------------------------------------------------------

// Judges the LAST apply run recorded in apply-update.log against the
// version now running:
//   { result: 'success', version } — that run copied `version` in,
//     and `version` is what is running now.
//   { result: 'failed', version } — that run ended without applying
//     `version` (done/failed, or stalled at copy-failed), and
//     `version` is still ahead of what's running: we're behind it.
//   { result: 'unknown', version } — a run started but its outcome
//     lines never landed (killed mid-flight — the 0.5.1 failure).
//   null — no log, no recognizable run, or the last run's news is
//     stale (the running version has moved past it either way).
function parseApplyLog(text, currentVersion) {
  if (typeof text !== 'string' || !text.trim()) return null;
  const lines = text.split(/\r?\n/);
  let startIdx = -1;
  let version = null;
  for (let i = 0; i < lines.length; i += 1) {
    const m = / started version=(\S+)/.exec(lines[i]);
    if (m) {
      startIdx = i;
      version = m[1];
    }
  }
  if (startIdx < 0 || !version || !parseVersion(version)) return null;
  let done = null;
  let copyFailed = false;
  for (const line of lines.slice(startIdx + 1)) {
    const d = / done result=(success|failed) version=(\S+)/.exec(line);
    if (d) done = { result: d[1], version: d[2] };
    if (/ copy-failed/.test(line)) copyFailed = true;
  }
  if (done && done.result === 'success') {
    return compareVersions(done.version, currentVersion) === 0
      ? { result: 'success', version: done.version }
      : null;
  }
  if ((done && done.result === 'failed') || copyFailed) {
    const target = done ? done.version : version;
    return isNewerVersion(target, currentVersion) ? { result: 'failed', version: target } : null;
  }
  const cmp = compareVersions(version, currentVersion);
  if (cmp === null || cmp < 0) return null;
  return { result: 'unknown', version };
}

// The one-line settings label for an apply outcome ('' = say
// nothing; the row's normal states take over).
function applyOutcomeLabel(outcome) {
  if (!outcome) return '';
  if (outcome.result === 'success') return `Updated to ${outcome.version}`;
  if (outcome.result === 'failed') return 'Update failed';
  return '';
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
    launchSwapScript = defaultLaunchSwapScript,
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
    return { ...state, currentVersion, canApply, lastApplyOutcome: getLastApplyOutcome() };
  }

  // The last apply run's verdict from apply-update.log (0.5.2),
  // judged against the running version — see parseApplyLog. Carries
  // the log path so the settings layer can point at the record.
  function getLastApplyOutcome() {
    const logPath = path.join(updatesRoot, APPLY_LOG_NAME);
    let text;
    try {
      text = fs.readFileSync(logPath, 'utf8');
    } catch {
      return null;
    }
    const outcome = parseApplyLog(text, currentVersion);
    return outcome ? { ...outcome, logPath } : null;
  }

  function versionDir(version) {
    return path.join(updatesRoot, version);
  }

  // A leftover swap script from an applied update removes itself; if
  // it couldn't (killed mid-run), main calls this at startup. Only
  // the script is removed — apply-update.log is deliberately kept:
  // it is the diagnostic record getLastApplyOutcome() reads.
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
  // The swap script is launched through WMI (0.5.2) so it survives
  // the app/portable-stub teardown; if that launch errors, the old
  // direct spawn is the fallback. Either way the launch path taken
  // is audited before the app quits.
  function apply() {
    if (state.state !== 'ready' || !state.pendingExePath) {
      return { ok: false, reason: 'no-verified-update' };
    }
    if (!canApply) return { ok: false, reason: 'not-portable' };
    const currentExePath = getCurrentExePath();
    if (!currentExePath) return { ok: false, reason: 'not-portable' };
    const scriptPath = path.join(updatesRoot, SWAP_SCRIPT_NAME);
    const script = buildSwapScript({
      pid: getPid(),
      currentExePath,
      newExePath: state.pendingExePath,
      logPath: path.join(updatesRoot, APPLY_LOG_NAME),
      targetVersion: state.pendingVersion,
    });
    fs.writeFileSync(scriptPath, script);
    let via = 'wmi';
    try {
      launchSwapScript(scriptPath);
    } catch {
      via = 'spawn-fallback';
      spawnSwapScript(scriptPath);
    }
    audit({
      ts: new Date().toISOString(),
      event: 'update_apply_started',
      version: state.pendingVersion,
      decision: 'update-apply',
      outcome: 'started',
      via,
    });
    onApplyStarted();
    return { ok: true };
  }

  return { check, apply, getState, getLastApplyOutcome, cleanupStaleArtifacts, updatesRoot };
}

module.exports = {
  PINNED_SIGNER_FINGERPRINT256,
  GITHUB_REPO,
  LATEST_RELEASE_URL,
  SUMS_ASSET_NAME,
  EXE_ASSET_NAME,
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
  buildWmiCreateCommand,
  buildWmiLaunchCommand,
  defaultLaunchViaWmi,
  defaultLaunchSwapScript,
  parseApplyLog,
  applyOutcomeLabel,
  APPLY_LOG_NAME,
  SWAP_SCRIPT_NAME,
  MAX_COPY_ATTEMPTS,
  defaultDownloadToFile,
  createUpdater,
};
