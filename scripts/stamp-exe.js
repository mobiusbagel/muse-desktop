#!/usr/bin/env node
// stamp-exe.js — rewrite a built Windows exe's version resources and icon
// group in place, without Wine/rcedit, using the pure-JS `resedit` library.
//
// Why: electron-builder normally stamps FileDescription/ProductName and
// the exe icon via rcedit, which needs Wine on this build machine (there
// is none), so the shipped exe kept the stock Electron identity — most
// visibly, the Windows taskbar jump list titled the app "Electron".
// This script performs the same edit at the binary level and then
// re-reads the file to verify the result; it exits non-zero if the
// read-back does not match.
//
// Usage:
//   node scripts/stamp-exe.js --read <exe>
//       Dump version strings, fixed versions and icon-group frames as JSON.
//   node scripts/stamp-exe.js <exe> [--icon <icon.ico>] [--version <x.y.z>] [--name <ProductName>]
//       Stamp <exe> in place (defaults: icon build/icon.ico, name and
//       version from package.json), then verify by re-reading from disk.
'use strict';

const fs = require('fs');
const path = require('path');

const projectRoot = path.resolve(__dirname, '..');

function fail(message) {
  console.error(`[stamp-exe] ERROR: ${message}`);
  process.exit(1);
}

// --- .ico parsing (for frame metadata + byte comparison) -------------------

function parseIco(buf) {
  if (buf.length < 6) fail('icon file too small to be an .ico');
  const reserved = buf.readUInt16LE(0);
  const type = buf.readUInt16LE(2);
  const count = buf.readUInt16LE(4);
  if (reserved !== 0 || type !== 1) fail('icon file is not a valid .ico');
  const frames = [];
  for (let i = 0; i < count; i++) {
    const off = 6 + i * 16;
    const width = buf[off] === 0 ? 256 : buf[off];
    const height = buf[off + 1] === 0 ? 256 : buf[off + 1];
    const bitCount = buf.readUInt16LE(off + 6);
    const dataSize = buf.readUInt32LE(off + 8);
    const dataOffset = buf.readUInt32LE(off + 12);
    frames.push({
      width,
      height,
      bitCount,
      dataSize,
      bytes: buf.subarray(dataOffset, dataOffset + dataSize),
    });
  }
  return frames;
}

// --- exe inspection ---------------------------------------------------------

async function loadResedit() {
  try {
    return await import('resedit');
  } catch (err) {
    fail(`could not load the 'resedit' package (${err.message}) — run npm install first`);
  }
}

function fixedVersionToString(ms, ls) {
  return `${(ms >>> 16) & 0xffff}.${ms & 0xffff}.${(ls >>> 16) & 0xffff}.${ls & 0xffff}`;
}

function inspectExe(resedit, filePath) {
  const { NtExecutable, NtExecutableResource, Resource } = resedit;
  const bin = fs.readFileSync(filePath);
  // ignoreCert: pe-library otherwise refuses to parse Authenticode-signed
  // binaries at all. Inspection only reads version/icon resources, and
  // since 0.4.0's signing step the payloads this inspects ARE signed —
  // scripts/verify-portable.js depends on this to check the final build.
  const exe = NtExecutable.from(bin, { ignoreCert: true });
  const res = NtExecutableResource.from(exe);

  const report = { file: filePath, versionStrings: {}, fixedFileVersion: null, fixedProductVersion: null, iconGroups: [] };

  const versionInfos = Resource.VersionInfo.fromEntries(res.entries);
  if (versionInfos.length > 0) {
    const vi = versionInfos[0];
    let languages = vi.getAllLanguagesForStringValues();
    if (languages.length === 0) languages = vi.getAvailableLanguages();
    for (const language of languages) {
      report.versionStrings[`${language.lang}/${language.codepage}`] = vi.getStringValues(language);
    }
    report.fixedFileVersion = fixedVersionToString(vi.fixedInfo.fileVersionMS, vi.fixedInfo.fileVersionLS);
    report.fixedProductVersion = fixedVersionToString(vi.fixedInfo.productVersionMS, vi.fixedInfo.productVersionLS);
  }

  for (const group of Resource.IconGroupEntry.fromEntries(res.entries)) {
    const items = group.getIconItemsFromEntries(res.entries);
    report.iconGroups.push({
      id: group.id,
      lang: group.lang,
      frames: group.icons.map((meta, i) => {
        const item = items[i];
        return {
          width: meta.width === 0 ? 256 : meta.width,
          height: meta.height === 0 ? 256 : meta.height,
          bitCount: meta.bitCount,
          dataSize: meta.dataSize,
          // Raw (PNG) frames expose their bytes; BMP frames report null
          // and are compared by metadata only.
          bytes: item && typeof item.isRaw === 'function' && item.isRaw() ? Buffer.from(item.bin) : null,
        };
      }),
    });
  }
  return report;
}

// --- stamping ---------------------------------------------------------------

function versionParts(version) {
  const parts = String(version).split('.').map((p) => parseInt(p, 10) || 0);
  while (parts.length < 3) parts.push(0);
  return parts;
}

async function stampExe(resedit, filePath, { iconPath, name, version }) {
  const { NtExecutable, NtExecutableResource, Resource, Data } = resedit;
  const bin = fs.readFileSync(filePath);
  // Same ignoreCert parsing allowance as inspectExe. The pipeline only
  // ever stamps a fresh unsigned exe (stamp runs before signing), but
  // parsing must not hard-fail if handed a signed one — note the stamp's
  // regenerated output drops any existing signature, which is why the
  // release order is pack → stamp → sign, never the reverse.
  const exe = NtExecutable.from(bin, { ignoreCert: true });
  const res = NtExecutableResource.from(exe);

  // -- version strings + fixed versions --
  const versionInfos = Resource.VersionInfo.fromEntries(res.entries);
  if (versionInfos.length === 0) fail(`${filePath} has no version resource to stamp`);
  const vi = versionInfos[0];
  let languages = vi.getAllLanguagesForStringValues();
  if (languages.length === 0) languages = vi.getAvailableLanguages();
  if (languages.length === 0) fail('version resource has no string languages to stamp');
  const stringValues = {
    FileDescription: name,
    ProductName: name,
    InternalName: name,
    OriginalFilename: `${name}.exe`,
    FileVersion: version,
    ProductVersion: version,
  };
  for (const language of languages) {
    for (const [key, value] of Object.entries(stringValues)) {
      vi.setStringValue(language, key, value);
    }
  }
  const [major, minor, patch] = versionParts(version);
  const ms = ((major << 16) | minor) >>> 0;
  const ls = ((patch << 16) | 0) >>> 0;
  vi.fixedInfo.fileVersionMS = ms;
  vi.fixedInfo.fileVersionLS = ls;
  vi.fixedInfo.productVersionMS = ms;
  vi.fixedInfo.productVersionLS = ls;
  vi.outputToResourceEntries(res.entries);

  // -- icon group --
  const iconBuf = fs.readFileSync(iconPath);
  const iconFile = Data.IconFile.from(iconBuf);
  const iconItems = iconFile.icons.map((entry) => entry.data);
  if (iconItems.length === 0) fail(`${iconPath} contains no icon frames`);
  const existingGroups = Resource.IconGroupEntry.fromEntries(res.entries);
  const groupId = existingGroups.length > 0 ? existingGroups[0].id : 1;
  const groupLang = existingGroups.length > 0 ? existingGroups[0].lang : 1033;
  Resource.IconGroupEntry.replaceIconsForResource(res.entries, groupId, groupLang, iconItems);

  res.outputResource(exe);
  const out = Buffer.from(exe.generate());
  const tmpPath = `${filePath}.stamp-tmp`;
  fs.writeFileSync(tmpPath, out);
  fs.renameSync(tmpPath, filePath);
  return { groupId, groupLang, framesStamped: iconItems.length };
}

// --- verification -----------------------------------------------------------

function framesMatch(a, b) {
  // a/b: [{width, height, bitCount, dataSize, bytes?}]
  if (a.length !== b.length) return false;
  const key = (f) => `${f.width}x${f.height}x${f.bitCount}:${f.dataSize}`;
  const left = a.map(key).sort();
  const right = b.map(key).sort();
  return left.every((value, i) => value === right[i]);
}

function verifyStamped(resedit, filePath, { iconPath, name, version }) {
  const report = inspectExe(resedit, filePath);
  const problems = [];
  const langKeys = Object.keys(report.versionStrings);
  if (langKeys.length === 0) problems.push('no version strings found after stamping');
  for (const langKey of langKeys) {
    const values = report.versionStrings[langKey];
    for (const key of ['FileDescription', 'ProductName', 'InternalName']) {
      if (values[key] !== name) problems.push(`${langKey} ${key} is ${JSON.stringify(values[key])}, expected ${JSON.stringify(name)}`);
    }
    if (values.OriginalFilename !== `${name}.exe`) {
      problems.push(`${langKey} OriginalFilename is ${JSON.stringify(values.OriginalFilename)}, expected ${JSON.stringify(`${name}.exe`)}`);
    }
    if (values.FileVersion !== version) problems.push(`${langKey} FileVersion is ${JSON.stringify(values.FileVersion)}, expected ${JSON.stringify(version)}`);
    if (values.ProductVersion !== version) problems.push(`${langKey} ProductVersion is ${JSON.stringify(values.ProductVersion)}, expected ${JSON.stringify(version)}`);
  }
  if (report.iconGroups.length === 0) {
    problems.push('no icon group found after stamping');
  } else {
    const sourceFrames = parseIco(fs.readFileSync(iconPath));
    const stampedFrames = report.iconGroups[0].frames;
    if (!framesMatch(stampedFrames, sourceFrames)) {
      problems.push(
        `icon frames differ from ${path.basename(iconPath)}: stamped ${JSON.stringify(
          stampedFrames.map((f) => `${f.width}x${f.height}:${f.dataSize}`),
        )} vs source ${JSON.stringify(sourceFrames.map((f) => `${f.width}x${f.height}:${f.dataSize}`))}`,
      );
    } else {
      // Byte-compare every frame that is stored raw (PNG) in both files.
      for (const stamped of stampedFrames) {
        if (!stamped.bytes) continue;
        const source = sourceFrames.find(
          (f) => f.width === stamped.width && f.height === stamped.height && f.dataSize === stamped.dataSize,
        );
        if (source && !source.bytes.equals(stamped.bytes)) {
          problems.push(`icon frame ${stamped.width}x${stamped.height} bytes differ from the source .ico`);
        }
      }
    }
  }
  return { report, problems };
}

// --- CLI --------------------------------------------------------------------

async function main() {
  const args = process.argv.slice(2);
  const resedit = await loadResedit();

  if (args[0] === '--read') {
    if (!args[1]) fail('usage: stamp-exe.js --read <exe>');
    const report = inspectExe(resedit, args[1]);
    // Strip raw bytes from the dump; sizes are the evidence.
    for (const group of report.iconGroups) {
      for (const frame of group.frames) delete frame.bytes;
    }
    console.log(JSON.stringify(report, null, 2));
    return;
  }

  const filePath = args[0];
  if (!filePath) {
    fail('usage: stamp-exe.js <exe> [--icon <icon.ico>] [--version <x.y.z>] [--name <ProductName>]  |  stamp-exe.js --read <exe>');
  }
  const pkg = JSON.parse(fs.readFileSync(path.join(projectRoot, 'package.json'), 'utf8'));
  let iconPath = path.join(projectRoot, 'build', 'icon.ico');
  let name = (pkg.build && pkg.build.productName) || 'Muse';
  let version = pkg.version;
  for (let i = 1; i < args.length; i++) {
    if (args[i] === '--icon') iconPath = path.resolve(args[++i]);
    else if (args[i] === '--name') name = args[++i];
    else if (args[i] === '--version') version = args[++i];
    else fail(`unknown argument: ${args[i]}`);
  }
  if (!fs.existsSync(filePath)) fail(`exe not found: ${filePath}`);
  if (!fs.existsSync(iconPath)) fail(`icon not found: ${iconPath}`);

  const before = inspectExe(resedit, filePath);
  const beforeStrings = Object.values(before.versionStrings)[0] || {};
  console.log(
    `[stamp-exe] before: FileDescription=${JSON.stringify(beforeStrings.FileDescription)} ` +
      `ProductName=${JSON.stringify(beforeStrings.ProductName)} FileVersion=${JSON.stringify(beforeStrings.FileVersion)}`,
  );

  const { groupId, framesStamped } = await stampExe(resedit, filePath, { iconPath, name, version });
  console.log(`[stamp-exe] stamped ${filePath}: strings -> ${name} ${version}, icon group ${groupId} -> ${framesStamped} frames from ${path.basename(iconPath)}`);

  const { report, problems } = verifyStamped(resedit, filePath, { iconPath, name, version });
  if (problems.length > 0) {
    for (const problem of problems) console.error(`[stamp-exe] VERIFY FAILED: ${problem}`);
    process.exit(1);
  }
  const afterStrings = Object.values(report.versionStrings)[0] || {};
  console.log(
    `[stamp-exe] verified: FileDescription=${JSON.stringify(afterStrings.FileDescription)} ` +
      `ProductName=${JSON.stringify(afterStrings.ProductName)} OriginalFilename=${JSON.stringify(afterStrings.OriginalFilename)} ` +
      `FileVersion=${JSON.stringify(afterStrings.FileVersion)} fixed=${report.fixedFileVersion} ` +
      `icon frames=${report.iconGroups[0].frames.map((f) => `${f.width}x${f.height}`).join(',')}`,
  );
}

if (require.main === module) {
  main().catch((err) => fail(err && err.stack ? err.stack : String(err)));
}

// Exported for scripts/verify-portable.js, which re-inspects the exe
// inside the final portable artifact with the same code that stamps it.
module.exports = { loadResedit, inspectExe, parseIco, framesMatch };
