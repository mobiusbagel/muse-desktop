#!/usr/bin/env node
// verify-portable.js — release fail-safe (0.3.1).
//
// scripts/stamp-exe.js verifies the exe it stamps in dist/win-unpacked,
// but the artifact users actually run is the portable .exe — and the
// 0.3.0 icon investigation had to prove *by hand* that the stamp
// survives portable packaging (the shipped portable's inner Muse.exe
// was byte-identical to the stamped one that time; nothing checked it
// automatically). This script closes that gap: it extracts the FINAL
// portable artifact and asserts, against the exe inside it:
//
//   (a) the icon-group frames byte-match build/icon.ico,
//   (b) FileDescription reads the package.json productName ("Muse")
//       in every language of the version resource,
//   (c) FileVersion reads the package.json version in every language.
//
// It prints every check it performs and exits non-zero on any mismatch,
// so a bad stamp fails the release loudly instead of shipping. Wired
// into `npm run release` after `dist:portable`.
//
// Usage:
//   node scripts/verify-portable.js [portable-exe]
//       (default: dist/Muse-Portable-<package.json version>.exe)
//
// Extraction uses 7-Zip: `7zz`/`7z` from PATH, else the copy in the
// electron-builder cache. The extraction dir is created on the
// workspace disk (project root) and always removed afterwards — never
// /tmp, which is a small tmpfs on the build VM and has truncated a
// 7z extraction before (see BUILD_NOTES 0.2.3).
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const { loadResedit, inspectExe, parseIco, framesMatch } = require('./stamp-exe');

const projectRoot = path.resolve(__dirname, '..');

function fail(message) {
  console.error(`[verify-portable] FAILED: ${message}`);
  process.exit(1);
}

function find7z() {
  for (const name of ['7zz', '7z']) {
    try {
      execFileSync(name, ['i'], { stdio: 'pipe' });
      return name;
    } catch {
      // Not on PATH (or not runnable) — keep looking.
    }
  }
  const cacheRoot = path.join(os.homedir(), '.cache', 'electron-builder');
  const found = [];
  const walk = (dir, depth) => {
    if (depth > 6 || found.length > 0) return;
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isFile() && entry.name === '7zz') found.push(full);
      else if (entry.isDirectory()) walk(full, depth + 1);
      if (found.length > 0) return;
    }
  };
  walk(cacheRoot, 0);
  if (found.length > 0) return found[0];
  fail('could not find 7-Zip (7zz/7z) on PATH or in the electron-builder cache');
}

function extract(sevenZip, archive, outDir) {
  fs.mkdirSync(outDir, { recursive: true });
  execFileSync(sevenZip, ['x', '-y', `-o${outDir}`, archive], { stdio: 'pipe' });
}

function findFile(root, basename) {
  const queue = [root];
  while (queue.length > 0) {
    const dir = queue.shift();
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) queue.push(full);
      else if (entry.name === basename) return full;
    }
  }
  return null;
}

async function main() {
  const pkg = JSON.parse(fs.readFileSync(path.join(projectRoot, 'package.json'), 'utf8'));
  const expectedName = (pkg.build && pkg.build.productName) || 'Muse';
  const expectedVersion = pkg.version;
  const portablePath = process.argv[2]
    ? path.resolve(process.argv[2])
    : path.join(projectRoot, 'dist', `Muse-Portable-${expectedVersion}.exe`);
  if (!fs.existsSync(portablePath)) fail(`portable artifact not found: ${portablePath}`);

  const sevenZip = find7z();
  console.log(`[verify-portable] artifact: ${path.relative(projectRoot, portablePath)} (${fs.statSync(portablePath).size} bytes)`);
  console.log(`[verify-portable] extracting with ${sevenZip}`);

  const workDir = fs.mkdtempSync(path.join(projectRoot, '.verify-portable-'));
  try {
    const stage1 = path.join(workDir, 'portable');
    extract(sevenZip, portablePath, stage1);
    const appArchive = findFile(stage1, 'app-64.7z');
    if (!appArchive) fail('portable payload archive ($PLUGINSDIR/app-64.7z) not found after extraction');
    const stage2 = path.join(workDir, 'app');
    extract(sevenZip, appArchive, stage2);
    const innerExe = findFile(stage2, 'Muse.exe');
    if (!innerExe) fail('Muse.exe not found inside the portable payload');
    console.log(`[verify-portable] inner exe: ${path.relative(workDir, innerExe)} (${fs.statSync(innerExe).size} bytes)`);

    const resedit = await loadResedit();
    const report = inspectExe(resedit, innerExe);
    const problems = [];
    const checked = [];

    // (b) + (c): version strings, every language.
    const langKeys = Object.keys(report.versionStrings);
    if (langKeys.length === 0) problems.push('no version strings found in the inner exe');
    for (const langKey of langKeys) {
      const values = report.versionStrings[langKey];
      if (values.FileDescription === expectedName) {
        checked.push(`FileDescription [${langKey}] = ${JSON.stringify(expectedName)}`);
      } else {
        problems.push(`FileDescription [${langKey}] is ${JSON.stringify(values.FileDescription)}, expected ${JSON.stringify(expectedName)}`);
      }
      if (values.FileVersion === expectedVersion) {
        checked.push(`FileVersion [${langKey}] = ${JSON.stringify(expectedVersion)}`);
      } else {
        problems.push(`FileVersion [${langKey}] is ${JSON.stringify(values.FileVersion)}, expected package.json version ${JSON.stringify(expectedVersion)}`);
      }
    }

    // (a): icon-group frames byte-match build/icon.ico.
    const iconPath = path.join(projectRoot, 'build', 'icon.ico');
    if (report.iconGroups.length === 0) {
      problems.push('no icon group found in the inner exe');
    } else {
      const sourceFrames = parseIco(fs.readFileSync(iconPath));
      const shippedFrames = report.iconGroups[0].frames;
      if (!framesMatch(shippedFrames, sourceFrames)) {
        problems.push(
          `icon frames differ from build/icon.ico: shipped ${JSON.stringify(
            shippedFrames.map((f) => `${f.width}x${f.height}:${f.dataSize}`),
          )} vs source ${JSON.stringify(sourceFrames.map((f) => `${f.width}x${f.height}:${f.dataSize}`))}`,
        );
      } else {
        checked.push(
          `icon group frames = build/icon.ico (${shippedFrames.map((f) => `${f.width}x${f.height}`).join(', ')})`,
        );
        let iconBytesOk = true;
        for (const shipped of shippedFrames) {
          if (!shipped.bytes) continue; // non-raw frames compare by metadata (already done)
          const source = sourceFrames.find(
            (f) => f.width === shipped.width && f.height === shipped.height && f.dataSize === shipped.dataSize,
          );
          if (source && !source.bytes.equals(shipped.bytes)) {
            iconBytesOk = false;
            problems.push(`icon frame ${shipped.width}x${shipped.height} bytes differ from build/icon.ico`);
          }
        }
        if (iconBytesOk) checked.push('every raw icon frame byte-identical to build/icon.ico');
      }
    }

    for (const line of checked) console.log(`[verify-portable] ✓ ${line}`);
    if (problems.length > 0) {
      for (const problem of problems) console.error(`[verify-portable] ✗ ${problem}`);
      fail(`${problems.length} check(s) failed — the portable artifact does not carry the stamp`);
    }
    console.log(`[verify-portable] PASS: the portable artifact carries the Muse stamp (name, version ${expectedVersion}, icon)`);
  } finally {
    fs.rmSync(workDir, { recursive: true, force: true });
  }
}

main().catch((err) => fail(err && err.stack ? err.stack : String(err)));
