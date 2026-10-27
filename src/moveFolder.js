// Assistant-folder relocation engine (used by the settings window's
// "Move folder…" flow).
//
// Safety contract:
//  - Pre-checks run before anything is touched; a failed pre-check changes
//    nothing.
//  - Same-volume moves use rename. Everything else copies file-by-file with
//    progress + abort support, verifies the copy (file count and total
//    bytes), and only then reports success — the caller flips the setting
//    and deletes the original. Any failure or abort before that point rolls
//    the partial copy back (files we created are removed; files we
//    overwrote are restored from backups) and the old folder stays live.
//  - Merge semantics: if the destination already has files, the assistant
//    folder's same-name files win (after an explicit UI confirmation — see
//    settingsHandlers: precheck reports needsMergeConfirm).
'use strict';

const fs = require('fs');
const path = require('path');

function samePath(a, b) {
  const ra = path.resolve(a);
  const rb = path.resolve(b);
  return process.platform === 'win32' ? ra.toLowerCase() === rb.toLowerCase() : ra === rb;
}

/** True when `child` is strictly inside `parent`. */
function isInside(parent, child) {
  const rel = path.relative(path.resolve(parent), path.resolve(child));
  return rel !== '' && rel !== '..' && !rel.startsWith('..' + path.sep) && !path.isAbsolute(rel);
}

/** Recursive listing: { files: [{rel, size}], dirs: [rel], totalBytes, fileCount }. */
function scanTree(root) {
  const files = [];
  const dirs = [];
  let totalBytes = 0;
  const stack = [''];
  while (stack.length > 0) {
    const relDir = stack.pop();
    const absDir = relDir ? path.join(root, relDir) : root;
    let entries;
    try {
      entries = fs.readdirSync(absDir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const rel = relDir ? path.join(relDir, entry.name) : entry.name;
      if (entry.isDirectory()) {
        dirs.push(rel);
        stack.push(rel);
      } else if (entry.isFile()) {
        let size = 0;
        try {
          size = fs.statSync(path.join(root, rel)).size;
        } catch {
          // Vanished mid-scan; count as 0.
        }
        files.push({ rel, size });
        totalBytes += size;
      }
    }
  }
  return { files, dirs, totalBytes, fileCount: files.length };
}

function existingAncestor(p) {
  let dir = path.resolve(p);
  while (!fs.existsSync(dir)) {
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return dir;
}

function freeSpaceBytes(target) {
  const st = fs.statfsSync(existingAncestor(target));
  return st.bsize * st.bavail;
}

function deviceOf(p) {
  return fs.statSync(existingAncestor(p)).dev;
}

function precheckMove(from, to) {
  const errors = [];
  if (!from || !to) errors.push('Both a current folder and a destination are required.');
  if (from && !fs.existsSync(from)) errors.push(`Current assistant folder does not exist: ${from}`);

  let scan = null;
  let freeBytes = null;
  let needsMergeConfirm = false;

  if (errors.length === 0) {
    if (samePath(from, to)) {
      errors.push('The destination is the current assistant folder.');
    } else if (isInside(from, to)) {
      errors.push('The destination is inside the current assistant folder.');
    } else if (isInside(to, from)) {
      errors.push('The current assistant folder is inside the destination.');
    }
  }

  if (errors.length === 0) {
    scan = scanTree(from);
    try {
      freeBytes = freeSpaceBytes(to);
      if (freeBytes <= scan.totalBytes * 1.1) {
        errors.push(
          `Not enough free space at the destination: moving needs more than ` +
            `${Math.ceil(scan.totalBytes * 1.1)} bytes free, only ${freeBytes} available.`,
        );
      }
    } catch (err) {
      errors.push(`Could not check free space at the destination: ${err.message}`);
    }
    if (fs.existsSync(to)) {
      if (!fs.statSync(to).isDirectory()) {
        errors.push('The destination exists and is not a folder.');
      } else {
        try {
          needsMergeConfirm = fs.readdirSync(to).length > 0;
        } catch {
          needsMergeConfirm = false;
        }
      }
    }
  }

  return {
    ok: errors.length === 0,
    errors,
    needsMergeConfirm,
    totalBytes: scan ? scan.totalBytes : 0,
    fileCount: scan ? scan.fileCount : 0,
    freeBytes,
  };
}

function abortError() {
  const err = new Error('Move canceled by user.');
  err.code = 'ABORTED';
  return err;
}

function rollbackCopy({ createdFiles, backups, createdDirs }) {
  for (const f of createdFiles) {
    try {
      fs.rmSync(f, { force: true });
    } catch {}
  }
  for (const [destAbs, backupAbs] of backups) {
    try {
      fs.rmSync(destAbs, { force: true });
      fs.renameSync(backupAbs, destAbs);
    } catch {}
  }
  const deepestFirst = [...createdDirs].sort((a, b) => b.length - a.length);
  for (const d of deepestFirst) {
    try {
      fs.rmdirSync(d); // only succeeds when empty
    } catch {}
  }
}

/**
 * Move the folder contents from `from` to `to`.
 * opts: { onProgress, signal, forceCopy } — forceCopy skips the rename fast
 * path (used by tests; production uses it when rename is impossible).
 * Resolves { method: 'rename' | 'copy', fileCount, bytes }.
 */
async function moveAssistantFolder({ from, to, onProgress = () => {}, signal = null, forceCopy = false }) {
  const pre = precheckMove(from, to);
  if (!pre.ok) {
    const err = new Error(pre.errors.join(' '));
    err.code = 'PRECHECK_FAILED';
    err.errors = pre.errors;
    throw err;
  }
  const scan = scanTree(from);
  const isAborted = () => !!(signal && signal.aborted);

  // --- Fast path: same volume + destination absent => rename ---------------
  if (!forceCopy && !fs.existsSync(to) && deviceOf(from) === deviceOf(to)) {
    fs.mkdirSync(path.dirname(path.resolve(to)), { recursive: true });
    fs.renameSync(from, to);
    const verify = scanTree(to);
    if (verify.fileCount !== scan.fileCount || verify.totalBytes !== scan.totalBytes) {
      try {
        fs.renameSync(to, from);
      } catch {}
      throw new Error('Verification failed after rename; the move was rolled back.');
    }
    onProgress({
      filesDone: scan.fileCount,
      filesTotal: scan.fileCount,
      bytesDone: scan.totalBytes,
      bytesTotal: scan.totalBytes,
    });
    return { method: 'rename', fileCount: scan.fileCount, bytes: scan.totalBytes };
  }

  // --- Copy path: cross-volume or merging into an existing folder ---------
  const createdDirs = [];
  const createdFiles = [];
  const backups = new Map(); // destAbs -> backupAbs (files we overwrote)
  const ensureDir = (dir) => {
    const missing = [];
    let cur = path.resolve(dir);
    while (!fs.existsSync(cur)) {
      missing.push(cur);
      const parent = path.dirname(cur);
      if (parent === cur) break;
      cur = parent;
    }
    for (const d of missing.reverse()) {
      fs.mkdirSync(d);
      createdDirs.push(d);
    }
  };

  let filesDone = 0;
  let bytesDone = 0;
  try {
    ensureDir(to);
    for (const dirRel of scan.dirs) ensureDir(path.join(to, dirRel));

    for (const f of scan.files) {
      if (isAborted()) throw abortError();
      const srcAbs = path.join(from, f.rel);
      const dstAbs = path.join(to, f.rel);
      ensureDir(path.dirname(dstAbs));
      if (fs.existsSync(dstAbs)) {
        const backupAbs = dstAbs + '.muse-move-backup';
        fs.renameSync(dstAbs, backupAbs);
        backups.set(dstAbs, backupAbs);
      } else {
        createdFiles.push(dstAbs);
      }
      fs.copyFileSync(srcAbs, dstAbs);
      filesDone++;
      bytesDone += f.size;
      onProgress({
        filesDone,
        filesTotal: scan.fileCount,
        bytesDone,
        bytesTotal: scan.totalBytes,
      });
      if (filesDone % 20 === 0) {
        // Keep the event loop (and the Cancel button) responsive.
        await new Promise((resolve) => setImmediate(resolve));
      }
    }

    if (isAborted()) throw abortError();

    // Verify the copied set: same file count and total bytes as the source.
    let vCount = 0;
    let vBytes = 0;
    for (const f of scan.files) {
      const st = fs.statSync(path.join(to, f.rel)); // throws if missing
      vCount++;
      vBytes += st.size;
    }
    if (vCount !== scan.fileCount || vBytes !== scan.totalBytes) {
      throw new Error('Verification failed: the copy does not match the original (file count / bytes).');
    }
  } catch (err) {
    rollbackCopy({ createdFiles, backups, createdDirs });
    throw err;
  }

  // Verified: backups of overwritten destination files are no longer needed.
  for (const backupAbs of backups.values()) {
    try {
      fs.rmSync(backupAbs, { force: true });
    } catch {}
  }
  return { method: 'copy', fileCount: scan.fileCount, bytes: scan.totalBytes };
}

/** Relative paths still present under `root` (capped), for remains reports. */
function listRemains(root, cap = 50) {
  const out = [];
  const stack = [''];
  while (stack.length > 0 && out.length < cap) {
    const relDir = stack.pop();
    let entries;
    try {
      entries = fs.readdirSync(relDir ? path.join(root, relDir) : root, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const rel = relDir ? path.join(relDir, entry.name) : entry.name;
      out.push(entry.isDirectory() ? rel + path.sep : rel);
      if (entry.isDirectory()) stack.push(rel);
      if (out.length >= cap) break;
    }
  }
  return out;
}

function appendMoveLog(userDataPath, { from, to, bytes, fileCount, result }) {
  const line =
    `${new Date().toISOString()} from=${from} to=${to} ` +
    `bytes=${bytes ?? '?'} files=${fileCount ?? '?'} result=${result}\n`;
  try {
    fs.appendFileSync(path.join(userDataPath, 'moves.log'), line);
  } catch (err) {
    console.error('[moves] could not write moves.log:', err.message);
  }
}

module.exports = {
  precheckMove,
  moveAssistantFolder,
  scanTree,
  listRemains,
  appendMoveLog,
  isInside,
  samePath,
};
