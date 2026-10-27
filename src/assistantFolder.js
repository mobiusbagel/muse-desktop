// The Assistant Folder: Muse's home turf on the user's PC.
//   <assistantFolder>/Workspace — Muse's working files and builds
//   <assistantFolder>/Shared    — files the user drops in for Muse
//
// Folder-choice UX (0.2.1): pickers never ask for the assistant folder
// itself. The user picks a PARENT location and the app creates a folder
// named "Muse" there, with Workspace + Shared inside. The default (no
// pick) is %USERPROFILE%\Muse.
//
// This module owns creating that structure (including case-normalizing
// the subfolder names — 0.2.0 and earlier created lowercase workspace/
// shared) and the storage accounting against the configured cap
// (settings.maxStorageGB).
'use strict';

const fs = require('fs');
const path = require('path');

const ASSISTANT_FOLDER_NAME = 'Muse';
const SUBFOLDERS = ['Workspace', 'Shared'];
const BYTES_PER_GB = 1024 ** 3;

/** The assistant folder that lives under a user-picked parent location. */
function destinationForParent(parentDir) {
  return path.join(parentDir, ASSISTANT_FOLDER_NAME);
}

/**
 * Make sure root has exactly the canonical Workspace/Shared subfolders.
 *  - A lowercase (or otherwise mis-cased) counterpart is case-renamed to
 *    the canonical name, contents untouched.
 *  - A missing one is created.
 *  - If both casings somehow exist as separate folders, both are left
 *    alone and the conflict is reported.
 * Returns { renamed: [{from, to}], created: [name], conflicts: [name] }
 * and logs everything it did.
 */
function normalizeSubfolders(root) {
  const actions = { renamed: [], created: [], conflicts: [] };
  let entries = [];
  try {
    entries = fs.readdirSync(root, { withFileTypes: true });
  } catch {
    entries = [];
  }
  const dirNames = entries.filter((e) => e.isDirectory()).map((e) => e.name);
  for (const canonical of SUBFOLDERS) {
    if (dirNames.includes(canonical)) continue;
    const variant = dirNames.find((n) => n.toLowerCase() === canonical.toLowerCase());
    if (variant) {
      try {
        fs.renameSync(path.join(root, variant), path.join(root, canonical));
        actions.renamed.push({ from: variant, to: canonical });
        console.log(`[assistant-folder] renamed subfolder ${variant} -> ${canonical} in ${root}`);
      } catch (err) {
        actions.conflicts.push(canonical);
        console.error(
          `[assistant-folder] could not rename ${variant} -> ${canonical} in ${root}: ${err.message}`,
        );
      }
    } else {
      fs.mkdirSync(path.join(root, canonical), { recursive: true });
      actions.created.push(canonical);
      console.log(`[assistant-folder] created subfolder ${canonical} in ${root}`);
    }
  }
  // Both casings present as separate folders (only possible on a
  // case-sensitive filesystem): report, don't merge or delete anything.
  for (const canonical of SUBFOLDERS) {
    const variants = dirNames.filter((n) => n.toLowerCase() === canonical.toLowerCase());
    if (variants.length > 1 && !actions.conflicts.includes(canonical)) {
      actions.conflicts.push(canonical);
      console.log(
        `[assistant-folder] both ${variants.join(' and ')} exist in ${root}; leaving both as-is`,
      );
    }
  }
  return actions;
}

/**
 * First-run creation helper: given the parent location the user picked,
 * create <parent>/Muse with Workspace + Shared inside and return the
 * assistant folder path.
 */
function createAssistantFolderAt(parentDir) {
  const root = destinationForParent(parentDir);
  fs.mkdirSync(root, { recursive: true });
  normalizeSubfolders(root);
  console.log('[assistant-folder] created at:', root);
  return root;
}

function ensureAssistantFolder(settings) {
  const root = settings.assistantFolder;
  if (!fs.existsSync(root)) {
    fs.mkdirSync(root, { recursive: true });
    console.log('[assistant-folder] created:', root);
  }
  // Startup normalization: fixes the lowercase workspace/shared pair that
  // 0.2.0 created, and creates the capitalized pair where missing.
  normalizeSubfolders(root);
  console.log('[assistant-folder] ready:', root);
  return root;
}

function folderSizeBytes(root) {
  let total = 0;
  const stack = [root];
  while (stack.length > 0) {
    const dir = stack.pop();
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue; // unreadable dir: skip rather than fail the whole walk
    }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        stack.push(full);
      } else if (entry.isFile()) {
        try {
          total += fs.statSync(full).size;
        } catch {
          // File vanished mid-walk; ignore.
        }
      }
    }
  }
  return total;
}

function round2(n) {
  return Math.round(n * 100) / 100;
}

function getStorageInfo(settings) {
  const usedBytes = folderSizeBytes(settings.assistantFolder);
  const maxBytes = settings.maxStorageGB * BYTES_PER_GB;
  return {
    folder: settings.assistantFolder,
    usedBytes,
    usedGB: round2(usedBytes / BYTES_PER_GB),
    maxStorageGB: settings.maxStorageGB,
    percentUsed: maxBytes > 0 ? round2((usedBytes / maxBytes) * 100) : 0,
  };
}

module.exports = {
  ensureAssistantFolder,
  getStorageInfo,
  folderSizeBytes,
  destinationForParent,
  createAssistantFolderAt,
  normalizeSubfolders,
  SUBFOLDERS,
  ASSISTANT_FOLDER_NAME,
};
