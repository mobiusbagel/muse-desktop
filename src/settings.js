// App settings, stored as settings.json in userData alongside
// permissions.json. Phase 1 only reads/writes this file; an in-app
// settings UI lands in a later phase.
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');

const DEFAULT_SETTINGS = {
  // %USERPROFILE%\Muse on Windows.
  assistantFolder: path.join(os.homedir(), 'Muse'),
  maxStorageGB: 10,
  // 0.3.0: when true, the bridge additionally listens on the machine's
  // Tailscale IPv4 (never a LAN/public address). Off = loopback only.
  bridgeRemoteAccess: false,
  // 0.5.0: gates the updater's once-after-launch check only; a manual
  // "Check now" always runs.
  autoCheckUpdates: true,
};

// Settings keys removed by later builds (0.5.5 removed
// `trayLeftClick`, the 0.5.3 tray left-click behavior setting).
// ensureSettings deletes them from the loaded values and marks the
// file dirty, so the existing save flow rewrites settings.json
// without them — a removed setting never rides along in the live
// object and gets re-persisted by every later save.
const REMOVED_SETTINGS_KEYS = ['trayLeftClick'];

function saveSettings(userDataPath, values) {
  const file = path.join(userDataPath, 'settings.json');
  fs.mkdirSync(userDataPath, { recursive: true });
  fs.writeFileSync(file, JSON.stringify(values, null, 2) + '\n');
  return file;
}

function ensureSettings(userDataPath) {
  const file = path.join(userDataPath, 'settings.json');
  let values = { ...DEFAULT_SETTINGS };
  let dirty = false;
  // `created` = no settings.json existed (true first run);
  // `fromInstaller` = the folder came from the installer's hand-off file.
  let created = false;
  let fromInstaller = false;
  if (fs.existsSync(file)) {
    try {
      const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
      values = { ...DEFAULT_SETTINGS, ...parsed };
      // Drop keys this build no longer knows (see
      // REMOVED_SETTINGS_KEYS): the delete + dirty flag make the
      // save below rewrite the file without them.
      for (const key of REMOVED_SETTINGS_KEYS) {
        if (key in values) {
          delete values[key];
          dirty = true;
        }
      }
      // Persist newly introduced defaults (e.g. bridgeRemoteAccess in
      // 0.3.0) so the file on disk reflects the full current schema.
      if (Object.keys(DEFAULT_SETTINGS).some((key) => !(key in parsed))) dirty = true;
      console.log('[settings] loaded:', file);
    } catch (err) {
      console.error('[settings] could not parse settings.json; using defaults:', err.message);
    }
  } else {
    dirty = true;
    created = true;
  }

  // Installer hand-off: the NSIS installer writes assistant-folder.txt into
  // userData with the assistant folder the user picked during setup. The
  // first run folds that choice into settings.json and removes the file, so
  // settings.json is the single source of truth from then on.
  const handoffFile = path.join(userDataPath, 'assistant-folder.txt');
  if (fs.existsSync(handoffFile)) {
    try {
      const chosen = fs.readFileSync(handoffFile, 'utf8').split(/\r?\n/)[0].trim();
      if (chosen) {
        values.assistantFolder = chosen;
        dirty = true;
        fromInstaller = true;
        console.log('[settings] assistant folder chosen during install:', chosen);
      }
      fs.rmSync(handoffFile, { force: true });
    } catch (err) {
      console.error('[settings] could not read installer hand-off:', err.message);
    }
  }

  if (dirty) {
    saveSettings(userDataPath, values);
    console.log('[settings] wrote:', file);
  }
  return { values, file, created, fromInstaller };
}

module.exports = { ensureSettings, saveSettings, DEFAULT_SETTINGS, REMOVED_SETTINGS_KEYS };
