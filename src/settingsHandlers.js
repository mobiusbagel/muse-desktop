// IPC handlers behind the settings window. The `context` object is owned by
// main.js and holds the live settings object, so a successful move flips
// storage accounting (and, in Phase 2, permission scoping) to the new root
// the moment settings.json is rewritten.
'use strict';

const { dialog, app } = require('electron');
const fs = require('fs');
const { applyOutcomeLabel } = require('./updater');
const { getStorageInfo, destinationForParent, normalizeSubfolders } = require('./assistantFolder');
const { saveSettings } = require('./settings');
const { precheckMove, moveAssistantFolder, listRemains, appendMoveLog } = require('./moveFolder');

// THE remote-access settings path (0.3.0; shared since 0.5.4): flip
// bridgeRemoteAccess in settings.json, persist, and rebind the
// bridge listeners live via main's applyBridgeAccess (loopback
// always; Tailscale IPv4 added when on). The settings-window toggle
// and the tray menu's Remote Access checkbox both run exactly this
// — there is no second implementation to drift.
async function setRemoteAccess(context, enabled) {
  context.settings.bridgeRemoteAccess = !!enabled;
  saveSettings(context.userDataPath, context.settings);
  console.log(`[settings] bridgeRemoteAccess set to ${context.settings.bridgeRemoteAccess}`);
  if (typeof context.applyBridgeAccess === 'function') {
    await context.applyBridgeAccess();
  }
  // The tray menu renders the setting (checkbox) and the bridge
  // status line; both just changed. Guarded: main installs the hook
  // once the tray exists.
  if (typeof context.refreshTrayMenu === 'function') {
    context.refreshTrayMenu();
  }
}

function registerSettingsHandlers(ipcMain, context) {
  // One-line updater status for the settings window (0.5.0). The full
  // state lives in updater.js; only the label crosses IPC. Before
  // any check runs this session (and whenever the check state has
  // nothing fresher to say), the row reports the last apply's
  // outcome from apply-update.log (0.5.2): "Updated to <version>"
  // after a successful swap into this build, "Update failed" when
  // the last apply fell short of a version still ahead of us.
  const updateStatus = () => {
    const s = typeof context.getUpdateState === 'function' ? context.getUpdateState() : null;
    if (!s) return '';
    switch (s.state) {
      case 'checking':
        return 'Checking…';
      case 'up-to-date':
        return 'Up to date';
      case 'ready':
        return `Update available: ${s.pendingVersion}`;
      case 'error':
        return 'Check failed';
      default:
        return applyOutcomeLabel(s.lastApplyOutcome);
    }
  };

  const currentState = () => ({
    ...getStorageInfo(context.settings),
    moving: context.moving,
    bridgeRemoteAccess: !!context.settings.bridgeRemoteAccess,
    bridgeStatus:
      typeof context.getBridgeStatus === 'function' ? context.getBridgeStatus().label : '',
    appVersion: app.getVersion(),
    updateStatus: updateStatus(),
    autoCheckUpdates: context.settings.autoCheckUpdates !== false,
  });

  ipcMain.handle('settings:get-state', () => currentState());

  // Remote access toggle (0.3.0): the shared settings path (see
  // setRemoteAccess above — the tray checkbox runs the same code).
  ipcMain.handle('settings:set-remote-access', async (_event, enabled) => {
    await setRemoteAccess(context, enabled);
    return currentState();
  });

  // Updater (0.5.0): "Check now" runs a full check (download + verify
  // included); the toggle only gates the automatic launch check.
  ipcMain.handle('settings:check-updates', async () => {
    if (typeof context.checkForUpdates === 'function') {
      await context.checkForUpdates();
    }
    return currentState();
  });

  ipcMain.handle('settings:set-auto-check', (_event, enabled) => {
    context.settings.autoCheckUpdates = !!enabled;
    saveSettings(context.userDataPath, context.settings);
    console.log(`[settings] autoCheckUpdates set to ${context.settings.autoCheckUpdates}`);
    return currentState();
  });

  ipcMain.handle('settings:save-cap', (_event, gb) => {
    const value = Number(gb);
    if (!Number.isFinite(value) || value <= 0) {
      throw new Error('Max storage must be a positive number of GB.');
    }
    context.settings.maxStorageGB = Math.round(value * 100) / 100;
    saveSettings(context.userDataPath, context.settings);
    console.log(`[settings] maxStorageGB set to ${context.settings.maxStorageGB}`);
    return currentState();
  });

  // The picker chooses a PARENT location; the assistant folder is the
  // "Muse" folder the app creates/uses inside it (0.2.1 UX ruling).
  ipcMain.handle('settings:pick-folder', async () => {
    const options = {
      title: 'Choose where the Muse folder should live',
      properties: ['openDirectory', 'createDirectory'],
    };
    const win = context.getSettingsWindow();
    const result = win && !win.isDestroyed()
      ? await dialog.showOpenDialog(win, options)
      : await dialog.showOpenDialog(options);
    if (result.canceled || result.filePaths.length === 0) return null;
    return result.filePaths[0];
  });

  ipcMain.handle('settings:precheck-move', (_event, parentDir) => {
    const dest = destinationForParent(parentDir);
    if (context.moving) {
      return {
        ok: false,
        errors: ['A move is already in progress.'],
        needsMergeConfirm: false,
        totalBytes: 0,
        fileCount: 0,
        freeBytes: 0,
        destination: dest,
      };
    }
    return { ...precheckMove(context.settings.assistantFolder, dest), destination: dest };
  });

  ipcMain.handle('settings:start-move', async (_event, parentDir) => {
    if (context.moving) throw new Error('A move is already in progress.');
    const dest = destinationForParent(parentDir);
    const from = context.settings.assistantFolder;
    context.moving = true; // bridge /health now reports storage: "moving"
    context.abortController = new AbortController();
    try {
      // Engine re-runs pre-checks, copies/renames, and verifies. Any throw
      // here means: partial copy rolled back, old folder still live,
      // setting unchanged.
      const result = await moveAssistantFolder({
        from,
        to: dest,
        signal: context.abortController.signal,
        onProgress: (progress) => {
          const win = context.getSettingsWindow();
          if (win && !win.isDestroyed()) {
            win.webContents.send('settings:move-progress', progress);
          }
        },
      });

      // Verified — flip the setting. Storage accounting and permission
      // scoping root at the new folder from this moment.
      context.settings.assistantFolder = dest;
      saveSettings(context.userDataPath, context.settings);
      console.log(`[assistant-folder] moved: ${from} -> ${dest} (${result.method})`);

      // Guarantee the canonical Workspace/Shared pair at the new home:
      // creates them if the move didn't bring them, and case-renames a
      // lowercase pair that arrived with the moved contents.
      const subfolderActions = normalizeSubfolders(dest);

      // Only now delete the original. A partial failure is reported
      // exactly, not treated as fatal.
      try {
        fs.rmSync(from, { recursive: true, force: true });
      } catch (err) {
        console.error('[assistant-folder] old folder delete failed:', err.message);
      }
      const remains = fs.existsSync(from) ? listRemains(from) : [];

      appendMoveLog(context.userDataPath, {
        from,
        to: dest,
        bytes: result.bytes,
        fileCount: result.fileCount,
        result: `ok method=${result.method}${remains.length ? ` old-folder-remains=${remains.length} items` : ''}`,
      });

      return {
        ok: true,
        from,
        to: dest,
        bytes: result.bytes,
        fileCount: result.fileCount,
        method: result.method,
        remainsAtOld: remains,
        subfolders: subfolderActions,
      };
    } catch (err) {
      appendMoveLog(context.userDataPath, {
        from,
        to: dest,
        result: `failed ${err.code || 'ERROR'}: ${err.message}`,
      });
      console.error('[assistant-folder] move failed:', err.message);
      throw err;
    } finally {
      context.moving = false;
      context.abortController = null;
    }
  });

  ipcMain.on('settings:cancel-move', () => {
    if (context.abortController) context.abortController.abort();
  });
}

module.exports = { registerSettingsHandlers, setRemoteAccess };
