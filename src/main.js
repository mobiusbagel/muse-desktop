// Muse desktop app — main process.
// A standalone Windows shell for muse.ai: tray resident, global hotkey,
// single instance, and the Local Bridge with permission-gated tools
// (Phase 2).
'use strict';

const { app, globalShortcut, ipcMain, dialog, desktopCapturer } = require('electron');
const os = require('os');
const path = require('path');
const { createMainWindow } = require('./mainWindow');
const { createTray } = require('./tray');
const { startBridgeSet, BRIDGE_PORT } = require('./bridge');
const { getBridgeStatus } = require('./bridgeNetwork');
const { probeTailscaleClient } = require('./tailscaleProbe');
const { ensurePermissionsPolicy } = require('./permissions');
const { ensureSettings, saveSettings } = require('./settings');
const { ensureAssistantFolder, getStorageInfo, createAssistantFolderAt } = require('./assistantFolder');
const { createSettingsWindow } = require('./settingsWindow');
const { createActivityWindow, registerActivityHandlers } = require('./activityWindow');
const { registerSettingsHandlers } = require('./settingsHandlers');
const { ensureBridgeToken } = require('./bridgeAuth');
const { createRpcHandler } = require('./rpc');
const { createScreenCapture } = require('./screenCapture');
const { createUpdater } = require('./updater');
const { createPermissionPromptService } = require('./promptService');
const { appendAuditLog } = require('./bridgeAudit');
const { formatBytes, formatPercent } = require('./formatBytes');

// Pin userData to %APPDATA%/Muse no matter how the package is named.
app.setName('Muse');
app.setPath('userData', path.join(app.getPath('appData'), 'Muse'));

// Windows taskbar identity: grouping, jump lists and notifications key
// off the AppUserModelID. Pin it to the packaged appId (ai.muse.desktop)
// before any window is created, so the running app is always "Muse".
if (process.platform === 'win32') {
  app.setAppUserModelId('ai.muse.desktop');
}

const HOTKEY = 'CommandOrControl+Alt+M'; // Ctrl+Alt+M on Windows

let mainWindow = null;
let settingsWindow = null;
let activityWindow = null;
let tray = null;
let bridgeSet = null;
let bridgeDeps = null;
let updater = null;
let isQuitting = false;

// The bridge status for the settings window, computed fresh from the
// live setting + current interfaces (pure logic in bridgeNetwork.js).
// When remote access is on, the Tailscale client probes are gathered
// too, so an unbound status can say why (not connected / not running /
// not installed); probing costs a tasklist call, so it only happens in
// that one case. Probes never affect which hosts get bound.
function currentBridgeStatus() {
  const enabled = !!(context.settings && context.settings.bridgeRemoteAccess);
  return getBridgeStatus(
    enabled,
    os.networkInterfaces(),
    BRIDGE_PORT,
    enabled ? probeTailscaleClient() : null,
  );
}

function onBridgeListen({ host, address, port }) {
  if (host === '127.0.0.1') return; // loopback bind is logged by bridge.js
  // A non-loopback bind is by construction the Tailscale address — the
  // only other host bridgeHosts() ever produces. Never log the token.
  console.log(`[bridge] remote access: Tailscale listener bound at http://${address}:${port} (X-Bridge-Token required)`);
  appendAuditLog(context.userDataPath, {
    ts: new Date().toISOString(),
    event: 'tailnet_listener_bound',
    address: `${address}:${port}`,
  });
}

// (Re)bind the bridge listeners to match the remote-access setting:
// loopback always; the Tailscale IPv4 too when the setting is on and a
// Tailscale address exists. Toggling the setting calls this and applies
// live — no relaunch needed.
async function restartBridgeListeners() {
  if (bridgeSet) {
    const previous = bridgeSet;
    bridgeSet = null;
    await previous.closeAll();
  }
  if (!bridgeDeps) return;
  const status = currentBridgeStatus();
  const hosts = ['127.0.0.1'];
  if (status.mode === 'tailscale') hosts.push(status.address);
  if (status.mode === 'tailscale-missing') {
    console.log('[bridge] remote access is on, but no Tailscale address was detected — loopback only');
  }
  bridgeSet = startBridgeSet({ ...bridgeDeps, hosts, port: BRIDGE_PORT, onListen: onBridgeListen });
}

// Shared state for the settings window / move engine / bridge. `settings`
// is the live object: a successful folder move mutates it in place, so
// storage accounting (and Phase 2 permission scoping) follow immediately.
const context = {
  userDataPath: null,
  settings: null,
  moving: false,
  abortController: null,
  getSettingsWindow: () => settingsWindow,
  getBridgeStatus: () => currentBridgeStatus(),
  applyBridgeAccess: () => restartBridgeListeners(),
  getUpdateState: () => (updater ? updater.getState() : null),
  checkForUpdates: () => (updater ? updater.check() : Promise.resolve(null)),
};

function openSettingsWindow() {
  if (settingsWindow && !settingsWindow.isDestroyed()) {
    settingsWindow.show();
    settingsWindow.focus();
    return;
  }
  settingsWindow = createSettingsWindow();
  settingsWindow.on('closed', () => {
    settingsWindow = null;
  });
}

function openActivityWindow() {
  if (activityWindow && !activityWindow.isDestroyed()) {
    activityWindow.show();
    activityWindow.focus();
    return;
  }
  activityWindow = createActivityWindow();
  activityWindow.on('closed', () => {
    activityWindow = null;
  });
}

function wireWindow(win) {
  // Closing the window hides it to the tray instead of quitting;
  // Quit lives in the tray menu.
  win.on('close', (event) => {
    if (!isQuitting) {
      event.preventDefault();
      win.hide();
    }
  });
  win.on('closed', () => {
    if (mainWindow === win) mainWindow = null;
  });
}

function showWindow() {
  if (!mainWindow || mainWindow.isDestroyed()) {
    mainWindow = createMainWindow(app.getPath('userData'));
    wireWindow(mainWindow);
    return;
  }
  if (mainWindow.isMinimized()) mainWindow.restore();
  mainWindow.show();
  mainWindow.focus();
}

function toggleWindow() {
  if (!mainWindow || mainWindow.isDestroyed() || !mainWindow.isVisible()) {
    showWindow();
  } else {
    mainWindow.hide();
  }
}

function quitApp() {
  isQuitting = true;
  app.quit();
}

// The updater's only prompt (0.5.0): a verified download is ready.
// Portable runs can apply it (self-swap); other runs get the one-line
// reason instead of an action. "Later" keeps the verified file and
// the offer comes back on the next launch's check.
let updatePromptOpen = false;
function showUpdatePrompt(info) {
  if (updatePromptOpen) return;
  updatePromptOpen = true;
  const options = {
    type: 'info',
    title: 'Muse',
    message: `Muse ${info.version} is ready`,
  };
  if (info.canApply) {
    options.buttons = ['Restart to update', 'Later'];
    options.defaultId = 0;
    options.cancelId = 1;
  } else {
    options.buttons = ['OK'];
    options.detail = 'Updates can only be applied from the portable build.';
  }
  dialog
    .showMessageBox(options)
    .then(({ response }) => {
      if (info.canApply && response === 0 && updater) updater.apply();
    })
    .catch(() => {})
    .finally(() => {
      updatePromptOpen = false;
    });
}

// First-run assistant-folder picker. This is the fallback for installs
// that didn't come through the NSIS installer (which asks during setup
// and hands the choice over via assistant-folder.txt): on a true first
// run with no installer choice, ask once here. Later changes go through
// the settings window (tray -> Assistant Folder & Storage).
async function maybePromptForAssistantFolder(userDataPath, settings) {
  const { response } = await dialog.showMessageBox({
    type: 'question',
    buttons: ['Choose location…', 'Use default'],
    defaultId: 1,
    cancelId: 1,
    title: 'Muse — Assistant Folder',
    message: 'Where should the Muse folder live?',
    detail:
      'The assistant folder is Muse\'s home turf on this PC: its Workspace ' +
      'and the files you share with it (in Shared) live there, and the ' +
      'storage cap applies to it. Pick a location and a folder named ' +
      '"Muse" will be created there for you.' +
      `\n\nDefault: ${settings.assistantFolder}` +
      '\n\nYou can move it later from the tray menu ' +
      '(Assistant Folder & Storage).',
  });
  if (response !== 0) return;
  const picked = await dialog.showOpenDialog({
    title: 'Choose where the Muse folder should live',
    properties: ['openDirectory', 'createDirectory'],
  });
  if (!picked.canceled && picked.filePaths.length > 0) {
    // The picker chose a parent location; the app creates the Muse
    // folder (with Workspace + Shared) inside it.
    settings.assistantFolder = createAssistantFolderAt(picked.filePaths[0]);
    saveSettings(userDataPath, settings);
    console.log('[settings] assistant folder chosen on first run:', settings.assistantFolder);
  }
}

// --- Single instance ---------------------------------------------------------
const gotSingleInstanceLock = app.requestSingleInstanceLock();
if (!gotSingleInstanceLock) {
  app.quit();
} else {
  app.on('second-instance', () => {
    showWindow();
  });

  app.whenReady().then(async () => {
    const userDataPath = app.getPath('userData');
    context.userDataPath = userDataPath;
    ensurePermissionsPolicy(userDataPath);

    const ensured = ensureSettings(userDataPath);
    const settings = ensured.values;
    context.settings = settings;
    if (ensured.created && !ensured.fromInstaller) {
      await maybePromptForAssistantFolder(userDataPath, settings);
    }
    try {
      ensureAssistantFolder(settings);
      const info = getStorageInfo(settings);
      console.log(
        `[assistant-folder] ${info.folder} — ${formatBytes(info.usedBytes)} used of ` +
          `${info.maxStorageGB} GB cap (${formatPercent(info.usedBytes, info.maxStorageGB * 1024 ** 3)})`,
      );
    } catch (err) {
      console.error('[assistant-folder] setup failed:', err.message);
    }

    registerSettingsHandlers(ipcMain, context);
    registerActivityHandlers(() => context.userDataPath);

    // Phase 2: bridge token, PC-side permission prompts, and the tool
    // dispatcher that gates every /rpc call through permissions.json.
    const bridgeToken = ensureBridgeToken(userDataPath);
    const promptService = createPermissionPromptService();
    const handleRpc = createRpcHandler({
      userDataPath,
      getSettings: () => context.settings,
      isMoving: () => context.moving,
      prompt: (request) => promptService.ask(request),
      // 0.5.1: screen.capture runs on Electron's desktopCapturer;
      // screenCapture.js holds the (unit-tested) validation/scaling.
      captureScreen: createScreenCapture({
        getSources: (options) => desktopCapturer.getSources(options),
      }),
    });

    bridgeDeps = {
      version: app.getVersion(),
      getStorageInfo: () => getStorageInfo(context.settings),
      isMoving: () => context.moving,
      getBridgeToken: () => bridgeToken,
      handleRpc,
      onAuthFailure: () =>
        appendAuditLog(userDataPath, {
          ts: new Date().toISOString(),
          method: null,
          params: {},
          decision: 'auth-rejected',
          outcome: 'refused',
          error: 'unauthorized',
        }),
    };
    await restartBridgeListeners();

    // 0.5.0: the in-app updater (GitHub Releases; downloads verified
    // against SHA256SUMS.txt AND the pinned Muse Desktop signing
    // cert before anything is offered — see updater.js). Applying
    // replaces this exe, which only portable runs can do.
    updater = createUpdater({
      currentVersion: app.getVersion(),
      userDataPath,
      canApply: !!process.env.PORTABLE_EXECUTABLE_FILE,
      getCurrentExePath: () => process.env.PORTABLE_EXECUTABLE_FILE,
      audit: (entry) => appendAuditLog(userDataPath, entry),
      onReady: (info) => showUpdatePrompt(info),
      onApplyStarted: () => quitApp(),
    });
    updater.cleanupStaleArtifacts();
    if (settings.autoCheckUpdates) {
      const launchCheckTimer = setTimeout(() => {
        updater.check().catch(() => {});
      }, 15_000);
      if (launchCheckTimer.unref) launchCheckTimer.unref();
    }

    mainWindow = createMainWindow(app.getPath('userData'));
    wireWindow(mainWindow);

    tray = createTray({
      onToggle: toggleWindow,
      onOpenSettings: openSettingsWindow,
      onOpenActivity: openActivityWindow,
      onCheckForUpdates: () => {
        if (updater) updater.check().catch(() => {});
      },
      onQuit: quitApp,
    });

    const hotkeyOk = globalShortcut.register(HOTKEY, toggleWindow);
    console.log(`[hotkey] ${HOTKEY} ${hotkeyOk ? 'registered' : 'FAILED to register'}`);

    app.on('activate', showWindow); // macOS nicety; harmless on Windows
  });
}

app.on('before-quit', () => {
  isQuitting = true;
});

app.on('will-quit', () => {
  globalShortcut.unregisterAll();
  if (bridgeSet) bridgeSet.closeAll();
});

// The app is tray-resident: an empty window list is a normal state.
app.on('window-all-closed', () => {});
