// Muse desktop app — main process.
// A standalone Windows shell for muse.ai: tray resident, global hotkey,
// single instance, and the Local Bridge with permission-gated tools
// (Phase 2).
'use strict';

const { app, globalShortcut, ipcMain, dialog, desktopCapturer, screen, shell } = require('electron');
const os = require('os');
const path = require('path');
const { createMainWindow } = require('./mainWindow');
const { createTray } = require('./tray');
const { buildUserTasks, parseTaskArg, routeTaskArg } = require('./jumpList');
const { sectionUrlForTask, navigateWindowToSection, chordForTask, sendChordWhenReady } = require('./museNav');
const { restartApp, defaultLaunchExeViaWmi } = require('./restartApp');
const { startBridgeSet, BRIDGE_PORT } = require('./bridge');
const { getBridgeStatus } = require('./bridgeNetwork');
const { probeTailscaleClient } = require('./tailscaleProbe');
const { ensurePermissionsPolicy } = require('./permissions');
const { ensureSettings, saveSettings } = require('./settings');
const { ensureAssistantFolder, getStorageInfo, createAssistantFolderAt } = require('./assistantFolder');
const { createSettingsWindow } = require('./settingsWindow');
const { createActivityWindow, registerActivityHandlers } = require('./activityWindow');
const { registerSettingsHandlers, setRemoteAccess } = require('./settingsHandlers');
const { ensureBridgeToken } = require('./bridgeAuth');
const { createRpcHandler } = require('./rpc');
const { createScreenCapture, createScreenList } = require('./screenCapture');
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
let trayHandle = null;
let bridgeSet = null;
let bridgeDeps = null;
let updater = null;
let isQuitting = false;
// The section URL the main window was created at on a Jump List
// section-task cold start (0.5.6), consumed by openMuseSection so
// the router does not navigate a window that is already loading
// its destination.
let coldStartSectionUrl = null;

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
  checkForUpdates: () =>
    updater
      ? updater.check().then((s) => {
          refreshTrayMenu();
          return s;
        })
      : Promise.resolve(null),
  // Restore previous version (0.5.8): the settings window's one
  // rollback control runs the updater's reverse swap; a successful
  // start quits the app through the updater's onApplyStarted, like
  // a forward apply.
  restorePreviousUpdate: () => (updater ? updater.restorePrevious() : { ok: false, reason: 'no-updater' }),
  // The shared remote-access path (settingsHandlers) calls this
  // after a toggle so the tray menu's checkbox + status line stay
  // true no matter which surface flipped the setting.
  refreshTrayMenu: () => refreshTrayMenu(),
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

// --- Tray menu state (0.5.4) -------------------------------------------------
// The tray menu is rebuilt from a fresh snapshot whenever anything
// it renders changes: window show/hide (here in wireWindow), the
// remote-access setting (either surface — the shared settings path
// calls context.refreshTrayMenu), bridge rebinds, and updater
// state transitions (check start/settle, ready).
function trayMenuState() {
  const s = updater ? updater.getState() : null;
  return {
    version: app.getVersion(),
    bridgeStatusLabel: currentBridgeStatus().label,
    windowVisible: !!(mainWindow && !mainWindow.isDestroyed() && mainWindow.isVisible()),
    remoteAccess: !!(context.settings && context.settings.bridgeRemoteAccess),
    updateState: s ? s.state : 'idle',
    pendingVersion: s ? s.pendingVersion : null,
  };
}

function refreshTrayMenu() {
  if (trayHandle) trayHandle.refreshMenu();
}

// "Open Assistant Folder" (Jump List task): the folder root in
// Explorer — Workspace and Shared live directly inside it.
function openAssistantFolder() {
  const folder = context.settings && context.settings.assistantFolder;
  if (!folder) return;
  shell.openPath(folder).then((error) => {
    if (error) console.error('[shell] could not open the assistant folder:', error);
  });
}

// The tray's updates item, idle family: run a check and keep the
// menu honest while it runs (state reads 'checking' synchronously;
// refresh again when it settles into ready/up-to-date/error).
function trayCheckForUpdates() {
  if (!updater) return;
  const pending = updater.check();
  refreshTrayMenu();
  pending.then(
    () => refreshTrayMenu(),
    () => refreshTrayMenu(),
  );
}

// The tray's updates item, ready state: the EXISTING ready prompt
// (same dialog, same confirm semantics as the onReady flow) — the
// menu item never applies an update by itself.
function trayRestartToUpdate() {
  if (!updater) return;
  const s = updater.getState();
  if (s.state === 'ready' && s.pendingVersion) {
    showUpdatePrompt({ version: s.pendingVersion, canApply: s.canApply, canInstall: s.canInstall });
  }
}

// The tray's Remote Access checkbox runs the one settings path
// (settingsHandlers.setRemoteAccess — the settings window's toggle
// is the same code, including persistence, live rebind, and the
// tray-menu refresh at the end).
function trayToggleRemoteAccess(enabled) {
  setRemoteAccess(context, enabled).catch((err) => {
    console.error('[settings] remote access toggle failed:', err.message);
  });
}

// "Restart Muse": portable runs relaunch the portable exe via
// WMI (outside the stub's process tree — see restartApp.js), other
// runs via app.relaunch(); a WMI failure falls back to relaunch.
// Either way this instance then quits through the normal path.
function restartMuse() {
  const { via } = restartApp({
    portableExePath: process.env.PORTABLE_EXECUTABLE_FILE || null,
    launchViaWmi: defaultLaunchExeViaWmi,
    relaunch: () => app.relaunch(),
    quit: quitApp,
  });
  console.log(`[restart] next instance launched via ${via}`);
}

// A Jump List Muse section task (0.5.6: Ideas/Goals/Library/
// Feed): the main window is the destination. Show + focus it, then
// navigate — unless this is the cold start that created the window
// directly at the section URL, in which case it is already loading
// the right page and a second navigation would only restart it.
function openMuseSection(task) {
  const alreadyRequested = coldStartSectionUrl;
  coldStartSectionUrl = null;
  showWindow();
  navigateWindowToSection(mainWindow, task, alreadyRequested);
}

// A Jump List Muse overlay task (0.5.6: Search / Settings): the
// overlays have no URL — they open with Muse's own global chords
// (Ctrl+K / Ctrl+,). Show + focus the window and send the chord as
// input events once the page has loaded; sendChordWhenReady skips
// (and logs) rather than firing blind if the load never finishes.
// No navigation: the chords are app-global in Muse and land on
// whatever muse.ai page is showing.
function openMuseChord(task) {
  const chord = chordForTask(task);
  if (!chord) return;
  showWindow();
  if (!mainWindow || mainWindow.isDestroyed()) return;
  sendChordWhenReady({
    webContents: mainWindow.webContents,
    chord,
    log: (message) => console.log(message),
  }).catch((err) => console.error('[muse-nav] chord failed:', err.message));
}

// The Jump List tasks' destination callbacks (all hoisted
// function declarations in this module). Since 0.5.4's split the
// tray menu carries none of these — destinations are launcher-only.
const taskActions = {
  onOpenSettings: openSettingsWindow,
  onOpenAssistantFolder: openAssistantFolder,
  onOpenActivity: openActivityWindow,
  onOpenMuseSection: openMuseSection,
  onMuseChord: openMuseChord,
};

function wireWindow(win) {
  // Closing the window hides it to the tray instead of quitting;
  // Quit lives in the tray menu.
  win.on('close', (event) => {
    if (!isQuitting) {
      event.preventDefault();
      win.hide();
    }
  });
  // The tray menu's toggle item labels itself from the window's
  // visibility — keep it true as the window comes and goes.
  win.on('show', () => refreshTrayMenu());
  win.on('hide', () => refreshTrayMenu());
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
// Portable runs apply it by self-swap ("Restart to update");
// installed runs apply it by launching the verified installer
// (0.6.2, "Install update" — Muse closes and the Setup swaps the
// build in place). A run with neither path gets the one-line reason
// instead of an action. "Later" keeps the verified file and the
// offer comes back on the next launch's check.
let updatePromptOpen = false;
function showUpdatePrompt(info) {
  if (updatePromptOpen) return;
  updatePromptOpen = true;
  const options = {
    type: 'info',
    title: 'Muse',
    message: `Muse ${info.version} is ready`,
  };
  const actionable = Boolean(info.canApply || info.canInstall);
  if (info.canApply) {
    options.buttons = ['Restart to update', 'Later'];
    options.defaultId = 0;
    options.cancelId = 1;
  } else if (info.canInstall) {
    options.buttons = ['Install update', 'Later'];
    options.defaultId = 0;
    options.cancelId = 1;
    options.detail = 'Muse will close and the verified installer will update it in place.';
  } else {
    options.buttons = ['OK'];
    options.detail = 'Updates can only be applied from the portable build.';
  }
  dialog
    .showMessageBox(options)
    .then(({ response }) => {
      if (actionable && response === 0 && updater) updater.apply();
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
  app.on('second-instance', (_event, argv) => {
    // A Jump List task launch arrives here as the second instance's
    // argv (the lock keeps it from ever becoming its own instance):
    // route the task; anything else is a plain re-launch → focus.
    if (!routeTaskArg(argv, taskActions)) showWindow();
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
      // 0.5.3: screen.list reads Electron's screen module. INDEX
      // ALIGNMENT is the contract (see screenCapture.js): the list
      // must be ordered the way desktopCapturer orders its screen
      // sources, so an entry's index is capture's displayIndex for
      // the same display. Both enumerations come from Electron, but
      // the provider does not trust them to agree implicitly — it
      // re-orders getAllDisplays() by matching each capturer
      // source's display_id to the Display.id it belongs to, in
      // source order. Displays the capturer did not enumerate keep
      // their relative order at the end; if the capturer call fails
      // outright, getAllDisplays() order is used as-is. width/height
      // are DIP sizes (Display.size), scaleFactor and the primary
      // flag ride along for the module to normalize.
      listScreens: createScreenList({
        getDisplays: async () => {
          const displays = screen.getAllDisplays();
          const primaryId = screen.getPrimaryDisplay().id;
          let ordered = displays;
          try {
            const sources = await desktopCapturer.getSources({
              types: ['screen'],
              thumbnailSize: { width: 1, height: 1 },
            });
            const byId = new Map(displays.map((d) => [String(d.id), d]));
            const aligned = [];
            for (const source of sources) {
              const match = byId.get(String(source.display_id));
              if (match) {
                aligned.push(match);
                byId.delete(String(source.display_id));
              }
            }
            ordered = [...aligned, ...byId.values()];
          } catch {
            // Capturer unavailable: fall back to screen-module order.
          }
          return ordered.map((d) => ({
            width: d.size.width,
            height: d.size.height,
            scaleFactor: d.scaleFactor,
            isPrimary: d.id === primaryId,
          }));
        },
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
      // 0.6.2: anything that is not the portable build is an
      // installed run, whose update path is the verified installer.
      canInstall: !process.env.PORTABLE_EXECUTABLE_FILE,
      getCurrentExePath: () => process.env.PORTABLE_EXECUTABLE_FILE,
      audit: (entry) => appendAuditLog(userDataPath, entry),
      onReady: (info) => {
        refreshTrayMenu();
        showUpdatePrompt(info);
      },
      onApplyStarted: () => quitApp(),
    });
    // 0.5.8: judge the pending record a previous apply left behind
    // against the apply log (see updater.js) — a successful swap
    // into THIS version becomes the confirmed last-update marker
    // the settings Restore control reads; anything else is
    // consumed without one.
    updater.reconcileUpdateMarker();
    updater.cleanupStaleArtifacts();
    if (settings.autoCheckUpdates) {
      const launchCheckTimer = setTimeout(() => {
        updater
          .check()
          .catch(() => {})
          .finally(() => refreshTrayMenu());
      }, 15_000);
      if (launchCheckTimer.unref) launchCheckTimer.unref();
    }

    // A cold launch carrying a Jump List task (--task=…) starts
    // tray-resident: the main window is created hidden and only
    // the task's own surface appears (settings/activity windows;
    // open-folder shows nothing of its own). The exception is a
    // Muse section task (0.5.6): there the main window IS the
    // destination, so it is created shown, directly at the
    // section URL, and openMuseSection (routed below) leaves the
    // in-flight load alone via coldStartSectionUrl. The overlay
    // (chord) tasks keep the hidden start — their action shows
    // the window itself.
    const startupTask = parseTaskArg(process.argv);
    const startupSectionUrl = startupTask ? sectionUrlForTask(startupTask) : null;
    coldStartSectionUrl = startupSectionUrl;
    mainWindow = createMainWindow(app.getPath('userData'), {
      show: !startupTask || !!startupSectionUrl,
      url: startupSectionUrl || undefined,
    });
    wireWindow(mainWindow);

    trayHandle = createTray({
      onToggle: toggleWindow,
      onToggleRemoteAccess: trayToggleRemoteAccess,
      onCheckForUpdates: trayCheckForUpdates,
      onRestartUpdate: trayRestartToUpdate,
      onRestart: restartMuse,
      onQuit: quitApp,
      getMenuState: trayMenuState,
    });

    // Jump List tasks (Windows): the nine destination commands
    // ride the app icon's taskbar menu; each launches with
    // --task=<name>, routed above on cold start and via
    // second-instance afterwards. The tasks borrow the running
    // exe's icon (the stamped logo).
    if (process.platform === 'win32') {
      const exePath = process.env.PORTABLE_EXECUTABLE_FILE || process.execPath;
      try {
        app.setUserTasks(buildUserTasks(exePath));
      } catch (err) {
        console.error('[jump-list] setUserTasks failed:', err.message);
      }
    }
    if (startupTask) routeTaskArg(process.argv, taskActions);

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
