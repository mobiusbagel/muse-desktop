// System tray icon, its context menu, and the left-click dispatch.
//
// Design rule (0.5.4): the tray menu is the cockpit of the RUNNING
// app — state + lifecycle only. Destinations (settings, the folder,
// activity) live on the Windows Jump List instead (jumpList.js);
// no item appears on both surfaces.
//
// The menu is built by a PURE template function from an app-state
// snapshot, and createTray rebuilds it whenever main reports a
// state change (window visibility, remote-access toggle, bridge
// bind, updater state) — so what the menu says is always true:
// the toggle reads "Hide Muse" only while the window is visible,
// the Remote Access checkbox mirrors the setting, and the updates
// item turns into the pending restart when one is verified.
'use strict';

const { Tray, Menu, nativeImage } = require('electron');
const fs = require('fs');
const path = require('path');

// Pure dispatch for the tray icon's left-click (0.5.3): the current
// trayLeftClick setting value in, the action out. Anything that is
// not 'settings' is the default 'window' behavior. Dependency-free
// so the suite can exercise it without Electron.
function trayLeftClickTarget(value) {
  return value === 'settings' ? 'settings' : 'window';
}

// The updates item is the state-driven one (0.5.4):
//   checking        → disabled "Checking…"
//   ready           → "Restart to Update to <version>…" — its click
//                     runs the existing ready-prompt flow (main
//                     owns it); it never applies directly.
//   anything else   → "Check for Updates…" (idle, up-to-date, and
//     (idle family)     error/failed all land back here)
function updatesMenuItem(state, actions) {
  if (state.updateState === 'checking') {
    return { label: 'Checking…', enabled: false };
  }
  if (state.updateState === 'ready' && state.pendingVersion) {
    return { label: `Restart to Update to ${state.pendingVersion}…`, click: actions.onRestartUpdate };
  }
  return { label: 'Check for Updates…', click: actions.onCheckForUpdates };
}

// buildTrayMenuTemplate(state, actions) — the whole context menu
// as data, in display order. Pure: no Electron, no globals.
//
// state = {
//   version,           // app version, for the status line
//   bridgeStatusLabel, // the settings window's bridge status line
//                      // (bridgeNetwork's getBridgeStatus label)
//   windowVisible,     // main window currently visible
//   remoteAccess,      // the bridgeRemoteAccess setting
//   updateState,       // updater state ('idle' | 'checking' |
//                      // 'up-to-date' | 'ready' | 'error')
//   pendingVersion,    // verified update's version when ready
// }
// actions = the click callbacks: onToggle, onToggleRemoteAccess,
// onCheckForUpdates, onRestartUpdate, onRestart, onQuit. (The
// settings opener is not a menu action — it is only the left-click
// 'settings' dispatch below.)
function buildTrayMenuTemplate(state, actions) {
  return [
    // Status first: two disabled lines, version and bridge state,
    // in the same wording the settings window uses.
    { label: `Muse ${state.version}`, enabled: false },
    { label: state.bridgeStatusLabel, enabled: false },
    { type: 'separator' },
    // The toggle label states the action it will actually take.
    { label: state.windowVisible ? 'Hide Muse' : 'Show Muse', click: actions.onToggle },
    {
      // Electron flips a checkbox item's checked before click
      // fires; the handler passes the item's new state through to
      // the one settings path (no parallel state here).
      label: 'Remote Access',
      type: 'checkbox',
      checked: !!state.remoteAccess,
      click: (menuItem) => actions.onToggleRemoteAccess(!!(menuItem && menuItem.checked)),
    },
    { type: 'separator' },
    updatesMenuItem(state, actions),
    { label: 'Restart Muse', click: actions.onRestart },
    { label: 'Quit', click: actions.onQuit },
  ];
}

function createTray(deps) {
  const {
    onToggle,
    onOpenSettings,
    onToggleRemoteAccess,
    onCheckForUpdates,
    onRestartUpdate,
    onRestart,
    onQuit,
    getTrayLeftClick,
    getMenuState,
  } = deps;
  // Muse logo at 16 px with a 32 px @2x representation for high-DPI trays.
  const assetsDir = path.join(__dirname, '..', 'assets');
  const icon = nativeImage.createFromPath(path.join(assetsDir, 'tray-16.png'));
  icon.addRepresentation({
    scaleFactor: 2,
    buffer: fs.readFileSync(path.join(assetsDir, 'tray-32.png')),
  });
  const tray = new Tray(icon);
  tray.setToolTip('Muse');

  const actions = {
    onToggle,
    onToggleRemoteAccess,
    onCheckForUpdates,
    onRestartUpdate,
    onRestart,
    onQuit,
  };

  // Rebuild the menu from a fresh state snapshot. Called once at
  // creation and again by main whenever anything the menu renders
  // changes.
  function refreshMenu() {
    tray.setContextMenu(Menu.buildFromTemplate(buildTrayMenuTemplate(getMenuState(), actions)));
  }
  refreshMenu();

  // Left-click dispatches on the CURRENT trayLeftClick setting,
  // read at click time — changing it in the settings window takes
  // effect immediately, no relaunch. 'window' (default) is the
  // historical behavior: toggle the main window.
  tray.on('click', () => {
    const value = typeof getTrayLeftClick === 'function' ? getTrayLeftClick() : undefined;
    if (trayLeftClickTarget(value) === 'settings') onOpenSettings();
    else onToggle();
  });
  return { tray, refreshMenu };
}

module.exports = { createTray, trayLeftClickTarget, buildTrayMenuTemplate };
