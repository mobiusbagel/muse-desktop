// System tray icon with a Show/Hide + Quit menu.
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

function createTray({ onToggle, onOpenSettings, onOpenActivity, onCheckForUpdates, onQuit, getTrayLeftClick }) {
  // Muse logo at 16 px with a 32 px @2x representation for high-DPI trays.
  const assetsDir = path.join(__dirname, '..', 'assets');
  const icon = nativeImage.createFromPath(path.join(assetsDir, 'tray-16.png'));
  icon.addRepresentation({
    scaleFactor: 2,
    buffer: fs.readFileSync(path.join(assetsDir, 'tray-32.png')),
  });
  const tray = new Tray(icon);
  tray.setToolTip('Muse');

  const menu = Menu.buildFromTemplate([
    { label: 'Show/Hide Muse', click: onToggle },
    { label: 'Assistant Folder & Storage…', click: onOpenSettings },
    { label: 'Bridge Activity…', click: onOpenActivity },
    { label: 'Check for Updates…', click: onCheckForUpdates },
    { type: 'separator' },
    { label: 'Quit', click: onQuit },
  ]);
  tray.setContextMenu(menu);
  // Left-click dispatches on the CURRENT trayLeftClick setting,
  // read at click time — changing it in the settings window takes
  // effect immediately, no relaunch. 'window' (default) is the
  // historical behavior: toggle the main window.
  tray.on('click', () => {
    const value = typeof getTrayLeftClick === 'function' ? getTrayLeftClick() : undefined;
    if (trayLeftClickTarget(value) === 'settings') onOpenSettings();
    else onToggle();
  });
  return tray;
}

module.exports = { createTray, trayLeftClickTarget };
