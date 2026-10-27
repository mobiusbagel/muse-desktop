// System tray icon with a Show/Hide + Quit menu.
'use strict';

const { Tray, Menu, nativeImage } = require('electron');
const fs = require('fs');
const path = require('path');

function createTray({ onToggle, onOpenSettings, onOpenActivity, onCheckForUpdates, onQuit }) {
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
  tray.on('click', onToggle);
  return tray;
}

module.exports = { createTray };
