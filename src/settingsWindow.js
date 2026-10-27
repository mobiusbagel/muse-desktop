// The Assistant Folder & Storage settings window: a separate BrowserWindow
// loading a LOCAL bundled page. It is never attached to the remote muse.ai
// window; its preload exposes only the settings IPC bridge.
'use strict';

const { BrowserWindow } = require('electron');
const path = require('path');

function createSettingsWindow() {
  const win = new BrowserWindow({
    width: 620,
    height: 680,
    minWidth: 520,
    minHeight: 560,
    title: 'Muse — Assistant Folder & Storage',
    icon: path.join(__dirname, '..', 'assets', 'icon.png'),
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, 'settings', 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });
  win.loadFile(path.join(__dirname, 'settings', 'index.html'));
  return win;
}

module.exports = { createSettingsWindow };
