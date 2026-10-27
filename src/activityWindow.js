// The Bridge Activity window: a separate BrowserWindow loading a LOCAL
// bundled page that renders the bridge audit log in plain language
// (parsed and formatted in the main process — see bridgeActivity.js).
// Read-only by construction: the page can ask for entries, nothing
// else; there is no edit or delete path for the log.
'use strict';

const { BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const { readBridgeActivity } = require('./bridgeActivity');

function createActivityWindow() {
  const win = new BrowserWindow({
    width: 760,
    height: 560,
    minWidth: 560,
    minHeight: 360,
    title: 'Muse — Bridge Activity',
    icon: path.join(__dirname, '..', 'assets', 'icon.png'),
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, 'activity', 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });
  win.loadFile(path.join(__dirname, 'activity', 'index.html'));
  return win;
}

// One IPC channel: hand the renderer the formatted entries. Registered
// once from main.js; the getter supplies the live userData path.
function registerActivityHandlers(getUserDataPath) {
  ipcMain.handle('bridge-activity:get-entries', () => readBridgeActivity(getUserDataPath()));
}

module.exports = { createActivityWindow, registerActivityHandlers };
