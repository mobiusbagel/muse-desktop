// Creates the main BrowserWindow: loads muse.ai on the default (persistent)
// session, restores remembered bounds, and allows in-app popup windows so
// sign-in / OAuth flows complete inside the app.
'use strict';

const { BrowserWindow, screen } = require('electron');
const path = require('path');
const WindowState = require('./windowState');

const MUSE_URL = 'https://muse.ai';

function createMainWindow(userDataPath) {
  const state = new WindowState(path.join(userDataPath, 'window-state.json'));
  state.sanitizePosition(screen.getAllDisplays().map((d) => d.bounds));

  const win = new BrowserWindow({
    ...state.bounds,
    minWidth: 800,
    minHeight: 600,
    title: 'Muse',
    icon: path.join(__dirname, '..', 'assets', 'icon.png'),
    autoHideMenuBar: true,
    backgroundColor: '#111318',
    webPreferences: {
      // The remote muse.ai page is untrusted web content from Electron's
      // point of view: no preload, no Node, isolated context, sandboxed.
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });
  if (state.isMaximized) win.maximize();
  state.track(win);

  // target=_blank links and window.open() calls (used by sign-in/OAuth)
  // open as in-app popup windows rather than an external browser, so auth
  // flows are least likely to break. The popups get the same locked-down
  // webPreferences as the main window.
  win.webContents.setWindowOpenHandler(() => ({
    action: 'allow',
    overrideBrowserWindowOptions: {
      autoHideMenuBar: true,
      webPreferences: {
        contextIsolation: true,
        nodeIntegration: false,
        sandbox: true,
      },
    },
  }));

  win.loadURL(MUSE_URL);
  return win;
}

module.exports = { createMainWindow, MUSE_URL };
