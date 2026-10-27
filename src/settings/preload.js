// Preload for the LOCAL settings page only. Exposes a minimal, purpose-built
// API over IPC. This preload is never attached to the remote muse.ai page.
'use strict';

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('museSettings', {
  getState: () => ipcRenderer.invoke('settings:get-state'),
  saveCap: (gb) => ipcRenderer.invoke('settings:save-cap', gb),
  setRemoteAccess: (enabled) => ipcRenderer.invoke('settings:set-remote-access', enabled),
  checkUpdates: () => ipcRenderer.invoke('settings:check-updates'),
  setAutoCheck: (enabled) => ipcRenderer.invoke('settings:set-auto-check', enabled),
  pickFolder: () => ipcRenderer.invoke('settings:pick-folder'),
  precheckMove: (dest) => ipcRenderer.invoke('settings:precheck-move', dest),
  startMove: (dest) => ipcRenderer.invoke('settings:start-move', dest),
  cancelMove: () => ipcRenderer.send('settings:cancel-move'),
  onProgress: (cb) => ipcRenderer.on('settings:move-progress', (_event, progress) => cb(progress)),
});
