// Preload for the LOCAL permission-prompt page only. Exposes just the
// two calls the prompt needs. Never attached to the remote muse.ai page.
'use strict';

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('musePrompt', {
  getRequest: () => ipcRenderer.invoke('bridge-prompt:get-request'),
  respond: (answer) => ipcRenderer.send('bridge-prompt:respond', answer),
});
