// Preload for the LOCAL Bridge Activity page only. Exposes exactly one
// call: fetch the formatted activity entries. Never attached to the
// remote muse.ai page.
'use strict';

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('museActivity', {
  getEntries: () => ipcRenderer.invoke('bridge-activity:get-entries'),
});
