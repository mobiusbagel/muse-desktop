// "Restart Muse" (tray menu, 0.5.4): a full quit + relaunch.
//
// In a portable run the relaunch must NOT be a plain child spawn
// of this process: the NSIS portable stub tears down its process
// tree/job on exit, and a child launched the ordinary way dies
// with it — the same kill that silently ate the 0.5.0/0.5.1 update
// swap. So portable runs relaunch the portable exe through WMI
// (Win32_Process.Create, parented to the WMI service, outside the
// app's tree — the mechanism src/updater.js proved for the swap),
// and only then quit. If the WMI launch errors, fall back to
// Electron's app.relaunch() before quitting: the user must never
// be left with a dead app and no path back short of finding the
// exe. Non-portable runs use app.relaunch() directly.
//
// The decision logic is dependency-free (effects injected) so the
// suite can exercise every path without Electron or Windows.
'use strict';

const { spawnSync } = require('child_process');
const { buildWmiCreateCommand } = require('./updater');

// The WMI command line that starts the exe: double-quoted, since
// a portable commonly lives under a path with spaces.
function exeCommandLine(exePath) {
  return `"${exePath}"`;
}

// Default WMI launcher for an exe path: synchronously issues the
// Win32_Process.Create request; throws on any failure.
function defaultLaunchExeViaWmi(exePath) {
  const result = spawnSync(
    'powershell.exe',
    ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', buildWmiCreateCommand(exeCommandLine(exePath))],
    { stdio: 'ignore', windowsHide: true, timeout: 30_000 },
  );
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`WMI relaunch failed (exit ${result.status === null ? 'killed' : result.status})`);
  }
}

// restartApp({ portableExePath, launchViaWmi, relaunch, quit })
//   portableExePath: PORTABLE_EXECUTABLE_FILE, or null/'' when the
//     run is not the portable build.
//   launchViaWmi(exePath): issues the WMI create; throws on error.
//   relaunch(): Electron's app.relaunch().
//   quit(): the app's normal quit path.
// Returns { via } — 'wmi' | 'relaunch-fallback' | 'relaunch' —
// naming how the next instance was started. quit() is always the
// last effect, and exactly one start mechanism runs first.
function restartApp({ portableExePath, launchViaWmi, relaunch, quit }) {
  let via = 'relaunch';
  if (portableExePath) {
    try {
      launchViaWmi(portableExePath);
      via = 'wmi';
    } catch {
      relaunch();
      via = 'relaunch-fallback';
    }
  } else {
    relaunch();
  }
  quit();
  return { via };
}

module.exports = { restartApp, exeCommandLine, defaultLaunchExeViaWmi };
