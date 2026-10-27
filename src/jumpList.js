// Windows Jump List tasks (0.5.4; Muse section shortcuts added in 0.5.6).
//
// Design rule (0.5.4): the tray menu is the cockpit of the RUNNING
// app (state + lifecycle only); the Jump List is a LAUNCHER
// (destinations only, must work cold). No item lives on both
// surfaces. Update-checking is deliberately NOT a task: launching
// the app already auto-checks, and checking belongs to the running
// app's tray.
//
// app.setUserTasks puts a Tasks section in the app icon's taskbar
// jump list (right-click the pinned/running icon). Each task starts
// the app — or, through the single-instance lock, hands its argv to
// the running instance — with a --task=<name> argument; the router
// below maps that argument to the destination callbacks in main.js.
// This module is dependency-free: task definitions, the argv parser
// and the router are all pure, and main.js supplies the Electron
// calls.
'use strict';

// The task set — nine destinations, in display order. The first
// three (0.5.4) open the app's own satellite surfaces; the six
// after them (0.5.6) jump into Muse itself: the sidebar sections
// with routes (Ideas/Goals/Library/Feed — navigation, see
// src/museNav.js) and the two route-less overlays (Search via
// Ctrl+K, Settings via Ctrl+, — chord actions, also museNav.js).
// `arguments` is the exact string the task launches the exe with;
// parseTaskArg reads it back. Note the Muse settings overlay is
// --task=muse-settings: --task=settings already means the app's
// own Assistant Folder & Storage window and is not disturbed.
const TASK_DEFINITIONS = [
  { task: 'open-folder', title: 'Open Assistant Folder', arguments: '--task=open-folder' },
  { task: 'settings', title: 'Assistant Folder & Storage…', arguments: '--task=settings' },
  { task: 'activity', title: 'Bridge Activity…', arguments: '--task=activity' },
  { task: 'search', title: 'Search', arguments: '--task=search' },
  { task: 'ideas', title: 'Ideas', arguments: '--task=ideas' },
  { task: 'goals', title: 'Goals', arguments: '--task=goals' },
  { task: 'library', title: 'Library', arguments: '--task=library' },
  { task: 'feed', title: 'Feed', arguments: '--task=feed' },
  { task: 'muse-settings', title: 'Settings', arguments: '--task=muse-settings' },
];

const KNOWN_TASKS = new Set(TASK_DEFINITIONS.map((d) => d.task));

// The setUserTasks payload: every task runs the same exe (the
// portable file when there is one, else the app's own path) and
// borrows its icon (index 0 — the stamped Muse logo).
function buildUserTasks(exePath) {
  return TASK_DEFINITIONS.map((d) => ({
    program: exePath,
    arguments: d.arguments,
    iconPath: exePath,
    iconIndex: 0,
    title: d.title,
    description: '',
  }));
}

// The --task value in an argv array, or null. Accepts both the
// '--task=<name>' single-token form (what the tasks above launch)
// and a split '--task' '<name>' pair. Unknown or empty values read
// as no task — a normal launch.
function parseTaskArg(argv) {
  if (!Array.isArray(argv)) return null;
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (typeof arg !== 'string') continue;
    let value = null;
    if (arg.startsWith('--task=')) value = arg.slice('--task='.length);
    else if (arg === '--task' && i + 1 < argv.length) value = argv[i + 1];
    if (value && KNOWN_TASKS.has(value)) return value;
  }
  return null;
}

// Which action key each task routes to. 'check-updates' (and any
// other unknown value) is intentionally absent: parseTaskArg reads
// it as no task, so such a launch is a normal launch. The section
// tasks share one action (the routed task name rides along as the
// call's argument, and src/museNav.js turns it into the URL); the
// two overlay tasks share the chord action the same way.
const TASK_ACTIONS = {
  settings: 'onOpenSettings',
  'open-folder': 'onOpenAssistantFolder',
  activity: 'onOpenActivity',
  search: 'onMuseChord',
  ideas: 'onOpenMuseSection',
  goals: 'onOpenMuseSection',
  library: 'onOpenMuseSection',
  feed: 'onOpenMuseSection',
  'muse-settings': 'onMuseChord',
};

// routeTaskArg(argv, actions) → the routed task name, or null when
// the argv carries no (known) task — the caller then does its
// default launch behavior. The action is called with the task
// name, so shared actions (sections, chords) know which task they
// are serving. A known task whose action is missing is still
// reported as routed: the launch asked for a task, so the default
// window show must not happen on its account.
function routeTaskArg(argv, actions) {
  const task = parseTaskArg(argv);
  if (!task) return null;
  const fn = actions ? actions[TASK_ACTIONS[task]] : null;
  if (typeof fn === 'function') fn(task);
  return task;
}

module.exports = { TASK_DEFINITIONS, TASK_ACTIONS, buildUserTasks, parseTaskArg, routeTaskArg };
