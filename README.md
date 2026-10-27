# Muse Desktop

A standalone Windows desktop app for [muse.ai](https://muse.ai): a proper
installed-feeling shell with a system tray icon, a global hotkey, and a
local bridge that lets Muse work with files, apps, and commands on your
PC — every action gated by a permission policy you control, with prompts
on your PC, and a plain-language audit log of everything that happened.

- **App:** Electron shell loading `https://muse.ai` — your session
  persists between launches, and the window remembers its size/position.
- **appId:** `ai.muse.desktop`

## Features

- **Tray resident:** closing the window hides it to the tray. The tray
  menu is the running app's cockpit: two status lines (the version,
  and the bridge status in the same words the settings window uses),
  a **Show Muse / Hide Muse** toggle that always labels the action
  it will take, a **Remote Access** checkbox mirroring the settings
  toggle, a state-aware updates item (**Check for Updates…** →
  **Checking…** → **Restart to Update to \<version\>…**),
  **Restart Muse**, and Quit.
- **Jump List launcher:** right-clicking the app's taskbar icon offers
  three destinations — **Open Assistant Folder**,
  **Assistant Folder & Storage…**, and **Bridge Activity…** — which
  work cold (the app starts straight at the destination) and route to
  the running instance when the app is already open. Nothing is
  duplicated between the tray menu and the Jump List.
- **Global hotkey:** `Ctrl+Alt+M` shows/hides the window from anywhere.
  Single instance: launching again just focuses the running app.
- **Assistant folder:** Muse's home turf on your PC — a folder named
  `Muse` (you pick where it lives; the app creates it) with `Workspace`
  and `Shared` subfolders and a storage cap (default 10 GB). It can be
  moved later from the settings window, with pre-checks, verified copy,
  and rollback on failure.
- **Local Bridge:** an HTTP API on `127.0.0.1:47631` with token auth,
  exposing permission-gated tools: `fs.list`, `fs.read`, `fs.write`,
  `fs.mkdir`, `app.launch`, `process.list`, `process.kill`,
  `shell.run`, `screen.capture` (a PNG screenshot of one display,
  downscaled to at most 2560 px wide by default), and `screen.list`
  (the connected displays — size, DPI scale factor and primary flag,
  indexed to match `screen.capture`'s `displayIndex`). Filesystem tools are
  scoped to the assistant folder (plus folders you explicitly approve);
  every capability defaults to "ask" in `permissions.json`, and
  `shell.run` can never be set to always-allow — its prompt shows the
  exact command, every time. (`screen.capture` is a standard
  capability: its prompt shows a one-line summary and offers
  always-allow.)
- **Bridge Activity:** a window (opened from the taskbar Jump List)
  rendering the audit log in plain language, newest first — what ran,
  what was allowed or refused, and why.
- **Remote access (optional, off by default):** the bridge can also
  listen on your machine's Tailscale address — never a LAN or public
  address — with the same token and permission gates.
- **Tray:** left-clicking the tray icon toggles the window by default;
  a **Tray left-click** option in the settings window switches it to
  opening the settings window instead. Takes effect immediately.
- **In-app updates:** the app checks GitHub Releases, downloads the new
  portable build, and verifies it **twice** before offering it: the
  SHA-256 must match the release's `SHA256SUMS.txt`, **and** the
  Authenticode signer's certificate fingerprint must match the pinned
  Muse Desktop signing certificate. Either check failing deletes the
  download and offers nothing. Applying an update replaces the portable
  exe in place — and because the app writes that file itself, it
  carries no Mark of the Web, so updates don't trip SmartScreen.

## Install

1. Download `Muse-Portable.exe` from the
   [latest release](https://github.com/mobiusbagel/muse-desktop/releases/latest).
   (The portable's name is version-free; the Settings window shows
   the installed version.)
2. Put it anywhere (Desktop is fine) and double-click.

### One-time certificate trust (and an honest SmartScreen note)

Release builds are Authenticode-signed with a **self-signed**
code-signing certificate, CN **Muse Desktop** (SHA-256 fingerprint
`0E:C7:DE:56:5D:F4:D6:70:32:07:47:5F:84:09:26:12:3D:03:BE:1B:8F:3D:38:C5:88:5F:22:D6:22:14:3B:DF`).
A self-signed signature names a publisher, but Windows does not trust
it until you install the public certificate once:

1. Download `muse-signing-cert.cer` (attached to each release) and
   check its fingerprint against the one above.
2. Double-click it → **Install Certificate** → install it into
   **Trusted Root Certification Authorities** and again into
   **Trusted Publishers** (or use `certmgr.msc`).

Even then, be aware: SmartScreen also weighs download *reputation*,
which a self-signed certificate cannot provide, so a browser-downloaded
build may still show a prompt the first time (**More info → Run
anyway**). What the signature does guarantee is tamper-evidence and a
consistent publisher identity — and it is what the in-app updater
verifies before it will offer you an update at all.

## Privacy model

- The muse.ai page runs with **no Node or desktop access**; all desktop
  powers live in the main process and the local settings/activity pages.
- The bridge listens on **loopback only** unless you turn on Tailscale
  remote access (which binds only your Tailscale address).
- Every bridge call requires the per-install token
  (`%APPDATA%\Muse\bridge-token.txt`) and passes the permission policy;
  prompts appear on your PC and time out to "deny" after 60 seconds.
- Every call is appended to a local audit log
  (`%APPDATA%\Muse\bridge-audit.log`) with a summary — paths, targets,
  sizes, the captured dimensions for `screen.capture`, and (for
  `shell.run`) the command itself — never file contents or image data.
- The updater talks to `api.github.com` only, sends no token, and
  verifies downloads as described above before offering anything.

## Build from source

```bash
npm install     # Electron 45 + electron-builder 26 (pinned)
npm start       # run the app from source
npm test        # test suite (plain Node, tests/run-tests.js)
npm run pack    # unpacked app dir (dist/win-unpacked)
npm run dist:portable   # portable single-file exe from the packed dir
npm run dist    # NSIS installer (needs Windows or Wine)
```

The full release pipeline is
`pack → stamp → sign:inner → dist:portable → verify:portable → sign:outer`
(`npm run release`). Signing needs [osslsigncode](https://github.com/mtrojnar/osslsigncode)
and your own code-signing certificate in `signing/` (gitignored):
`muse-signing.pfx`, `pfx-password.txt`, and `muse-signing-cert.pem`.
Unsigned builds work fine; only signing and the release fail-safe care.

**Forks:** the updater pins the Muse Desktop signer's fingerprint in
`src/updater.js` (`PINNED_SIGNER_FINGERPRINT256`). If you sign with
your own certificate, change that constant to your cert's SHA-256
fingerprint, or your builds will (correctly) refuse their own updates.
A few tests exercise the real certificate and the signed release
artifact; they skip cleanly when `signing/` or `dist/` are absent.

## License

MIT — see [LICENSE](LICENSE).
