# Muse Desktop 0.6.2

**Installed builds can update in place now.**

Through 0.6.1, a Muse installed from the Setup could *see* new
releases but not apply them — the prompt just explained that
updates are portable-only, and updating meant downloading and
running the new Setup by hand. That gap is closed:

- When an update is ready, an installed Muse now offers
  **Install update**. Behind that button it downloads the new
  `Muse-Setup-<version>.exe` and puts it through the same
  fail-closed verification as always — SHA-256 against
  `SHA256SUMS.txt` **and** the Authenticode signer fingerprint
  against the pinned Muse Desktop certificate
  (`0E:C7:DE:56:5D:F4:D6:70:32:07:47:5F:84:09:26:12:3D:03:BE:1B:8F:3D:38:C5:88:5F:22:D6:22:14:3B:DF`,
  unchanged). Only a verified installer is ever launched. Muse
  then closes and the Setup swaps the build in place; your
  settings, permissions, and Bridge token live in userData and are
  untouched.
- **Skipping versions is fine.** The updater always offers the
  latest release, so 0.6.0 installs jump straight here — and this
  build includes everything from 0.6.1, including the
  remember-my-choice permission prompts (per-capability remember;
  `shell.run` remembers the exact command only).
- **Update installs no longer re-ask where the Muse folder
  lives.** The installer's folder page and its hand-off file are
  first-install-only now, guarded on both sides (the installer
  skips them when a settings file exists; the app ignores a stale
  hand-off on an existing install), so an update can never move
  your assistant folder by accident.

Portable builds are unchanged: same self-swap, same "Restart to
update," same one-generation rollback. The rollback net stays
portable-only by design — an installed build's previous version is
the previous Setup.
