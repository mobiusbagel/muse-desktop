# Muse Desktop 0.6.0

**Releases are machine-built now — and there's a real installer.**

The app itself is unchanged from 0.5.9: same Bridge, same tools,
same behavior. What changed is how a release gets made, and what
you can download.

- **Built by GitHub Actions.** Every release from here on is built,
  signed, and verified by the pipeline in
  `.github/workflows/release.yml` when a version tag is pushed —
  same steps as the hand-run chain (pack → stamp → sign → verify),
  same certificate, with one new gate before anything publishes:
  each artifact's signer fingerprint is checked against the exact
  constant the in-app updater pins, the same test your running app
  applies to a download before it dares apply it.
- **`Muse-Setup-0.6.0.exe` — the installer is here.** A per-user
  install (no admin prompt) with Start Menu and desktop shortcuts.
  One page of the wizard asks where the **Muse folder** should
  live: pick a parent location and a `Muse` folder is created
  there with `Workspace` and `Shared` inside it. Two things worth
  knowing: the choice you make in the installer is applied on the
  app's first run, so if you already have a Muse folder, pick
  *its* parent location to keep using it — and quit the portable
  before installing, since the two builds share the same data.
  An installed Muse also starts instantly: no portable extraction
  step, ever.
- **`SHA256SUMS.txt` now covers both downloads** (the portable and
  the Setup). The old `Muse-win-unpacked` zip is retired; the
  portable *is* the unpacked app, wrapped.

**Updating from 0.5.9 works exactly as before** — an installed or
portable build downloads this release, verifies it (SHA-256 against
`SHA256SUMS.txt` **and** the Authenticode signature against the
Muse Desktop certificate, fingerprint unchanged:
`0E:C7:DE:56:5D:F4:D6:70:32:07:47:5F:84:09:26:12:3D:03:BE:1B:8F:3D:38:C5:88:5F:22:D6:22:14:3B:DF`),
and **Restart to update** swaps and relaunches it. Switching to
the installed build instead is a one-way door worth taking: run
the Setup once, and every future release still arrives in-app.
