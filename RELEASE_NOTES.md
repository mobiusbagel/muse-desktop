# Muse Desktop 0.6.1

**Bridge permission prompts can remember your choice now — including, carefully, shell commands.**

Every permission prompt on this PC gains a "Remember my choice"
checkbox. What it buys depends on what is being asked:

- **Ordinary capabilities** (reading, writing, listing, deleting or
  moving files, launching apps, processes, screenshots): remembering
  sets that capability to "allow" in `permissions.json`, exactly what
  the old "Always allow this capability" checkbox did — it just says
  what it means now.
- **`shell.run` is different, on purpose.** The checkbox there reads
  "Remember this exact command." Only that command — byte for byte —
  runs without asking from then on. Change one character, one space,
  one quote, and it asks again. The `shell.run` capability itself
  still can never be set to "allow": a hand-edited `permissions.json`
  cannot make shell silent, and a stored "deny" for the capability
  still beats the remembered list.

Remembered commands live in `permissions.json` as `shellAllowlist`,
next to the capability policies. Delete a line from that list and the
command asks again. The Bridge audit log records these runs with the
decision `allowlist`, so what ran on trust stays visible.

Nothing else changes in 0.6.1: same Bridge tools, same prompts
otherwise, same update path. **Updating works exactly as before** —
the app downloads this release, verifies it (SHA-256 against
`SHA256SUMS.txt` **and** the Authenticode signature against the
Muse Desktop certificate, fingerprint unchanged:
`0E:C7:DE:56:5D:F4:D6:70:32:07:47:5F:84:09:26:12:3D:03:BE:1B:8F:3D:38:C5:88:5F:22:D6:22:14:3B:DF`),
and **Restart to update** swaps and relaunches it.
