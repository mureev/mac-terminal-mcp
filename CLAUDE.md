# Mac Ops — notes for Claude sessions working on this repo

Read `README.md` first (safety model, tiers), then `docs/design-decisions.md`.

- **The installed copy is what runs.** Editing this folder changes nothing until a person re-runs `install.sh`
  (which is tier 2: it always asks). Say so when you change the server or the policy; never present an edit as live.
- **This repo is its own approval code.** Changes to tiers, the read allowlist, grants, deny lists or the Seatbelt
  profiles are security changes. Prefer handing them over as a reviewed patch; add a test that fails without the
  change; never weaken a protection to make a test pass.
- **Tests.** `python3 -B -m unittest discover -s tests -v`. On Linux (CI, a cloud VM) use `TMPDIR=/tmp`; the Mac-only
  sandbox tests skip there and must also pass on a Mac. Tests that run `git init` fail inside a Mac Ops grant (the
  sandbox forbids creating `.git`) and pass in Terminal: say which, don't weaken the protection. The suite tests the
  sandbox itself, so run it outside the sandbox.
- **Mac Ops' read classifier works on the command's text.** A `$`, a glob, a program outside its read list
  (`python3`, `rsync`, `tmux` ...) or a tier-2 program in the line turns a free read into a dialog. Keep reads plain;
  read files with `read_file`.
- **Keep it dependency-free.** Standard library only, Python 3.9+, one server file. No network calls from the server.
- **Nothing deployment-specific in this repo**: no host names, internal paths, people's names, tokens or captured
  state. Local configuration (extra `protected_folders`, `deny_paths`) belongs in the user's own copy of
  `policy.json`, not in commits.
