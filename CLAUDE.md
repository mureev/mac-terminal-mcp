# Mac Terminal MCP — notes for Claude sessions working on this repo

Read `README.md` first (the fence, the safety model), then `docs/design-decisions.md`.

- **The installed copy is what runs.** Editing this folder changes nothing until a person re-runs `install.sh` in
  their own Terminal (it refuses to run from a command this server runs). Say so when you change the server or the
  policy; never present an edit as live.
- **There are no tiers or dialogs (0.7).** The security boundary is the fence: the Seatbelt profile (`sb_profile`), its
  self-test (`_selftest`), the protected lists in the policy, the file tools' refusals (`protected_write`), and
  `outside_sandbox` (`route_for`). Changes to any of them are security changes. Prefer handing them over as a reviewed
  patch; add a test that fails without the change; never weaken a protection to make a test pass. Don't bring dialogs
  back to fix a gap: close it in the fence, or say plainly that it stays open.
- **Tests.** `python3 -B -m unittest discover -s tests -v`. On Linux (CI, a cloud VM) use `TMPDIR=/tmp`; the Mac-only
  sandbox tests skip there and must also pass on a Mac. Run the suite in Terminal, outside the fence: tests that run
  `git init` create `.git`, which the fence refuses (say which, don't weaken the protection), and the suite tests the
  sandbox itself.
- **In the fence, some things need outside_sandbox** (git push or a private fetch over https, gh, git clone/init,
  brew install, osascript): use it only for what the user asked for, with an honest why. Never for install.sh.
- **Keep it dependency-free.** Standard library only, Python 3.9+, one server file. No network calls from the server.
- **Nothing deployment-specific in this repo**: no host names, internal paths, people's names, tokens or captured
  state. Local configuration (extra `protected_folders`, `deny_paths`) belongs in the user's own
  `policy.local.json`, not in commits.
- **The name lives in constants**: `APP` ("mac-terminal": server key, folders, tmux socket, markers), `APP_TITLE`,
  `APP_ENV` in the server, and `NAME`/`TITLE`/`SERVER_PY`/`ENV_PREFIX` in install.sh. It was Mac Ops ("mac-ops",
  `MAC_OPS`) until 0.7; install.sh's `OLD_*` handles upgrades. Don't spell the name out anywhere else in code.
