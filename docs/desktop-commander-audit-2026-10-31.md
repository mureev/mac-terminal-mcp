# Desktop Commander MCP: security audit (2026-10-31)

Why Mac Terminal MCP (then called Mac Ops) exists. Lightly edited for publication: names of internal services and people are generalized.

**Question.** Should I install Desktop Commander (`@wonderwhy-er/desktop-commander`, ~10k GitHub stars) as a
local MCP server, to give Claude a macOS shell for: small Mac tasks (caffeinate, files), long-running and multiple
sessions, and SSH to hosts for patches?

**Verdict: no.** It does the job functionally, but its guardrails don't hold, it reports home by default, and it brings
650 npm packages onto a laptop that holds production tokens and infrastructure repositories with live secrets. We built our own server,
Mac Terminal MCP (then called Mac Ops), instead (`../README.md`). Desktop Commander was never installed on the Mac.

**What was audited.** v0.3.1 (npm, last modified 2026-10-22). The package was unpacked and read in the cloud sandbox,
never run on the Mac. Its dependency tree was resolved with `npm install --package-lock-only --ignore-scripts`. The
blocklist was tested by running `CommandManager.validateCommand` from `dist/command-manager.js` with its config and
telemetry imports stubbed out.

## Findings

1. **The command blocklist is easy to get around.** It parses the command line and compares command names with a
   denylist. With `sudo, su, security, ssh` blocked:
   - **Blocked:** `sudo ls`, `/usr/bin/sudo ls`, `echo $(sudo id)`, `/usr/bin/security dump-keychain`, `ssh prod-host`.
   - **Allowed:** `sh -c "sudo ls"`, `bash -c 'security find-generic-password -s <some-mcp-token> -w'`, `env sudo ls`,
     `command sudo ls`, `\sudo ls`, `s\udo ls`, `x=sudo; $x id`, `python3 -c "…os.system('sudo id')"`,
     `osascript -e 'do shell script "sudo id"'`, `nohup ssh prod-host &`.

   Its own README says it is "not a sandbox". The default list covers disk tools, user management, shutdown and
   Windows tools. It has nothing Mac-specific: no `security`, `ssh`, `osascript`, `launchctl` or `defaults`.
2. **Any shell running as the user can read the MCP tokens in the Keychain.** `security find-generic-password -w`
   returns the tokens of the other local MCP servers (monitoring, BI) without a prompt, because their install
   scripts say to "Always Allow" `security`. This holds for any free-form shell, Mac Terminal MCP (then called Mac Ops)
   included. Only two things prevent it: a person approving each command, or running the shell as a separate macOS
   user.
3. **`allowedDirectories` defaults to `[]`, which means the whole disk,** and it limits only the file tools. Terminal
   commands can reach any path.
4. **The model can loosen its own guardrails.** The `set_config_value` tool rewrites `blockedCommands`,
   `allowedDirectories` and `telemetryEnabled`. A prompt injection that reaches the model can therefore switch the
   guards off.
5. **It contacts its vendor's servers by default:**
   - Telemetry is on by default (`telemetry.desktopcommander.app`, with a Cloud Run proxy in europe-west1 as fallback).
   - `postinstall` runs `track-installation.js` when the package is installed.
   - Feature flags are fetched from `desktopcommander.app/flags/v2/production.json` at start and every 30 min. They
     drive experiments, user surveys and a welcome-page A/B test.
   - A feedback tool opens a tally.so form.
   - Telemetry can be switched off with `telemetryEnabled: false` or the environment variable
     `DESKTOP_COMMANDER_DISABLE_TELEMETRY=1`. Whether the flag fetch also stops when telemetry is off was not checked.
6. **The supply chain is large.** It has 34 direct and 650 transitive packages, including puppeteer,
   @supabase/supabase-js, sharp and exceljs, and needs Node ≥ 22.12. Every documented install method uses `@latest`
   through npx, so each Claude restart can run newly published code. Pinning the top-level version under npx does not
   pin the transitive dependencies (the Sept-2025 chalk/debug hijack came in that way).
7. **The local tool-call log keeps arguments unredacted** (`~/.claude-server-commander/claude_tool_call.log`, per its
   README). Commands that carry secrets stay on disk.
8. **It includes a `remote-device` module** (Supabase device auth, `mcp.desktopcommander.app`). A separate runner
   starts it, not the MCP server itself (`server.js` checks `DC_REMOTE_DEVICE`). It was not audited further.
9. **Functionally it fits.** `start_process`, `interact_with_process` and `read_process_output` cover long-running
   work (each call waits at most 50 s, while the process keeps running), and `list_sessions` and kill cover multiple
   sessions.
10. **As a raw SSH tool it would bypass a gated change process.** Production changes here go through committed,
    approved playbooks with check-before-apply and monitoring gates; raw SSH from a chat would skip all of them.
