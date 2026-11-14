<div align="center">

# Mac Terminal MCP

**A sandboxed terminal on your Mac for Claude chat and Cowork**

[![Release](https://img.shields.io/github/v/release/mureev/mac-terminal-mcp?label=release&color=238636)](https://github.com/mureev/mac-terminal-mcp/releases)
![macOS](https://img.shields.io/badge/macOS-only-111111?logo=apple&logoColor=white)
![Python](https://img.shields.io/badge/python-3.9%2B%20%C2%B7%20stdlib%20only-3776AB?logo=python&logoColor=white)
![Dependencies](https://img.shields.io/badge/dependencies-0-238636)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

<p><img src="docs/demo.gif" width="760" alt="A real recording of Claude chat on a Mac (Opus 5.5). Asked to fix the failing tests in a small project and then try adding a comment line to ~/.zshrc, Claude uses mac-terminal: the tests are fixed, and the macOS sandbox refuses the ~/.zshrc write with operation not permitted, because shell startup files run later, outside the sandbox. The working part is sped up."></p>

No approval dialogs: the macOS sandbox keeps Claude away from your keys, your Keychain and your startup files.<br>
To install it, give your agent this link:

```
https://github.com/mureev/mac-terminal-mcp
```

</div>

---

## What it is

Claude chat and Cowork have no shell on your Mac itself. This local MCP server gives them one: run commands, keep long
jobs going in tmux, read and edit files. One Python file, standard library only. No npm, no telemetry, no self-update.

- **No approval dialogs.** Every command runs inside one macOS sandbox profile (Seatbelt, the mechanism behind Claude
  Code's own sandbox).
- **What the sandbox stops:** reading `~/.ssh`, `~/.aws` and the Keychain; writing outside your home folder; changing
  files that run later (shell startup files, LaunchAgents, git hooks, Claude's config).
- **What it doesn't stop:** inside your home folder Claude can change or delete files, and the network is on.
- **When it blocks something you asked for** (a `git push`, a `brew install`), Claude reruns it outside the sandbox with
  a one-line reason, and that is logged.

## Is it for you?

On a Mac, with Claude chat or Cowork. If you work in Claude Code, its own `/sandbox` already does this, so you don't need
it. Cowork's built-in shell runs in the cloud or a Linux VM, not in macOS. Desktop Commander gives Claude a shell with no
sandbox at all ([why not the other options](AGENTS.md#why-not-the-standard-options)).

## For agents

Everything an agent needs, to install it and then to use it, is in **[AGENTS.md](AGENTS.md)**. Read it before installing.

## License

[MIT](LICENSE).
