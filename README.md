# maki-lancet-guard

A bash command guard for [maki](https://github.com/tontinton/maki), a port
of [pi-automode-classifier](https://github.com/deepu105/pi-automode-classifier)
by Deepu K Sasidharan: its stage design and rule categories, rebuilt on
maki's plugin API, with [LANCET Nano](https://github.com/TannerMidd/LANCET-model)
as its only model. Every `bash` tool call goes through two local stages:

1. **Rules** settle most calls in under a millisecond: the catastrophic are
   blocked, what only you can own asks you, routine work passes through to
   maki's own permission flow, and the rest goes to stage 2.
2. **LANCET** scores the command's risk on your CPU, in about 15 to 30 ms.
   A score at or above `ask_above` (0.2 by default) asks you; below that,
   the call continues.

There is no chat-model stage and nothing leaves your machine. The ask
survives allow rules and yolo mode, and `maki -p` denies it, so a headless
run fails closed. A daemon that is down or slow asks instead of letting a
command through.

## Install

Declare it in your global `init.lua` (`~/.config/maki/init.lua`), then
restart maki and accept the install prompt:

```lua
maki.pack.add({
  { src = "https://github.com/amirs-maki-plugins/maki-lancet-guard", version = "v1.0.0" },
})
```

Requires maki 0.7.0 or newer, `curl`, `unzip` and [uv](https://docs.astral.sh/uv/)
on your PATH. Update with `/packupdate maki-lancet-guard`.

Then download the model once:

```
/lancet-guard setup
```

This fetches the LANCET Nano v0.4.3 release from GitHub, verifies it
against the release's SHA-256 checksums, and builds a uv venv under
`~/.local/state/maki/lancet-guard/`. The bridge daemon that serves the
model is written there too.

## Use

The guard is on once installed. Per session:

- `/lancet-guard off` and `/lancet-guard on` toggle it. The state lives in
  `~/.local/state/maki/lancet-guard/state.json`, outside your project, so
  the agent cannot flip it silently.
- `/lancet-guard` shows the state: on or off, install and daemon status,
  and this session's counts.

The daemon starts on the first command the rules leave to LANCET, serves
every maki process on the machine, and exits after five idle minutes.
`/lancet-guard-spec` runs the plugin's test cases.

## What the rules do

The deny verdicts never reach the model: `rm -rf` of `/`, `$HOME` or a
system directory, `mkfs`, `dd` to a raw disk, fork bombs. Neither a
permissive model nor text planted in the transcript can let those through.

The asks cover what only you can own: root (`sudo`, `su`, `doas`),
publishing (`git push`, `gh pr`, `npm publish`, `docker push`, `git reset
--hard`), data leaving the machine (`curl -d`, `scp`, `nc`, remote
`rsync`, `ssh`), `curl | sh`, credential reads (`~/.ssh`, `~/.aws`,
`.env`, `*.pem`, `/etc/shadow`, ...), file changes outside the working
directory, package and service changes (`brew install`, `apt`,
`systemctl`), and anything touching maki's own configuration or this
guard's state.

Allowed without a prompt: read-only commands, builds, tests and linters,
local git work, and file changes inside the working directory or `/tmp`.
Everything else, like `kubectl delete` or a script with `deploy` in its
name, goes to LANCET.

## Configuration

Options go under `plugins.lancet_guard` in `maki.setup`:

```lua
maki.setup({
  plugins = {
    lancet_guard = {
      ask_above = 0.2,       -- LANCET risk score at or above which a call asks
      timeout_ms = 5000,     -- wait for one LANCET score
      start_timeout_ms = 10000, -- wait for the daemon to start
    },
  },
})
```

`0.2` is pi-automode-classifier's default. LANCET's own review threshold is
`0.2956`; a lower `ask_above` catches more risky commands and prompts on
more safe ones.

## Limits

LANCET reads the command line only. It cannot see what you asked the agent
to do, so the rules' asks (`git push`, `ssh`) always prompt: no model can
clear them. Commands over 8,192 bytes ask. The classifier never blocks a
call by itself; only the rules deny.

## Credits

The stage design, rule categories and default thresholds are ported from
[pi-automode-classifier](https://github.com/deepu105/pi-automode-classifier)
(MIT). The classifier is
[LANCET Nano](https://github.com/TannerMidd/LANCET-model) (Apache-2.0), a
CodeT5+ 220M command-risk model, downloaded from its releases at setup and
served locally through ONNX Runtime.
