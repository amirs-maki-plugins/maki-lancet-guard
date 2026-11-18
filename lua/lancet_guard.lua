-- lancet_guard: gates bash tool calls through two local stages, a port of
-- pi-automode-classifier's design with LANCET as its only model:
--   1. rules  deny the catastrophic, ask for what only the user can own,
--      allow routine work, and pass the rest on
--   2. LANCET scores what the rules leave open; a high score asks
-- There is no chat-model stage. A call the guard cannot score asks rather
-- than runs, and the ask survives allow rules and yolo mode.
--
-- The model bundle is the user's to install: the plugin writes an
-- install.sh next to the state it keeps, and every not-installed message
-- points at that one command.

local rules = require("lancet_rules")
local client = require("lancet_client")
local daemon = require("lancet_daemon")
local bridge_src = require("lancet_bridge_src")

local LANCET_VERSION = "v0.4.3"
local BUNDLE_DIRNAME = "lancet-" .. LANCET_VERSION .. "-nano-cpu-int8"
local RELEASE_BASE = "https://github.com/TannerMidd/LANCET-model/releases/download"
local DOWNLOAD_URL = RELEASE_BASE .. "/" .. LANCET_VERSION .. "/" .. BUNDLE_DIRNAME .. ".zip"
local SUMS_URL = RELEASE_BASE .. "/" .. LANCET_VERSION .. "/SHA256SUMS.txt"

local DENY_PREFIX = "BLOCKED by lancet-guard: "
local DENY_SUFFIX = ". Find a safer path, or ask the user to run it themselves."
local ASK_PREFIX = "lancet-guard: "
local SCORE_ASK_FMT = "LANCET scored this command's risk at %.2f."
local UNSCORED_FMT = "lancet-guard could not score this command (%s)."
local LONG_COMMAND_ASK = "lancet-guard: the command is too long for the classifier."
local PROTECTED_FMT = "the call touches a protected path (%s)."

-- LANCET reads at most this many bytes; past it the answer is always review.
local MAX_COMMAND_BYTES = 8192

local function normalize_tilde(p, home)
  if p:sub(1, 2) == "~/" then
    return home .. p:sub(2)
  elseif p == "~" then
    return home
  end
  return p
end

-- Written to the state dir on load, run by the user in their own terminal.
local INSTALL_SH_FMT = [==[
#!/bin/sh
# Installs LANCET Nano %s for maki-lancet-guard into this directory.
set -e
cd "$(dirname "$0")"
curl -fL -o %s.zip %s
curl -fL -o SHA256SUMS.txt %s
shasum -a 256 -c SHA256SUMS.txt || sha256sum -c SHA256SUMS.txt
unzip -o %s.zip
uv venv venv
uv pip install --python venv/bin/python -r %s/requirements.txt
rm -f %s.zip
echo "lancet-guard: installed. Run /lancet-guard in maki to check."
]==]

local opts = maki.api.register_options({
  ask_above = { default = 0.2, min = 0, desc = "LANCET risk score at or above which a bash call asks the user" },
  timeout_ms = { default = 5000, min = 100, desc = "Milliseconds to wait for one LANCET score" },
  start_timeout_ms = { default = 10000, min = 500, desc = "Milliseconds to wait for the LANCET daemon to start" },
})

local state_dir = maki.env.state_dir()
if not state_dir then
  maki.log.error("lancet_guard: no state directory, the guard stays off")
  return
end

local base = state_dir .. "/lancet-guard"
local paths = {
  base = base,
  socket = base .. "/daemon.sock",
  bridge = base .. "/bridge.py",
  install = base .. "/install.sh",
  log = base .. "/daemon.log",
  state = base .. "/state.json",
  bundle = base .. "/" .. BUNDLE_DIRNAME,
  classify = base .. "/" .. BUNDLE_DIRNAME .. "/classify.py",
  model = base .. "/" .. BUNDLE_DIRNAME .. "/model",
  python = base .. "/venv/bin/python",
  venv = base .. "/venv",
}
paths.ready = function()
  return maki.fn.executable(paths.python) == 1
    and (maki.fs.metadata(paths.classify) or {}).is_file == true
end

local rule_ctx = {
  cwd = maki.uv.cwd(),
  home = maki.uv.os_homedir(),
  state_base = base,
  config_dir = maki.env.config_dir(),
}

-- Extra deny rules from a private config file next to the maki config,
-- never part of the plugin: protected paths, pinned environment variables,
-- denied flags and denied phrases. A missing file adds nothing.
local extra, guidance = {}, ""
do
  local text = rule_ctx.config_dir and maki.fs.read(rule_ctx.config_dir .. "/lancet-guard.yaml")
  if text then
    local decoded, yerr = maki.yaml.decode(text)
    if type(decoded) ~= "table" then
      maki.log.warn("lancet_guard: could not parse " .. rule_ctx.config_dir .. "/lancet-guard.yaml: " .. tostring(yerr))
    else
      extra = decoded
      if type(decoded.pinned_env) == "table" then
        for _, pin in pairs(decoded.pinned_env) do
          if type(pin) == "table" and type(pin.value) == "string" then
            pin.value = normalize_tilde(pin.value, rule_ctx.home)
          end
        end
      end
      if type(decoded.guidance) == "string" then
        guidance = decoded.guidance
      end
    end
  end
end

local function bash_ctx()
  local env_values = {}
  if type(extra.pinned_env) == "table" then
    for var in pairs(extra.pinned_env) do
      env_values[var] = maki.uv.os_getenv(var)
    end
  end
  return {
    cwd = rule_ctx.cwd,
    home = rule_ctx.home,
    state_base = rule_ctx.state_base,
    config_dir = rule_ctx.config_dir,
    extra = extra,
    env_values = env_values,
  }
end

local enabled
local counts = {
  denied = 0, rule_asks = 0, allowed = 0, classified = 0,
  score_asks = 0, passed = 0, unscored = 0,
}

local function load_state()
  local text = maki.fs.read(paths.state)
  if text then
    local decoded = maki.json.decode(text)
    if type(decoded) == "table" then
      return decoded.enabled ~= false
    end
  end
  return true
end

local function save_state()
  local encoded, err = maki.json.encode({ enabled = enabled })
  if not encoded then
    return nil, err
  end
  return maki.fs.atomic_write(paths.state, encoded)
end

local wrote_state_files = pcall(function()
  maki.fs.mkdir(base, { parents = true })
  maki.fs.write(paths.bridge, bridge_src)
  maki.fs.write(paths.install, string.format(
    INSTALL_SH_FMT,
    LANCET_VERSION, BUNDLE_DIRNAME, DOWNLOAD_URL, SUMS_URL,
    BUNDLE_DIRNAME, BUNDLE_DIRNAME, BUNDLE_DIRNAME
  ))
end)
if not wrote_state_files then
  maki.log.warn("lancet_guard: could not write " .. base .. "; install.sh may be missing")
end
enabled = load_state()

local function deny_message(reason)
  local msg = DENY_PREFIX .. reason .. DENY_SUFFIX
  if guidance ~= "" then
    msg = msg .. "\n\n" .. guidance
  end
  return msg
end

maki.api.set_slot("tool.bash.input", function(prev, input, ctx)
  if not enabled or type(input) ~= "table" or type(input.command) ~= "string" then
    return prev(input, ctx)
  end
  local v = rules.verdict(input.command, bash_ctx())
  if v.verdict == rules.DENY then
    counts.denied = counts.denied + 1
    return nil, deny_message(v.reason)
  end
  if v.verdict == rules.ASK then
    counts.rule_asks = counts.rule_asks + 1
    return nil, { ask = ASK_PREFIX .. v.reason }
  end
  if v.verdict == rules.ALLOW then
    counts.allowed = counts.allowed + 1
    return prev(input, ctx)
  end

  counts.classified = counts.classified + 1
  if #input.command > MAX_COMMAND_BYTES then
    counts.unscored = counts.unscored + 1
    return nil, { ask = LONG_COMMAND_ASK }
  end
  local score, err
  local ok, aerr = pcall(function()
    local up, derr = daemon.ensure(paths, opts.start_timeout_ms)
    if not up then
      err = derr
      return
    end
    score, err = client.score(paths.socket, input.command, maki.uv.cwd(), opts.timeout_ms)
  end)
  if not ok then
    err = aerr
  end
  if not score then
    counts.unscored = counts.unscored + 1
    return nil, { ask = string.format(UNSCORED_FMT, tostring(err)) }
  end
  if score >= opts.ask_above then
    counts.score_asks = counts.score_asks + 1
    return nil, { ask = string.format(SCORE_ASK_FMT, score) }
  end
  counts.passed = counts.passed + 1
  return prev(input, ctx)
end)

-- File tools get rules-only verdicts: LANCET reads command lines, not
-- paths. write and edit judge the target path; read and grep ask only for
-- credential files, whose content would land in the transcript.
--
-- A first out-of-tree write asks; once the write actually ran, the path is
-- owned for its session and later writes and edits to it are free. A
-- denied write never runs, so it never owns anything. Files created by
-- bash commands are not tracked.
local owned = {}

local function owned_set(ctx)
  local sid = ctx.session_id or ""
  if not owned[sid] then
    owned[sid] = {}
  end
  return owned[sid]
end

local function gate_path(verdict_fn)
  return function(prev, input, ctx)
    if not enabled or type(input) ~= "table" or type(input.path) ~= "string" then
      return prev(input, ctx)
    end
    local v = verdict_fn(input.path, rule_ctx, owned_set(ctx))
    if v.verdict == rules.ASK then
      counts.rule_asks = counts.rule_asks + 1
      return nil, { ask = ASK_PREFIX .. v.reason }
    end
    return prev(input, ctx)
  end
end

maki.api.set_slot("tool.write.input", gate_path(rules.write_verdict))
maki.api.set_slot("tool.edit.input", gate_path(rules.write_verdict))
maki.api.set_slot("tool.read.input", gate_path(rules.read_verdict))
maki.api.set_slot("tool.grep.input", gate_path(rules.read_verdict))

local function record_owned(prev, out, ctx)
  if not out.is_error and type(ctx.input) == "table" and type(ctx.input.path) == "string" then
    owned_set(ctx)[rules.owned_key(ctx.input.path, rule_ctx)] = true
  end
  return prev(out, ctx)
end

maki.api.set_slot("tool.write.output", record_owned)
maki.api.set_slot("tool.edit.output", record_owned)

-- A protected path from the private config denies any tool call whose
-- input mentions it, whatever the tool is. The pattern is matched both
-- raw and with JSON-escaped slashes. Three calls are exempt: edits to the
-- rule file itself (its content names the paths), and the batch and task
-- wrappers, whose sub-calls and prompts are checked one by one as their
-- own calls.
local BLOB_EXEMPT_TOOLS = { batch = true, task = true }

local function mentions_protected(blob)
  for _, pat in ipairs(type(extra.protected_paths) == "table" and extra.protected_paths or {}) do
    if type(pat) == "string" and pat ~= "" then
      if blob:find(pat, 1, true) or blob:find(pat:gsub("/", "\\/"), 1, true) then
        return pat
      end
    end
  end
  return nil
end

maki.api.set_slot("tool.*.input", function(prev, input, ctx)
  if enabled and type(extra.protected_paths) == "table" and not BLOB_EXEMPT_TOOLS[ctx.tool] then
    local is_rule_file = type(input) == "table"
      and rule_ctx.config_dir
      and input.path == rule_ctx.config_dir .. "/lancet-guard.yaml"
    if not is_rule_file then
      local blob = maki.json.encode(input) or ""
      local pat = mentions_protected(blob)
      if pat then
        counts.denied = counts.denied + 1
        return nil, deny_message(string.format(PROTECTED_FMT, pat))
      end
    end
  end
  return prev(input, ctx)
end)

local function status_line()
  local install = paths.ready()
    and "installed"
    or "not installed (sh " .. paths.install .. ")"
  local daemon_state = daemon.alive(paths.socket) and "daemon up" or "daemon down"
  return string.format(
    "lancet-guard: %s | %s | %s | %d denied, %d asked, %d classified, %d scored-ask, %d passed",
    enabled and "on" or "off",
    install,
    daemon_state,
    counts.denied,
    counts.rule_asks + counts.score_asks + counts.unscored,
    counts.classified,
    counts.score_asks,
    counts.passed
  )
end

maki.api.register_command({
  name = "/lancet-guard",
  description = "LANCET bash guard: on, off, or status",
  nargs = "?",
  handler = function(copts)
    local arg = (copts.fargs or {})[1]
    if arg == "on" or arg == "off" then
      enabled = arg == "on"
      local ok, err = save_state()
      if not ok then
        maki.log.error("lancet_guard: could not save state: " .. tostring(err))
      end
      maki.ui.flash("lancet-guard: " .. arg)
    else
      maki.ui.flash(status_line())
      maki.log.info(status_line())
    end
  end,
})

local function checks()
  local c = {}
  local function fail(fmt, ...)
    error(string.format(fmt, ...))
  end
  function c.eq(actual, expected, msg)
    if actual ~= expected then
      fail("%s\nexpected: %s\n  actual: %s", msg or "", tostring(expected), tostring(actual))
    end
  end
  function c.is(actual, expected, msg)
    if actual ~= expected then
      fail("%s\nexpected: %s\n  actual: %s", msg or "", tostring(expected), tostring(actual))
    end
  end
  function c.has(s, substr, msg)
    if type(s) ~= "string" or not s:find(substr, 1, true) then
      fail("%s\nexpected to contain: %s\n  actual: %s", msg or "", tostring(substr), tostring(s))
    end
  end
  return c
end

maki.api.register_command({
  name = "/lancet-guard-spec",
  description = "Run the lancet_guard spec cases",
  handler = function()
    maki.async.spawn(function()
      local passed, failed = 0, {}
      for _, mod in ipairs({ "lancet_rules_spec", "lancet_client_spec" }) do
        local ok, spec = pcall(require, mod)
        if not ok then
          failed[#failed + 1] = mod .. ": module failed to load: " .. tostring(spec)
        else
          local names = {}
          for n in pairs(spec.cases) do
            names[#names + 1] = n
          end
          table.sort(names)
          for _, n in ipairs(names) do
            local ok2, err = pcall(spec.cases[n], checks())
            if ok2 then
              passed = passed + 1
            else
              failed[#failed + 1] = mod .. "." .. n .. ": " .. tostring(err)
            end
          end
        end
      end
      if #failed == 0 then
        maki.ui.flash(string.format("/lancet-guard-spec: %d cases passed", passed))
        maki.log.info(string.format("lancet_guard spec: %d cases passed", passed))
        return
      end
      maki.ui.flash(string.format("/lancet-guard-spec: %d passed, %d FAILED (see maki.log)", passed, #failed))
      for _, f in ipairs(failed) do
        maki.log.error("lancet_guard spec " .. f)
      end
    end)
  end,
})

maki.log.info("lancet_guard: loaded (" .. (enabled and "on" or "off") .. ")")
