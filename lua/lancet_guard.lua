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

-- LANCET reads at most this many bytes; past it the answer is always review.
local MAX_COMMAND_BYTES = 8192

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

maki.api.set_slot("tool.bash.input", function(prev, input, ctx)
  if not enabled or type(input) ~= "table" or type(input.command) ~= "string" then
    return prev(input, ctx)
  end
  local v = rules.verdict(input.command, rule_ctx)
  if v.verdict == rules.DENY then
    counts.denied = counts.denied + 1
    return nil, DENY_PREFIX .. v.reason .. DENY_SUFFIX
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
