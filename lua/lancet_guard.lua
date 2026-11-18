-- lancet_guard: gates bash tool calls through two local stages, a port of
-- pi-automode-classifier's design with LANCET as its only model:
--   1. rules  deny the catastrophic, ask for what only the user can own,
--      allow routine work, and pass the rest on
--   2. LANCET scores what the rules leave open; a high score asks
-- There is no chat-model stage. A call the guard cannot score asks rather
-- than runs, and the ask survives allow rules and yolo mode.

local rules = require("lancet_rules")
local client = require("lancet_client")
local daemon = require("lancet_daemon")
local bridge_src = require("lancet_bridge_src")

local LANCET_VERSION = "v0.4.3"
local BUNDLE_DIRNAME = "lancet-" .. LANCET_VERSION .. "-nano-cpu-int8"
local RELEASE_BASE = "https://github.com/TannerMidd/LANCET-model/releases/download"
local DOWNLOAD_URL = RELEASE_BASE .. "/" .. LANCET_VERSION .. "/" .. BUNDLE_DIRNAME .. ".zip"
local SUMS_URL = RELEASE_BASE .. "/" .. LANCET_VERSION .. "/SHA256SUMS.txt"
-- The release asset's exact size, for the progress flash.
local ZIP_BYTES = 108521974
local MAX_DOWNLOAD_SECS = 1800
local POLL_MS = 1000
local INSTALL_TIMEOUT_MS = 300000
local STEP_TIMEOUT_MS = 30000

local DENY_PREFIX = "BLOCKED by lancet-guard: "
local DENY_SUFFIX = ". Find a safer path, or ask the user to run it themselves."
local ASK_PREFIX = "lancet-guard: "
local SCORE_ASK_FMT = "LANCET scored this command's risk at %.2f."
local UNSCORED_FMT = "lancet-guard could not score this command (%s)."
local LONG_COMMAND_ASK = "lancet-guard: the command is too long for the classifier."

-- LANCET reads at most this many bytes; past it the answer is always review.
local MAX_COMMAND_BYTES = 8192

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
  log = base .. "/daemon.log",
  state = base .. "/state.json",
  zip = base .. "/" .. BUNDLE_DIRNAME .. ".zip",
  sums = base .. "/SHA256SUMS.txt",
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

pcall(function()
  maki.fs.mkdir(base, { parents = true })
end)
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

local function tail_of(v)
  if type(v) == "table" then
    return table.concat(v, " ")
  end
  return tostring(v or "")
end

local function run_step(argv, step_opts)
  local id, err = maki.fn.jobstart(argv, {
    cwd = step_opts and step_opts.cwd,
    scope = "task",
    stdout = false,
    stderr = false,
  })
  if not id then
    return nil, err
  end
  local res, werr = maki.fn.jobwait(id, (step_opts and step_opts.timeout_ms) or STEP_TIMEOUT_MS)
  if not res then
    return nil, werr
  end
  if res.exit_code ~= 0 then
    return nil, (tail_of(res.stderr) .. " " .. tail_of(res.stdout)):gsub("%s+", " ")
  end
  return true
end

local setup_running = false
local SETUP_RUNNING_ERR = "setup is already running"

-- The model download runs with an on_exit flag and a size-polling loop, so
-- the flash shows progress and a slow network is not cut off by a wait
-- timeout.
local function run_download()
  local finished, exit_code = false, nil
  local id, err = maki.fn.jobstart({ "curl", "-fL", "-o", paths.zip, DOWNLOAD_URL }, {
    scope = "task",
    stdout = false,
    stderr = false,
    on_exit = function(_, code)
      finished, exit_code = true, code
    end,
  })
  if not id then
    return nil, err
  end
  for _ = 1, MAX_DOWNLOAD_SECS do
    if finished then
      break
    end
    maki.async.sleep(POLL_MS)
    local meta = maki.fs.metadata(paths.zip)
    maki.ui.flash(string.format(
      "lancet-guard: downloading the model, %.0f of %.0f MB",
      (meta and meta.size or 0) / 1048576,
      ZIP_BYTES / 1048576
    ))
  end
  if not finished then
    maki.fn.jobstop(id)
    return nil, "the download did not finish in " .. MAX_DOWNLOAD_SECS .. " seconds"
  end
  if exit_code ~= 0 then
    return nil, "curl exited with code " .. tostring(exit_code)
  end
  return true
end

local function setup_inner()
  local ok, err = maki.fs.mkdir(base, { parents = true })
  if not ok then
    return nil, err
  end
  local wok, werr = maki.fs.write(paths.bridge, bridge_src)
  if not wok then
    return nil, werr
  end
  local ok2, err2 = run_download()
  if not ok2 then
    return nil, "could not download the model: " .. err2
  end
  local steps = {
    { { "curl", "-fL", "-o", paths.sums, SUMS_URL },
      "download the checksums", STEP_TIMEOUT_MS },
    { "shasum -a 256 -c SHA256SUMS.txt || sha256sum -c SHA256SUMS.txt",
      "verify the checksums", STEP_TIMEOUT_MS, base },
    { { "unzip", "-o", paths.zip, "-d", base }, "unpack the bundle", STEP_TIMEOUT_MS },
    { { "uv", "venv", paths.venv }, "create the venv", INSTALL_TIMEOUT_MS },
    { { "uv", "pip", "install", "--python", paths.python, "-r", paths.bundle .. "/requirements.txt" },
      "install the dependencies", INSTALL_TIMEOUT_MS },
  }
  for _, step in ipairs(steps) do
    local argv, what, timeout_ms, cwd = step[1], step[2], step[3], step[4]
    maki.ui.flash("lancet-guard: " .. what)
    local ok3, err3 = run_step(argv, { timeout_ms = timeout_ms, cwd = cwd })
    if not ok3 then
      return nil, "could not " .. what .. ": " .. err3
    end
  end
  maki.fs.rm(paths.zip, { force = true })
  if not paths.ready() then
    return nil, "the install finished but the bundle looks incomplete"
  end
  return true
end

local function setup()
  if setup_running then
    return nil, SETUP_RUNNING_ERR
  end
  setup_running = true
  local ok, err = setup_inner()
  setup_running = false
  return ok, err
end

local function status_line()
  local install = paths.ready() and "installed" or "not installed (/lancet-guard setup)"
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
  description = "LANCET bash guard: setup, on, off, or status",
  nargs = "?",
  handler = function(copts)
    local arg = (copts.fargs or {})[1]
    if arg == "setup" then
      maki.async.spawn(function()
        local ok, err = setup()
        if ok then
          maki.ui.flash("lancet-guard: " .. LANCET_VERSION .. " installed")
        else
          maki.ui.flash("lancet-guard setup failed: " .. tostring(err):sub(1, 140))
          maki.log.error("lancet_guard setup: " .. tostring(err))
        end
      end)
    elseif arg == "on" or arg == "off" then
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
