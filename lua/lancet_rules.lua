-- lancet_rules: stage-1 verdicts for the lancet_guard plugin, a stateless
-- port of pi-automode-classifier's rules for bash commands. Every segment
-- of a command line is judged on its own and the worst verdict wins:
--   deny      catastrophic, blocked with no prompt
--   ask       only the user can approve
--   allow     routine work, maki's own permission flow still applies
--   classify  LANCET scores it (stage 2)

local M = {}

M.DENY, M.ASK, M.ALLOW, M.CLASSIFY = "deny", "ask", "allow", "classify"

local SEVERITY = { deny = 3, ask = 2, classify = 1, allow = 0 }

-- Reasons are shared consts so the specs assert against them.
M.R = {
  fork_bomb = "the command is a fork bomb",
  mkfs = "the command formats a disk",
  dd_disk = "the command writes to a raw disk device",
  rm_system = "the command deletes a system directory",
  root = "the command runs as root",
  publish = "the command publishes work others can see, or discards work",
  net_send = "the command sends data to a remote machine",
  pipe_shell = "the command pipes a download into a shell",
  credential = "the command reads a credential file",
  outside = "the command changes files outside the working directory",
  system_change = "the command changes installed software or system services",
  maki_own = "the command touches maki's own configuration or this guard's state",
  beyond = "the command reaches beyond this project",
  context = "the file changes what later sessions do",
  important = "the file lives in a system or configuration directory",
}

-- rm -rf of these (the directory itself, or anything below them) is a hard
-- deny. ~ and $HOME count only as themselves: a delete below them is an
-- outside-working-directory ask, not a deny.
local SYSTEM_DIRS = {
  "/etc", "/usr", "/bin", "/sbin", "/var", "/boot", "/dev", "/System",
  "/Library", "/Applications",
}

-- Wrappers stripped before the program is read. sudo, doas and pkexec
-- escalate, so seeing one is an ask on its own.
local ROOT_WRAPPERS = { sudo = true, doas = true, pkexec = true }
local PLAIN_WRAPPERS = { nohup = true, command = true, env = true, timeout = true, nice = true }

local ASK_PROGRAMS = {
  su = true, ssh = true, scp = true, sftp = true, telnet = true, ftp = true,
  nc = true, ncat = true, netcat = true, osascript = true, chflags = true,
}

-- program + subword pairs that publish or push work others can see.
local ASK_SUBWORDS = {
  git = { push = true },
  gh = { pr = true, release = true },
  npm = { publish = true },
  cargo = { publish = true },
  docker = { push = true },
  podman = { push = true },
  helm = { push = true },
}

local PACKAGE_MANAGERS = {
  apt = true, ["apt-get"] = true, dnf = true, yum = true, pacman = true,
  port = true, systemctl = true, launchctl = true, service = true,
  softwareupdate = true, mas = true,
}
local BREW_MUTATIONS = {
  install = true, uninstall = true, remove = true, purge = true, erase = true,
  delete = true, upgrade = true, reinstall = true, autoremove = true,
  cleanup = true,
}

-- curl and wget flags that put data on the wire.
local NET_DATA_FLAGS = {
  ["-d"] = true, ["--data"] = true, ["--data-raw"] = true, ["--data-binary"] = true,
  ["--data-urlencode"] = true, ["-F"] = true, ["--form"] = true, ["-T"] = true,
  ["--upload-file"] = true, ["--json"] = true, ["--post-data"] = true,
  ["--post-file"] = true,
}

local DOWNLOADERS = { curl = true, wget = true }
local SHELLS = { sh = true, bash = true, zsh = true, dash = true }

-- Programs that change files. They ask when a target sits outside the
-- working directory.
local MUTATING = {
  rm = true, mv = true, rmdir = true, shred = true, truncate = true, tee = true,
  cp = true, ln = true, install = true,
}

-- Read-only and build tools. Anything not listed classifies.
local ALLOW_PROGRAMS = {
  ls = true, cat = true, pwd = true, echo = true, printf = true, grep = true,
  rg = true, find = true, fd = true, head = true, tail = true, wc = true,
  stat = true, file = true, which = true, type = true, du = true, df = true,
  ps = true, uname = true, whoami = true, date = true, id = true, env = true,
  printenv = true, diff = true, cmp = true, tree = true, shasum = true,
  md5sum = true, sha256sum = true, awk = true, sed = true, jq = true, yq = true,
  column = true, sort = true, uniq = true, cut = true, tr = true, xargs = true,
  less = true, more = true, bat = true, basename = true, dirname = true,
  cargo = true, make = true, just = true, npm = true, pnpm = true, yarn = true,
  go = true, rustc = true, uv = true, nix = true, tsc = true, pytest = true,
  eslint = true, prettier = true, ruff = true, black = true, rsync = true,
  touch = true, mkdir = true, cp = true, ln = true, chmod = true, chown = true,
  install = true, rm = true, mv = true, rmdir = true, tee = true, brew = true,
}

-- Local git work runs freely; push and reset --hard are caught above.
local ALLOW_GIT_SUBWORDS = {
  add = true, commit = true, checkout = true, switch = true, restore = true,
  stash = true, merge = true, rebase = true, ["cherry-pick"] = true,
  branch = true, tag = true, init = true, clone = true, fetch = true,
  pull = true, status = true, diff = true, log = true, show = true,
  blame = true, describe = true, ["rev-parse"] = true, ["ls-files"] = true,
}

-- A word anywhere in an allow verdict demotes it to classify, because the
-- name says the command reaches further than the working directory.
local RISKY_WORDS = {
  deploy = true, publish = true, release = true, upload = true,
  prod = true, production = true,
}

-- Credentials, as suffixes of the home directory (the file itself, or
-- anything below the directory ones) or absolute system paths.
local CRED_HOME_PATHS = {
  ".ssh", ".aws", ".gnupg", ".kube", ".azure", ".oci", ".config/gcloud",
  ".docker/config.json", ".netrc", ".npmrc", ".pypirc", ".git-credentials",
}
local CRED_SYSTEM_PATHS = { "/etc/shadow", "/etc/master.passwd" }
-- Matched against the basename.
local CRED_BASENAMES = {
  "^%.env$", "^id_rsa", "^id_ed25519", "^id_ecdsa", "^id_dsa", "%.pem$",
  "%.key$", "%.p12$", "%.jks$", "%.kdbx$", "^secrets%.ya?ml$",
  "^credentials%.json$", "serviceaccount.+%.json$",
}

-- .env.production holds secrets; .env.example and friends hold placeholders.
local NON_SECRET_ENV_SUFFIXES = {
  example = true, sample = true, template = true, dist = true, defaults = true,
}

-- Naming a credential file is fine; only reading it asks.
local NAME_ONLY = {
  ls = true, stat = true, test = true, ["["] = true, chmod = true, chown = true,
  echo = true, printf = true, mkdir = true, touch = true, find = true,
  file = true, basename = true, dirname = true,
}

-- Redirect targets that never leave a mark worth asking about.
local HARMLESS_REDIRECTS = {
  ["/dev/null"] = true, ["/dev/stdout"] = true, ["/dev/stderr"] = true,
}

local REDIRECT_PATTERN = ">>?%s*([\"']?)([%w%./~$%%-]+)%1"

local function words_of(segment)
  local out = {}
  for w in segment:gmatch("%S+") do
    out[#out + 1] = w
  end
  return out
end

local function basename(word)
  return word and word:match("([^/\\]+)$") or word
end

local function strip_quotes(s)
  return (s:gsub("^[\"']", ""):gsub("[\"']$", ""))
end

local function normalize_path(p, home)
  if p:sub(1, 2) == "~/" then
    return home .. p:sub(2)
  elseif p == "~" then
    return home
  elseif p:sub(1, 6) == "$HOME/" then
    return home .. p:sub(6)
  elseif p == "$HOME" then
    return home
  end
  return p
end

local function under_dir(path, dir)
  if path == dir then
    return true
  end
  return path:sub(1, #dir + 1) == dir .. "/"
end

-- True when a path argument leaves the working directory. Relative paths
-- stay inside; /tmp is public scratch space and allowed like upstream.
local function path_outside(p, cwd, home)
  p = normalize_path(p, home)
  if p:sub(1, 1) ~= "/" then
    return p:sub(1, 2) == ".."
  end
  if under_dir(p, cwd) then
    return false
  end
  if under_dir(p, "/tmp") or under_dir(p, "/private/tmp") then
    return false
  end
  return not HARMLESS_REDIRECTS[p]
end

local function cred_basename_match(name)
  for _, pat in ipairs(CRED_BASENAMES) do
    if name:match(pat) then
      return true
    end
  end
  local env_suffix = name:match("^%.env%.(%w+)$")
  if env_suffix then
    return not NON_SECRET_ENV_SUFFIXES[env_suffix:lower()]
  end
  return false
end

-- Public keys, certificates, known_hosts and the .ssh/.aws config files are
-- not secrets, even though they live next to ones.
local function cred_exempt(p, home)
  local name = basename(p) or ""
  if name:match("%.pub$") or name:match("%.crt$") or name:match("%.cer$") then
    return true
  end
  if name == "known_hosts" or name == "config" then
    local np = normalize_path(p, home)
    return under_dir(np, home .. "/.ssh") or under_dir(np, home .. "/.aws")
  end
  return false
end

-- The path itself is a credential, or sits in a credential directory.
local function credential_target(p, home)
  if cred_exempt(p, home) then
    return false
  end
  local np = normalize_path(p, home)
  for _, cred in ipairs(CRED_HOME_PATHS) do
    if under_dir(np, home .. "/" .. cred) then
      return true
    end
  end
  for _, cred in ipairs(CRED_SYSTEM_PATHS) do
    if np == cred then
      return true
    end
  end
  local name = basename(np)
  return name ~= nil and cred_basename_match(name)
end

-- Instruction and project-config files that change what every later
-- session does, in any directory.
local CONTEXT_BASENAMES = {
  ["AGENTS.md"] = true, ["AGENTS.local.md"] = true, ["CLAUDE.md"] = true,
}

local function context_target(p)
  if CONTEXT_BASENAMES[basename(p) or ""] then
    return true
  end
  return p == ".maki" or p:find("^%.maki/") ~= nil or p:find("/%.maki/") ~= nil
    or p:find("/%.maki$") ~= nil
end

local function maki_own_target(p, ctx)
  local np = normalize_path(p, ctx.home)
  return (ctx.state_base and under_dir(np, ctx.state_base))
    or (ctx.config_dir and under_dir(np, ctx.config_dir)) or false
end

-- Directories whose files matter beyond one project: system trees, and
-- configuration under the home directory. Writes there always ask.
local IMPORTANT_SYSTEM_DIRS = {
  "/etc", "/usr", "/bin", "/sbin", "/var", "/boot", "/System", "/Library",
  "/Applications", "/private/etc", "/private/var",
}
local IMPORTANT_HOME_AREAS = { "Library", ".config" }

local function important_target(p, ctx)
  local np = normalize_path(p, ctx.home)
  for _, dir in ipairs(IMPORTANT_SYSTEM_DIRS) do
    if under_dir(np, dir) then
      return true
    end
  end
  if under_dir(np, ctx.home) then
    local parent = np:match("^(.*)/[^/]+$")
    local name = basename(np) or ""
    if parent == ctx.home and (name:sub(1, 1) == "." or IMPORTANT_HOME_AREAS[name]) then
      return true
    end
    for _, area in ipairs(IMPORTANT_HOME_AREAS) do
      if under_dir(np, ctx.home .. "/" .. area) then
        return true
      end
    end
  end
  return false
end

-- A credential path appears as an argument. For cp, mv, install and rsync
-- only the source arguments count: writing or copying over a credential
-- file does not put its content in the transcript.
local function reads_credential(args, prog, home)
  local last = #args
  if prog == "cp" or prog == "mv" or prog == "install" or prog == "rsync" then
    last = last - 1
  end
  for i = 1, last do
    local p = strip_quotes(args[i])
    if p:sub(1, 1) ~= "-" and credential_target(p, home) then
      return true
    end
  end
  return false
end

local function has_flag(args, flags)
  for _, a in ipairs(args) do
    if flags[a] then
      return true
    end
  end
  return false
end

-- curl and wget spell data flags with an = value, as in --post-data=x.
local function has_data_flag(args)
  for _, a in ipairs(args) do
    for flag in pairs(NET_DATA_FLAGS) do
      if a == flag or a:sub(1, #flag + 1) == flag .. "=" then
        return true
      end
    end
  end
  return false
end

local function has_risky_word(prog, args)
  for _, w in ipairs({ prog, table.unpack(args) }) do
    for token in tostring(w):gmatch("[%w_%-]+") do
      if RISKY_WORDS[token:gsub("^%-+", ""):lower()] then
        return true
      end
    end
  end
  return false
end

-- Strip leading wrapper words. Returns the program word, the argument
-- words, and whether a root wrapper was seen. `env VAR=x cmd` and
-- `timeout 10 cmd` drop their own leading options and assignments.
local function unwrap(segment)
  local rest = segment
  local saw_root = false
  for _ = 1, 16 do
    rest = rest:match("^%s*(.-)%s*$")
    local first = rest:match("^(%S+)")
    if not first then
      return nil, nil, saw_root
    end
    local base = basename(strip_quotes(first))
    if ROOT_WRAPPERS[base] then
      saw_root = true
      rest = rest:sub(#first + 1)
    elseif PLAIN_WRAPPERS[base] then
      rest = rest:sub(#first + 1)
      if base == "env" then
        rest = rest:gsub("^%s*[%w_]+=%S*%s*", "")
      elseif base == "timeout" then
        rest = rest:gsub("^%s*%-%S*%s*", ""):gsub("^%s*[%d%.]+%s*", "")
      end
    else
      break
    end
  end
  local w = words_of(rest)
  return w[1], w, saw_root
end

local function worse(a, b)
  if not a then
    return b
  end
  if not b then
    return a
  end
  return SEVERITY[b.verdict] > SEVERITY[a.verdict] and b or a
end

-- An rsync argument is remote when its colon comes before any slash, as in
-- host:path but not ./a:b or /a:b.
local function remote_spec(a)
  local colon = a:find(":")
  if not colon then
    return false
  end
  local slash = a:find("/")
  return slash == nil or slash > colon
end

-- Extra rules from the user's private config file. They are denies, so no
-- model and no later rule can let them through.
--
-- ctx.extra = {
--   deny_substrings = { "phrase", ... },
--   deny_flags = { "--flag", ... },
--   pinned_env = { VAR = { value = "expanded expected value", programs = { "prog" } } },
-- }
-- ctx.env_values = { VAR = current value from the environment }

local ASSIGNERS = {
  env = true, export = true, declare = true, typeset = true,
  ["local"] = true, readonly = true,
}

-- A pinned variable is assigned inline: a leading VAR=val of a command, or
-- an argument of env/export/declare/... Text inside echo or grep arguments
-- is fine, because those never set anything.
local function assigns_var(segment, var)
  for part in (segment .. "\n"):gmatch("([^(){}%c]*)") do
    local first_cmd = nil
    for wordtok in part:gmatch("%S+") do
      local word = wordtok:gsub("^[\"']", "")
      local prefix = var .. "="
      if first_cmd == nil then
        if word:sub(1, #prefix) == prefix then
          return true
        elseif not word:match("^[%a_][%w_]*=") then
          first_cmd = word
          if not ASSIGNERS[word] then
            break
          end
        end
      elseif word:sub(1, #prefix) == prefix then
        return true
      end
    end
  end
  return false
end

local function extra_denial(segment, prog, args, ctx)
  local extra = ctx.extra
  if not extra then
    return nil
  end
  if extra.pinned_env then
    for var, pin in pairs(extra.pinned_env) do
      if type(pin) == "table" and type(pin.value) == "string" then
        if assigns_var(segment, var) then
          return "the command sets " .. var .. " inline"
        end
        for _, p in ipairs(pin.programs or {}) do
          if p == prog and ctx.env_values and ctx.env_values[var] ~= pin.value then
            return "maki was not started with " .. var .. "=" .. pin.value
          end
        end
      end
    end
  end
  if extra.deny_flags then
    for _, flag in ipairs(extra.deny_flags) do
      for _, a in ipairs(args) do
        if a == flag or a:sub(1, #flag + 1) == flag .. "=" then
          return "the command passes " .. flag
        end
      end
    end
  end
  if extra.deny_substrings then
    local lower = segment:lower()
    for _, pat in ipairs(extra.deny_substrings) do
      if lower:find(tostring(pat):lower(), 1, true) then
        return "the command matches a denied pattern"
      end
    end
  end
  return nil
end

local function judge_segment(segment, ctx)
  local first, w, saw_root = unwrap(segment)
  if not first then
    return { verdict = M.ALLOW }
  end
  local prog = basename(strip_quotes(first))
  local args = {}
  for i = 2, #w do
    args[#args + 1] = w[i]
  end

  local extra_why = extra_denial(segment, prog, args, ctx)
  if extra_why then
    return { verdict = M.DENY, reason = extra_why }
  end

  if prog:match("^mkfs") then
    return { verdict = M.DENY, reason = M.R.mkfs }
  end
  if prog == "dd" then
    for _, a in ipairs(args) do
      if a:match("^of=/dev/") then
        return { verdict = M.DENY, reason = M.R.dd_disk }
      end
    end
  end
  if prog == "rm" and has_flag(args, {
    ["-r"] = true, ["-rf"] = true, ["-fr"] = true, ["-R"] = true,
    ["-Rf"] = true, ["-fR"] = true, ["--recursive"] = true,
  }) then
    for _, a in ipairs(args) do
      if a:sub(1, 1) ~= "-" then
        local p = normalize_path(strip_quotes(a), ctx.home)
        if p == "/" or p == ctx.home then
          return { verdict = M.DENY, reason = M.R.rm_system }
        end
        for _, dir in ipairs(SYSTEM_DIRS) do
          if under_dir(p, dir) then
            return { verdict = M.DENY, reason = M.R.rm_system }
          end
        end
      end
    end
  end

  if saw_root then
    return { verdict = M.ASK, reason = M.R.root }
  end

  for _, a in ipairs(args) do
    local p = strip_quotes(a)
    if ctx.state_base and under_dir(normalize_path(p, ctx.home), ctx.state_base) then
      return { verdict = M.ASK, reason = M.R.maki_own }
    end
    if ctx.config_dir and under_dir(normalize_path(p, ctx.home), ctx.config_dir) then
      return { verdict = M.ASK, reason = M.R.maki_own }
    end
  end

  if not NAME_ONLY[prog] and reads_credential(args, prog, ctx.home) then
    return { verdict = M.ASK, reason = M.R.credential }
  end

  if ASK_PROGRAMS[prog] then
    return { verdict = M.ASK, reason = M.R.beyond }
  end
  if prog == "rsync" then
    for _, a in ipairs(args) do
      if a:sub(1, 1) ~= "-" and remote_spec(a) then
        return { verdict = M.ASK, reason = M.R.net_send }
      end
    end
  end
  if (prog == "curl" or prog == "wget") and has_data_flag(args) then
    return { verdict = M.ASK, reason = M.R.net_send }
  end

  local sub = ASK_SUBWORDS[prog]
  if sub then
    local subword = basename(strip_quotes(args[1] or ""))
    if subword ~= "" and sub[subword] then
      return { verdict = M.ASK, reason = M.R.publish }
    end
  end
  if prog == "git" then
    local subword = basename(strip_quotes(args[1] or ""))
    if subword == "reset" then
      for _, a in ipairs(args) do
        if a == "--hard" then
          return { verdict = M.ASK, reason = M.R.publish }
        end
      end
    end
  end

  if PACKAGE_MANAGERS[prog] then
    return { verdict = M.ASK, reason = M.R.system_change }
  end
  if prog == "brew" then
    local subword = basename(strip_quotes(args[1] or ""))
    if subword ~= "" and BREW_MUTATIONS[subword] then
      return { verdict = M.ASK, reason = M.R.system_change }
    end
  end

  local mutating = MUTATING[prog]
    or (prog == "sed" and has_flag(args, { ["-i"] = true, ["--in-place"] = true }))
  if mutating then
    for _, a in ipairs(args) do
      if a:sub(1, 1) ~= "-" then
        local p = strip_quotes(a)
        if (p:sub(1, 1) == "/" or p:sub(1, 2) == "~/" or p:sub(1, 3) == "../")
          and path_outside(p, ctx.cwd, ctx.home) then
          return { verdict = M.ASK, reason = M.R.outside }
        end
      end
    end
  end

  -- A redirect writes a file, whatever the program is.
  for _, target in segment:gmatch(REDIRECT_PATTERN) do
    local p = strip_quotes(target)
    if p ~= "" and path_outside(p, ctx.cwd, ctx.home) then
      return { verdict = M.ASK, reason = M.R.outside }
    end
  end

  if prog == "git" then
    local subword = basename(strip_quotes(args[1] or ""))
    if subword ~= "" and ALLOW_GIT_SUBWORDS[subword] and not has_risky_word(prog, args) then
      return { verdict = M.ALLOW }
    end
    return { verdict = M.CLASSIFY }
  end

  if ALLOW_PROGRAMS[prog] and not has_risky_word(prog, args) then
    return { verdict = M.ALLOW }
  end

  return { verdict = M.CLASSIFY }
end

-- Split a command line into segments judged on their own: separators,
-- command substitutions, backticks and `shell -c` strings each contribute.
local function segments_of(cmd, depth, out)
  for raw in cmd:gmatch("[^;\r\n&|]+") do
    local seg = raw:match("^%s*(.-)%s*$") or ""
    if seg ~= "" then
      out[#out + 1] = seg
      if depth < 2 then
        local inner = seg:match("^%S+%s+%-c%s+[\"'](.-)[\"']%s*$")
        if inner then
          segments_of(inner, depth + 1, out)
        end
      end
    end
  end
  if depth < 2 then
    for inner in cmd:gmatch("%$%((.-)%)") do
      segments_of(inner, depth + 1, out)
    end
    for inner in cmd:gmatch("`(.-)`") do
      segments_of(inner, depth + 1, out)
    end
  end
end

-- verdict(cmd, ctx) -> { verdict = "deny"|"ask"|"allow"|"classify", reason = string? }
-- ctx = { cwd = string, home = string, state_base = string?, config_dir = string? }
function M.verdict(cmd, ctx)
  if cmd:find(":|:", 1, true) or cmd:find(":%s*|%s*:") then
    return { verdict = M.DENY, reason = M.R.fork_bomb }
  end
  local segments = {}
  segments_of(cmd, 0, segments)

  local worst
  local downloader, bare_shell = false, false
  for _, seg in ipairs(segments) do
    worst = worse(worst, judge_segment(seg, ctx))
    local first, w = unwrap(seg)
    if first then
      local prog = basename(strip_quotes(first))
      if DOWNLOADERS[prog] then
        downloader = true
      end
      if SHELLS[prog] and #w == 1 then
        bare_shell = true
      end
    end
  end
  if downloader and bare_shell then
    return { verdict = M.ASK, reason = M.R.pipe_shell }
  end
  return worst or { verdict = M.ALLOW }
end

-- owned_key(path, ctx): the set key for a path, home-normalized so ~/x
-- and the spelled-out form are one file.
function M.owned_key(p, ctx)
  return normalize_path(p, ctx.home)
end

-- write_verdict(path, ctx, owned?) -> { verdict = "allow"|"ask", reason = string? }
-- The target of a write or edit. Rules only: LANCET reads command lines,
-- not file paths. `owned` is the caller's set of paths already written
-- this session: a first out-of-tree write asks, and later writes to a file
-- that actually ran are free. Important directories never become owned.
function M.write_verdict(p, ctx, owned)
  if maki_own_target(p, ctx) then
    return { verdict = M.ASK, reason = M.R.maki_own }
  end
  if credential_target(p, ctx.home) then
    return { verdict = M.ASK, reason = M.R.credential }
  end
  if context_target(p) then
    return { verdict = M.ASK, reason = M.R.context }
  end
  if important_target(p, ctx) then
    return { verdict = M.ASK, reason = M.R.important }
  end
  if path_outside(p, ctx.cwd, ctx.home) then
    if owned and owned[M.owned_key(p, ctx)] then
      return { verdict = M.ALLOW }
    end
    return { verdict = M.ASK, reason = M.R.outside }
  end
  return { verdict = M.ALLOW }
end

-- read_verdict(path, ctx) -> { verdict = "allow"|"ask", reason = string? }
-- Reads go anywhere but to a credential file: the content would land in
-- the transcript.
function M.read_verdict(p, ctx)
  if credential_target(p, ctx.home) then
    return { verdict = M.ASK, reason = M.R.credential }
  end
  return { verdict = M.ALLOW }
end

-- Exported for the specs.
M._path_outside = path_outside
M._reads_credential = reads_credential
M._unwrap = unwrap
M._remote_spec = remote_spec
M._credential_target = credential_target
M._context_target = context_target
M._important_target = important_target
M._assigns_var = assigns_var

return M
