-- lancet_daemon: keeps the bridge process alive. The bridge is started
-- detached, so it survives a maki restart and serves every maki process on
-- the machine, and it exits on its own after an idle timeout. Any maki
-- process that finds the socket closed starts a new bridge; the bridge
-- unlinks a stale socket before it binds, so the newest one wins.

local M = {}

local POLL_MS = 100
local PROBE_TIMEOUT_SECS = 2
local START_SCRIPT_FMT = "nohup '%s' '%s' --socket '%s' --classify '%s' --model '%s' >> '%s' 2>&1 &"

M.NOT_INSTALLED_FMT = "lancet is not installed; run sh %s in your terminal"
M.START_ERR_FMT = "the lancet daemon did not start (see %s)"

local function socket_alive(path)
  local conn = maki.net.connect_unix(path, { timeout = PROBE_TIMEOUT_SECS })
  if not conn then
    return false
  end
  conn:close()
  return true
end

-- ensure(paths, start_timeout_ms) -> true? , string?
-- paths = { socket, python, bridge, classify, model, log, install, ready() }
-- Yields while polling for the socket to answer.
function M.ensure(paths, start_timeout_ms)
  if socket_alive(paths.socket) then
    return true
  end
  if not paths.ready() then
    return nil, string.format(M.NOT_INSTALLED_FMT, paths.install)
  end
  local script = string.format(
    START_SCRIPT_FMT,
    paths.python, paths.bridge, paths.socket, paths.classify, paths.model, paths.log
  )
  local id, err = maki.fn.jobstart(script, { scope = "task", stdout = false, stderr = false })
  if not id then
    return nil, err
  end
  local polls = math.max(1, math.floor(start_timeout_ms / POLL_MS))
  for _ = 1, polls do
    maki.async.sleep(POLL_MS)
    if socket_alive(paths.socket) then
      return true
    end
  end
  return nil, string.format(M.START_ERR_FMT, paths.log)
end

-- alive(socket) -> boolean, for /lancet-guard status.
function M.alive(socket)
  return socket_alive(socket)
end

return M
