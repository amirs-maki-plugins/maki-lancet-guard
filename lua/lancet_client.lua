-- lancet_client: one request to the lancet bridge daemon over its unix
-- socket. A request is a JSON line; the reply is the classifier's JSON
-- line. Any failure answers nil plus an error, and the caller turns that
-- into an ask, never into an allow.

local M = {}

local CONNECT_TIMEOUT_SECS = 5
local MAX_REPLY_BYTES = 65536

M.TIMEOUT_ERR = "the lancet daemon did not answer in time"
M.CLOSED_ERR = "the lancet daemon closed the connection"
M.OVERSIZED_ERR = "the lancet daemon reply is too large"
M.NO_SCORE_ERR = "the lancet daemon reply has no score"

-- score(socket_path, command, cwd, timeout_ms) -> number? , string?
-- Yields: the connection reads and writes are awaited.
function M.score(socket_path, command, cwd, timeout_ms)
  local conn, err = maki.net.connect_unix(socket_path, { timeout = CONNECT_TIMEOUT_SECS })
  if not conn then
    return nil, err
  end
  local reply, rerr = M.roundtrip(conn, command, cwd, timeout_ms)
  conn:close()
  return reply, rerr
end

-- roundtrip(conn, command, cwd, timeout_ms) -> number? , string?
-- Split out so the specs can drive it with a listener of their own; the
-- caller owns closing the connection.
function M.roundtrip(conn, command, cwd, timeout_ms)
  local req, jerr = maki.json.encode({ command = command, shell = "bash", cwd = cwd })
  if not req then
    return nil, jerr
  end
  local timed_out = false
  maki.async.spawn(function()
    maki.async.sleep(timeout_ms)
    timed_out = true
    conn:close()
  end)
  local ok, werr = conn:write(req .. "\n")
  if not ok then
    return nil, timed_out and M.TIMEOUT_ERR or werr
  end
  local data = ""
  while not data:find("\n", 1, true) do
    local chunk, cerr = conn:read()
    if not chunk then
      return nil, timed_out and M.TIMEOUT_ERR or (cerr or M.CLOSED_ERR)
    end
    data = data .. chunk
    if #data > MAX_REPLY_BYTES then
      return nil, M.OVERSIZED_ERR
    end
  end
  local line = data:match("^(.-)\n")
  local decoded, derr = maki.json.decode(line)
  if type(decoded) ~= "table" then
    return nil, derr or M.NO_SCORE_ERR
  end
  if decoded.error then
    return nil, tostring(decoded.error)
  end
  if type(decoded.score) ~= "number" then
    return nil, M.NO_SCORE_ERR
  end
  return decoded.score
end

return M
