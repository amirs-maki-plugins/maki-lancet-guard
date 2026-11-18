-- lancet_client_spec: protocol cases for the socket client, driven against
-- a fake bridge built with maki.net.listen_unix. No real LANCET bundle and
-- no onnxruntime are involved.

local client = require("lancet_client")

local SOCKET = (maki.env.state_dir() or "/tmp") .. "/lancet-guard-spec.sock"

maki.fs.rm(SOCKET, { force = true })

-- A listener that answers every request with `reply` (a table), or, when
-- reply is nil, consumes the request and stays silent to force a client
-- timeout.
local function start_fake(reply)
  local listener = maki.net.listen_unix(SOCKET)
  if not listener then
    error("spec could not listen on " .. SOCKET)
  end
  maki.async.spawn(function()
    while true do
      local conn = listener:accept()
      if not conn then
        return
      end
      if reply then
        local data = conn:read()
        if data then
          conn:write(maki.json.encode(reply) .. "\n")
        end
        conn:close()
      else
        conn:read()
      end
    end
  end)
  return listener
end

local cases = {}

cases.score_roundtrip = function(check)
  local listener = start_fake({ score = 0.05, label = "not_flagged" })
  local score, err = client.score(SOCKET, "cargo test", "/proj", 2000)
  listener:close()
  check.is(score, 0.05)
  check.eq(err, nil)
end

cases.risky_score_roundtrip = function(check)
  local listener = start_fake({ score = 0.97, label = "risky" })
  local score = client.score(SOCKET, "kubectl delete ns prod", "/proj", 2000)
  listener:close()
  check.is(score, 0.97)
end

cases.error_reply_fails = function(check)
  local listener = start_fake({ error = "classifier process exited" })
  local score, err = client.score(SOCKET, "ls", "/proj", 2000)
  listener:close()
  check.eq(score, nil)
  check.has(err, "classifier process exited")
end

cases.reply_without_score_fails = function(check)
  local listener = start_fake({ label = "not_flagged" })
  local score, err = client.score(SOCKET, "ls", "/proj", 2000)
  listener:close()
  check.eq(score, nil)
  check.eq(err, client.NO_SCORE_ERR)
end

cases.garbage_reply_fails = function(check)
  local listener = start_fake("not a table")
  local score, err = client.score(SOCKET, "ls", "/proj", 2000)
  listener:close()
  check.eq(score, nil)
  check.is(err ~= nil, true)
end

cases.silent_daemon_times_out = function(check)
  local listener = start_fake(nil)
  local score, err = client.score(SOCKET, "ls", "/proj", 200)
  listener:close()
  check.eq(score, nil)
  check.eq(err, client.TIMEOUT_ERR)
end

cases.dead_socket_fails = function(check)
  local score, err = client.score(SOCKET, "ls", "/proj", 200)
  check.eq(score, nil)
  check.is(err ~= nil, true)
end

return { name = "lancet_client", cases = cases }
