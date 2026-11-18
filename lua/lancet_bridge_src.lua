-- lancet_bridge_src: the Python source of the bridge daemon, embedded so
-- the plugin is one self-contained unit in every load mode. /lancet-guard
-- setup writes it to <state>/lancet-guard/bridge.py next to the venv and
-- the model bundle, and the daemon runs it from there.

return [==[
#!/usr/bin/env python3
"""Serve LANCET classify.py over a unix socket, one request per connection.

Request:  one JSON line, e.g. {"command": "ls", "shell": "bash", "cwd": "/x"}
Reply:    classify.py's JSON line, or {"error": "..."}.

The classifier process is started once and kept alive, restarted when it
exits. The daemon exits after IDLE_SECS without a request, so it does not
sit in memory when nothing classifies commands.
"""
import argparse
import json
import os
import socket
import subprocess
import sys
import time

IDLE_SECS = 300
ACCEPT_TIMEOUT_SECS = 60
REQ_TIMEOUT_SECS = 30
RECV_BYTES = 65536


class Classifier:
    def __init__(self, classify, model):
        self.classify = classify
        self.model = model
        self.proc = None

    def _start(self):
        self.proc = subprocess.Popen(
            [sys.executable, "-I", self.classify, "--model", self.model],
            cwd=os.path.dirname(self.classify),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )

    def ask(self, request):
        if self.proc is None or self.proc.poll() is not None:
            self._start()
        self.proc.stdin.write((json.dumps(request) + "\n").encode())
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        if not line:
            self.proc = None
            raise RuntimeError("classifier process exited")
        return json.loads(line)


def read_request(conn):
    data = b""
    while not data.endswith(b"\n"):
        chunk = conn.recv(RECV_BYTES)
        if not chunk:
            return None
        data += chunk
    return data


def serve(args):
    classifier = Classifier(args.classify, args.model)
    try:
        os.unlink(args.socket)
    except FileNotFoundError:
        pass
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(args.socket)
    server.listen(4)
    server.settimeout(ACCEPT_TIMEOUT_SECS)
    last_request = time.monotonic()
    while True:
        try:
            conn, _ = server.accept()
        except socket.timeout:
            if time.monotonic() - last_request >= IDLE_SECS:
                return
            continue
        with conn:
            conn.settimeout(REQ_TIMEOUT_SECS)
            data = read_request(conn)
            if not data:
                continue
            last_request = time.monotonic()
            try:
                request = json.loads(data)
                if isinstance(request, dict) and "shell" not in request:
                    request["shell"] = "bash"
                reply = classifier.ask(request)
            except Exception as exc:
                reply = {"error": str(exc)}
            try:
                conn.sendall((json.dumps(reply) + "\n").encode())
            except BrokenPipeError:
                pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", required=True)
    parser.add_argument("--classify", required=True)
    parser.add_argument("--model", required=True)
    serve(parser.parse_args())


if __name__ == "__main__":
    main()
]==]
