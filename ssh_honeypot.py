#!/usr/bin/env python3
import argparse
import json
import logging
import os
import socket
import threading
import time
from datetime import datetime

import paramiko


def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)


def load_or_create_host_key(path: str) -> paramiko.PKey:
    if os.path.exists(path):
        return paramiko.RSAKey.from_private_key_file(path)
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(path)
    return key


class JsonLogger:
    def __init__(self, log_dir: str):
        ensure_dir(log_dir)
        self.file_path = os.path.join(log_dir, "events.jsonl")
        # Also attach a simple console logger for quick viewing
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s %(levelname)s %(message)s",
        )
        self.lock = threading.Lock()

    def log(self, event: dict):
        event["ts"] = datetime.utcnow().isoformat() + "Z"
        line = json.dumps(event, ensure_ascii=False)
        with self.lock:
            with open(self.file_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        logging.info(line)


class HoneypotServer(paramiko.ServerInterface):
    def __init__(self, client_addr, jlog: JsonLogger):
        super().__init__()
        self.client_addr = client_addr
        self.jlog = jlog
        self.event = threading.Event()
        self.username = None

    def get_allowed_auths(self, username):
        return "password"  # advertise password only

    def check_auth_password(self, username, password):
        self.username = username
        self.jlog.log(
            {
                "type": "auth_attempt",
                "remote": f"{self.client_addr[0]}:{self.client_addr[1]}",
                "username": username,
                "password": password,
                "result": "accepted",
            }
        )
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        # Interactive shell requested
        self.event.set()
        return True

    def check_channel_exec_request(self, channel, command):
        # Log and send a plausible response, then close
        cmd = command.decode("utf-8", errors="replace") if isinstance(command, (bytes, bytearray)) else str(command)
        self.jlog.log(
            {
                "type": "exec",
                "remote": f"{self.client_addr[0]}:{self.client_addr[1]}",
                "username": self.username,
                "command": cmd,
            }
        )
        response = fake_command_output(cmd)
        try:
            channel.sendall(response.encode("utf-8"))
            channel.send_exit_status(0)
        except Exception:
            pass
        finally:
            try:
                channel.close()
            except Exception:
                pass
        # We handled it, so return True
        return True


FAKE_FILES = [
    "README.md",
    "backup.tar.gz",
    "deploy.sh",
    "id_rsa",
    "id_rsa.pub",
    "notes.txt",
]


def fake_command_output(cmd: str) -> str:
    cmd = (cmd or "").strip()
    if cmd in ("whoami",):
        return "root\n"
    if cmd.startswith("id"):
        return "uid=0(root) gid=0(root) groups=0(root)\n"
    if cmd.startswith("uname"):
        return "Linux honeypot 5.4.0-146-generic #163-Ubuntu SMP x86_64 GNU/Linux\n"
    if cmd in ("pwd",):
        return "/root\n"
    if cmd.startswith("ls"):
        return "\n".join(FAKE_FILES) + "\n"
    if cmd.startswith("cat /etc/passwd"):
        return (
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "sshd:x:100:65534::/run/sshd:/usr/sbin/nologin\n"
        )
    if cmd.startswith("cat "):
        return "Permission denied\n"
    if cmd in ("exit", "logout"):
        return "\n"
    if cmd == "help":
        return "Try common commands like ls, id, whoami, uname, pwd.\n"
    return f"bash: {cmd.split()[0]}: command not found\n"


def interactive_shell(channel, client_addr, username, jlog: JsonLogger):
    try:
        banner = (
            "Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0 x86_64)\n"
            "\n"
            "System load: 0.01\tProcesses: 112\tUsers logged in: 1\n"
            "Usage of /: 42% of 25.0GB\tMemory usage: 23%\tSwap usage: 1%\n"
            "\n"
        )
        channel.sendall(banner.encode("utf-8"))
        cwd = "/root"
        while True:
            prompt = f"root@honeypot:{cwd}# "
            channel.sendall(prompt.encode("utf-8"))
            data = read_line(channel)
            if data is None:
                break
            cmd = data.strip()
            if not cmd:
                continue
            jlog.log(
                {
                    "type": "shell",
                    "remote": f"{client_addr[0]}:{client_addr[1]}",
                    "username": username,
                    "command": cmd,
                }
            )
            if cmd in ("exit", "logout"):
                channel.sendall(b"logout\n")
                break
            # very small fake cwd support
            if cmd.startswith("cd"):
                parts = cmd.split(maxsplit=1)
                if len(parts) == 1 or parts[1] in ("~", "$HOME"):
                    cwd = "/root"
                else:
                    path = parts[1]
                    if path.startswith("/"):
                        cwd = path
                    else:
                        cwd = os.path.normpath(os.path.join(cwd, path))
                continue
            out = fake_command_output(cmd)
            channel.sendall(out.encode("utf-8"))
    except Exception:
        pass
    finally:
        try:
            channel.close()
        except Exception:
            pass


def read_line(channel, timeout=180):
    channel.settimeout(timeout)
    buf = bytearray()
    try:
        while True:
            b = channel.recv(1)
            if not b:
                return None
            if b in (b"\n", b"\r"):
                break
            buf.extend(b)
        return buf.decode("utf-8", errors="replace")
    except Exception:
        return None


def handle_client(client, addr, host_key, jlog: JsonLogger):
    t = paramiko.Transport(client)
    try:
        t.add_server_key(host_key)
        server = HoneypotServer(addr, jlog)
        t.start_server(server=server)
        chan = t.accept(30)
        if chan is None:
            return
        # wait a moment to see if shell was requested
        server.event.wait(1.0)
        if server.event.is_set():
            interactive_shell(chan, addr, server.username, jlog)
        else:
            # If no shell (likely exec), give a short grace period
            time.sleep(0.5)
    except Exception as e:
        jlog.log({"type": "error", "remote": f"{addr[0]}:{addr[1]}", "error": str(e)})
    finally:
        try:
            t.close()
        except Exception:
            pass
        try:
            client.close()
        except Exception:
            pass


def serve(host: str, port: int, host_key_path: str, log_dir: str):
    jlog = JsonLogger(log_dir)
    host_key = load_or_create_host_key(host_key_path)

    sock = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_STREAM)
    # Allow quick rebinding
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(100)

    logging.info(f"SSH honeypot listening on {host}:{port}")
    logging.info(f"Host key: {host_key_path}")
    logging.info(f"Logging to: {os.path.join(log_dir, 'events.jsonl')}")

    while True:
        client, addr = sock.accept()
        jlog.log({"type": "connect", "remote": f"{addr[0]}:{addr[1]}"})
        thr = threading.Thread(target=handle_client, args=(client, addr, host_key, jlog), daemon=True)
        thr.start()


def parse_args():
    p = argparse.ArgumentParser(description="Simple SSH honeypot (port 22 capable via redirect)")
    p.add_argument("--host", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    p.add_argument("--port", type=int, default=22, help="Bind port (default: 22)")
    p.add_argument("--host-key", default="honeypot_host_key", help="Path to server host key (generated if missing)")
    p.add_argument("--log-dir", default="logs", help="Directory for JSON logs")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    try:
        serve(args.host, args.port, args.host_key, args.log_dir)
    except PermissionError:
        print("Permission denied binding to port 22. Run with sufficient privileges, use setcap on python, or run via Docker.")
    except KeyboardInterrupt:
        print("\nStopping honeypot...")
