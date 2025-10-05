#!/usr/bin/env python3
import argparse
import json
import logging
import os
import random
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
        response = fake_command_output(cmd, cwd="/root")
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


FAKE_HOSTNAME = "honeypot"

# Very small fake filesystem and file contents
FAKE_FS_DIRS = {
    "/": ["bin", "boot", "dev", "etc", "home", "lib", "lib64", "proc", "root", "run", "sbin", "tmp", "usr", "var"],
    "/root": [
        "README.md",
        "backup.tar.gz",
        "deploy.sh",
        "id_rsa",
        "id_rsa.pub",
        "notes.txt",
        ".bashrc",
        ".profile",
        ".ssh",
    ],
    "/root/.ssh": [
        "authorized_keys",
        "known_hosts",
    ],
    "/etc": [
        "passwd",
        "shadow",
        "group",
        "os-release",
        "hostname",
        "hosts",
        "issue",
    ],
    "/var": ["log", "tmp", "lib"],
    "/var/log": ["auth.log", "syslog"],
}

FAKE_FILE_CONTENT = {
    "/etc/passwd": (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "sshd:x:100:65534::/run/sshd:/usr/sbin/nologin\n"
    ),
    "/etc/shadow": (
        "root:*:19445:0:99999:7:::\n"
        "daemon:*:19445:0:99999:7:::\n"
        "sshd:*:19445:0:99999:7:::\n"
    ),
    "/etc/group": (
        "root:x:0:\n"
        "daemon:x:1:\n"
        "ssh:x:101:sshd\n"
    ),
    "/etc/hostname": FAKE_HOSTNAME + "\n",
    "/etc/hosts": (
        "127.0.0.1\tlocalhost\n"
        "127.0.1.1\t" + FAKE_HOSTNAME + "\n"
        "::1\tlocalhost ip6-localhost ip6-loopback\n"
    ),
    "/etc/issue": "Ubuntu 20.04.6 LTS \n \l\n",
    "/etc/os-release": (
        "NAME=\"Ubuntu\"\n"
        "VERSION=\"20.04.6 LTS (Focal Fossa)\"\n"
        "ID=ubuntu\n"
        "PRETTY_NAME=\"Ubuntu 20.04.6 LTS\"\n"
    ),
    "/root/README.md": "Internal notes.\n",
    "/root/notes.txt": "todo: rotate keys\n",
    "/root/id_rsa": "-----BEGIN OPENSSH PRIVATE KEY-----\n...fake...\n-----END OPENSSH PRIVATE KEY-----\n",
    "/root/id_rsa.pub": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDf... user@host\n",
    "/root/.ssh/authorized_keys": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB... user@host\n",
    "/var/log/auth.log": "Oct  5 12:00:00 honeypot sshd[123]: Server listening on 0.0.0.0 port 22.\n",
    "/var/log/syslog": "Oct  5 12:00:00 honeypot systemd[1]: Started Session c1 of user root.\n",
}


def _resolve_path(cwd: str, path: str) -> str:
    if not path:
        return cwd
    if path.startswith("~"):
        path = path.replace("~", "/root", 1)
    if not path.startswith("/"):
        path = os.path.normpath(os.path.join(cwd, path))
    return os.path.normpath(path)


def _dir_listing(path: str, all_flag: bool = False, long_flag: bool = False) -> str:
    # Decide which directory content to show
    items = FAKE_FS_DIRS.get(path)
    if items is None:
        return f"ls: cannot access '{path}': No such file or directory\n"
    names = list(items)
    hidden = [n for n in names if n.startswith(".")]
    visible = [n for n in names if not n.startswith(".")]
    def _ls_l_line(name: str, is_dir: bool = False, size: int = 4096) -> str:
        perms = ("d" if is_dir else "-") + "rwxr-xr-x"
        nlink = 1
        user = "root"
        group = "root"
        # Make sizes plausible
        if is_dir:
            size = 4096
        # Use a fixed but plausible date
        date = "Oct  5  2025"
        return f"{perms} {nlink} {user} {group} {size:>6} {date} {name}"

    if not long_flag:
        names_to_show = ([".", ".."] if all_flag else []) + visible + (hidden if all_flag else [])
        return "\n".join(names_to_show) + "\n"
    else:
        lines = []
        if all_flag:
            lines.append(_ls_l_line(".", True))
            lines.append(_ls_l_line("..", True))
        for n in visible:
            is_dir = (os.path.join(path, n) in FAKE_FS_DIRS)
            lines.append(_ls_l_line(n, is_dir=is_dir, size=(12345 if not is_dir else 4096)))
        if all_flag:
            for n in hidden:
                is_dir = (os.path.join(path, n) in FAKE_FS_DIRS)
                lines.append(_ls_l_line(n, is_dir=is_dir, size=(2048 if not is_dir else 4096)))
        return "\n".join(lines) + "\n"


def fake_command_output(cmd: str, cwd: str = "/root") -> str:
    cmd = (cmd or "").strip()
    if not cmd:
        return "\n"
    # Parse simple tokens
    parts = cmd.split()
    prog = parts[0]
    args = parts[1:]

    # Basics
    if prog == "whoami":
        return "root\n"
    if prog == "id":
        return "uid=0(root) gid=0(root) groups=0(root)\n"
    if prog == "uname":
        return "Linux honeypot 5.4.0-146-generic #163-Ubuntu SMP x86_64 GNU/Linux\n"
    if prog == "hostname":
        return FAKE_HOSTNAME + "\n"
    if prog == "pwd":
        return cwd + "\n"
    if prog == "echo":
        return (" ".join(args) + "\n") if args else "\n"
    if prog == "which":
        if args:
            return f"/usr/bin/{args[0]}\n"
        return "\n"
    if prog == "help":
        return (
            "Available: ls, cd, cat, id, whoami, uname, pwd, ps, df, free, ss, netstat, ip a, ifconfig, who, last, hostname, echo, which.\n"
        )
    if prog in ("exit", "logout"):
        return "\n"

    # ls handling
    if prog == "ls":
        long_flag = any(a in ("-l", "-la", "-al", "-lh", "-alh", "-lah") for a in args)
        all_flag = any(a in ("-a", "-la", "-al", "-alh", "-lah") for a in args)
        target = None
        for a in args:
            if not a.startswith("-"):
                target = a
                break
        target = _resolve_path(cwd, target) if target else cwd
        return _dir_listing(target, all_flag=all_flag, long_flag=long_flag)

    # cat handling
    if prog == "cat":
        if not args:
            return "cat: missing file operand\n"
        path = _resolve_path(cwd, args[0])
        if path in FAKE_FILE_CONTENT:
            return FAKE_FILE_CONTENT[path]
        # directory case
        if path in FAKE_FS_DIRS:
            return f"cat: {args[0]}: Is a directory\n"
        # a few special cases
        if path == "/proc/cpuinfo":
            return (
                "processor\t: 0\nmodel name\t: Intel(R) Xeon(R) CPU\ncpu MHz\t\t: 2300.000\n"  # shortened
            )
        if path == "/proc/meminfo":
            return "MemTotal:       2048000 kB\nMemFree:         512000 kB\n"
        return f"cat: {args[0]}: No such file or directory\n"

    # ps aux (static sample)
    if prog == "ps":
        return (
            "USER       PID %%CPU %%MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
            "root         1  0.0  0.1  22528  9500 ?        Ss   12:00   0:01 /sbin/init\n"
            "root       222  0.0  0.2  50000 12000 ?        Ss   12:01   0:00 /usr/sbin/sshd -D\n"
            "root      1337  0.0  0.1  12000  8000 pts/0    Ss   12:02   0:00 -bash\n"
        )

    # networking snapshots
    if prog == "netstat":
        return (
            "Active Internet connections (only servers)\nProto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name\n"
            "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      222/sshd\n"
        )
    if prog == "ss":
        return (
            "State   Recv-Q  Send-Q   Local Address:Port   Peer Address:Port  Process\n"
            "LISTEN  0       128      0.0.0.0:22           0.0.0.0:*          users:(\"sshd\",pid=222,fd=3)\n"
        )
    if prog == "ip" and args and args[0] == "a":
        return (
            "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\n    inet 127.0.0.1/8 scope host lo\n"
            "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n    inet 10.0.0.10/24 brd 10.0.0.255 scope global eth0\n"
        )
    if prog == "ifconfig":
        return (
            "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 10.0.0.10  netmask 255.255.255.0  broadcast 10.0.0.255\n"
        )

    # system info
    if prog == "df":
        return (
            "Filesystem      Size  Used Avail Use% Mounted on\n"
            "/dev/sda1        25G   11G   13G  47% /\n"
        )
    if prog == "free":
        return (
            "              total        used        free      shared  buff/cache   available\n"
            "Mem:        1990Mi       820Mi       500Mi        20Mi        670Mi       1040Mi\n"
        )
    if prog == "uptime":
        return " 17:00:00 up  1:23,  1 user,  load average: 0.10, 0.08, 0.05\n"
    if prog == "who":
        return "root     pts/0        2025-10-05 12:02 (203.0.113.10)\n"
    if prog == "last":
        return "root     pts/0        203.0.113.10    Sun Oct  5 12:02   still logged in\n\nwtmp begins Sun Oct  5 12:00:00 2025\n"

    # read-only FS reactions
    if prog in ("touch", "rm", "mv", "mkdir", "rmdir", "chmod", "chown", "apt", "apt-get", "yum"):
        return f"{prog}: cannot perform operation: Read-only file system\n"

    # fallthrough
    return f"bash: {prog}: command not found\n"


def interactive_shell(channel, client_addr, username, jlog: JsonLogger):
    try:
        last_login = "Last login: Sun Oct  5 12:02:01 2025 from 203.0.113.10\n"
        banner = (
            last_login
            + "Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0 x86_64)\n\n"
            + "System load: 0.01\tProcesses: 112\tUsers logged in: 1\n"
            + "Usage of /: 42% of 25.0GB\tMemory usage: 23%\tSwap usage: 1%\n\n"
        )
        channel.sendall(banner.encode("utf-8"))
        cwd = "/root"
        while True:
            prompt = f"root@{FAKE_HOSTNAME}:{cwd}# "
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
                    path = _resolve_path(cwd, parts[1])
                    # only allow into known directories for realism
                    if path in FAKE_FS_DIRS:
                        cwd = path
                    else:
                        channel.sendall(f"bash: cd: {parts[1]}: No such file or directory\n".encode("utf-8"))
                continue
            # slight, random delay to mimic execution time
            try:
                time.sleep(random.uniform(0.05, 0.25))
            except Exception:
                pass
            out = fake_command_output(cmd, cwd=cwd)
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
