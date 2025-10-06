#!/usr/bin/env python3
"""
Cowrie 命令清单小工具

功能：
- 从 cowrie JSON 日志（默认 data/cowrie/var/log/cowrie/cowrie.json）解析命令事件
- 输出最近 N 条命令（时间/IP/会话/事件类型/命令）
- 可选输出按会话与按 IP 的命令数量汇总

用法示例：
- 最近 50 条命令：
  python3 scripts/cowrie_cmds.py -n 50
- 按会话/IP 汇总：
  python3 scripts/cowrie_cmds.py -n 50 --summary
- 只看指定 IP：
  python3 scripts/cowrie_cmds.py --ip 1.2.3.4

注意：
- 仅解析 eventid 为 cowrie.command.input / cowrie.command.failed 的事件。
"""

import argparse
import json
from collections import defaultdict, deque
from pathlib import Path
from typing import Dict, Any, Iterable


def iter_events(path: Path) -> Iterable[Dict[str, Any]]:
    if not path.exists():
        return []
    with path.open("r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except Exception:
                continue
            yield ev


def main():
    p = argparse.ArgumentParser(description="Parse Cowrie JSON log for command events")
    p.add_argument("-f", "--file", default="data/cowrie/var/log/cowrie/cowrie.json", help="Path to cowrie.json")
    p.add_argument("-n", "--limit", type=int, default=50, help="Show last N command events")
    p.add_argument("--ip", help="Filter by source IP")
    p.add_argument("--session", help="Filter by session id")
    p.add_argument("--only-failed", action="store_true", help="Only include failed commands")
    p.add_argument("--summary", action="store_true", help="Show summary by session and IP")
    args = p.parse_args()

    path = Path(args.file)
    want = {"cowrie.command.input", "cowrie.command.failed"}
    last = deque(maxlen=max(1, args.limit))
    by_sess: Dict[str, Dict[str, Any]] = defaultdict(lambda: {"ip": None, "count": 0})
    by_ip: Dict[str, int] = defaultdict(int)

    if not path.exists():
        print(f"Log file not found: {path}")
        return

    for ev in iter_events(path):
        eid = ev.get("eventid")
        if eid not in want:
            continue
        if args.only_failed and eid != "cowrie.command.failed":
            continue
        if args.ip and ev.get("src_ip") != args.ip:
            continue
        if args.session and ev.get("session") != args.session:
            continue

        # Accumulate for summary
        s = ev.get("session")
        ip = ev.get("src_ip")
        by_ip[ip] += 1
        by_sess[s]["ip"] = ip
        by_sess[s]["count"] += 1
        last.append(ev)

    # Recent list
    print("-- Recent commands --")
    if not last:
        print("(no matching command events)")
    else:
        for ev in last:
            ts = ev.get("timestamp")
            ip = ev.get("src_ip")
            sess = ev.get("session")
            eid = ev.get("eventid")
            cmd = ev.get("input") or ev.get("message")
            print(f"{ts} {ip} {sess} {eid}: {cmd}")

    if args.summary:
        print("\n-- Session summary (top 20) --")
        items = sorted(by_sess.items(), key=lambda x: x[1]["count"], reverse=True)
        for s, meta in items[:20]:
            print(f"session={s} ip={meta['ip']} commands={meta['count']}")

        print("\n-- IP summary (top 20) --")
        ip_items = sorted(by_ip.items(), key=lambda x: x[1], reverse=True)[:20]
        for ip, c in ip_items:
            print(f"ip={ip} commands={c}")


if __name__ == "__main__":
    main()

