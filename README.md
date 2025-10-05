# 简易 SSH 蜜罐

基于 Python/Paramiko 的轻量 SSH 蜜罐：记录连接、凭据、exec 命令与交互式输入（JSON 行）。默认监听 `0.0.0.0:22`，首次运行自动生成主机私钥。

## 快速开始

- 安装依赖：
  - `pip install -r requirements.txt`
- 启动（默认 0.0.0.0:22）：
  - `sudo python3 ssh_honeypot.py`
- 可选参数：
  - `--host 0.0.0.0 --port 22 --host-key honeypot_host_key --log-dir logs`
- 日志文件：
  - `logs/events.jsonl`（JSON 行）

## 本地测试

- SSH 连接（任意凭据都会被接受并记录）：
  - `ssh -o StrictHostKeyChecking=no test@127.0.0.1`
- 实时查看日志：
  - `tail -f logs/events.jsonl`

## Docker（可选）

- 构建：`docker compose build`
- 启动：`docker compose up -d`
- 日志：`tail -f data/logs/events.jsonl`
- 如需对外占用 `22` 端口，请先确保宿主机未占用该端口（例如将系统 SSH 改到其他端口）。

## 注意

- 仅用于安全研究/教学，请在合法合规前提下部署。
- 建议在容器/隔离环境中以最小权限运行。
