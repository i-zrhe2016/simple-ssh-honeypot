# Cowrie 蜜罐（SSH/Telnet）

本仓库使用官方镜像 `cowrie/cowrie` 通过 Docker Compose 部署中交互蜜罐（SSH 默认 2222、Telnet 默认 2223）。已将宿主端口映射为：
- SSH: 宿主 `22` → 容器 `2222`
- Telnet: 宿主 `23` → 容器 `2223`

## 快速开始（Docker）

1) 启动
- 确认宿主未占用 22/23（若系统 sshd 占用 22，请先改到其他端口）。
- `docker compose up -d`

2) 测试
- SSH: `ssh -o StrictHostKeyChecking=no 127.0.0.1`
- Telnet（可选）: `telnet 127.0.0.1 23`

3) 日志与下载
- Cowrie 日志目录（宿主）：`data/cowrie/var/log/cowrie/`
- 会话文本：`cowrie.log`，JSON：`cowrie.json`，下载样本：`data/cowrie/var/lib/cowrie/downloads/`
- 查看：`tail -f data/cowrie/var/log/cowrie/cowrie.log`

## 自定义（可选）

- 如需修改配置，先把默认配置拷贝出来，再挂载到 `/cowrie/etc`：
  - 复制：`docker cp cowrie:/cowrie/etc ./data/cowrie/etc`
  - 修改 `./data/cowrie/etc/cowrie.cfg` 后，在 compose 中追加：
    - `- ./data/cowrie/etc:/cowrie/etc`
  - 重启：`docker compose restart`

## 说明

- 仅用于安全研究/教学目的，请遵循当地法律法规并注意隐私合规。
- 高危：对外开放 22/23 存在被滥用风险，建议在隔离网络/云防火墙下部署，并限制出站流量。

---

附：此前的 Python 简易 SSH 蜜罐（文件 `ssh_honeypot.py`）已弃用，改为 Cowrie 部署方案。
