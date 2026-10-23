# backend

数据采集、聚合与推送（路线图 M1）。目前的数据源是**本机网卡抓包**，只能看到进出本机的流量。

```
en0 抓包（Scapy）→ PacketEvent → 聚合器（200ms 窗口）→ flow / node 消息 → WebSocket
```

## 安装

```bash
cd backend
python3 -m venv .venv
.venv/bin/pip install -e .
```

## 运行

```bash
.venv/bin/python -m vela                # 默认抓 en0，监听 en0 自己的 IPv4:8765
.venv/bin/python -m vela --help         # 网卡、地址、端口、token、窗口长度
```

启动后会打印连接地址，例如 `ws://192.168.2.17:8765/?token=...`。token 不指定时每次随机生成，固定下来可以用 `--token` 或环境变量 `VELA_TOKEN`。

用调试客户端查看推送的消息：

```bash
.venv/bin/python -m vela.watch 'ws://192.168.2.17:8765/?token=...'
```

### 权限

macOS 抓包需要读 `/dev/bpf*`。安装 Wireshark 时勾选 ChmodBPF，把当前用户加入 `access_bpf` 组后不用 sudo；否则用 `sudo` 运行。

### 安全

- 只允许绑定局域网或回环地址，`0.0.0.0` 和公网地址会被拒绝。
- token 错误的连接返回 HTTP 401。
- 只读包头和 DNS 响应里的域名→IP 映射，不解析、不保存载荷。

## 代码结构

| 文件 | 作用 |
|---|---|
| `vela/events.py` | 统一事件 `PacketEvent`，所有数据源适配器都输出它 |
| `vela/sources/pcap.py` | 本机抓包适配器 |
| `vela/aggregator.py` | 按 (本机, 对端, 传输层, 服务端口) 聚合成 flow；维护节点表，用 DNS 响应给外网节点命名 |
| `vela/server.py` | WebSocket 推送：新连接先收到节点快照，之后每个窗口收到新增节点和 flow |
| `vela/watch.py` | 调试客户端 |

## 测试

```bash
.venv/bin/python -m unittest discover -s tests
```
