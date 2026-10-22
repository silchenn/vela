# 架构

```
┌────────────── 数据源 ──────────────┐
│ 本机抓包 │ 网关 conntrack │ Suricata eve.json │ Zeek logs │
└─────┬─────────────┬──────────────┬───────────────┘
      └──────── 适配器（统一成 flow 事件）────────┐
                                                  ▼
                          聚合器（每 200ms 一个窗口）
                          + 节点治理（DNS 映射 / ASN 合并 / 生命周期）
                                                  │
                                ┌─────────────────┴──────────────┐
                                ▼                                ▼
                         检测引擎（D1–D6）                 设备探活（ping / ARP）
                                └─────────────┬──────────────────┘
                                              ▼
                          WebSocket（仅局域网 + token）
                                              ▼
                          前端：Three.js 星图（保留模拟数据模式）
```

## 技术选型（暂定）

| 层 | 原型 | 正式版 |
|---|---|---|
| 采集 | Python + Scapy | Go（gopacket）/ conntrack / eBPF |
| 聚合与检测 | Python | Go |
| 传输 | WebSocket | WebSocket |
| 前端 | Three.js 单文件 | Three.js + Vite 模块化 |

## 消息格式（前端原型的模拟器已按 flow 格式输出，接入时补上 `type` 字段）

### flow：每个聚合窗口内的一条连接

```json
{
  "type": "flow",
  "ts": 1792564110000,
  "src": "192.168.1.10",
  "dst": "140.82.112.3",
  "proto": "https",
  "port": 443,
  "bytes_up": 4096,
  "bytes_down": 182344,
  "window_ms": 200
}
```

`proto` 取值：`https` / `quic` / `http` / `dns` / `alert`。

### node：节点信息与状态

```json
{
  "type": "node",
  "ip": "140.82.112.3",
  "name": "GitHub",
  "asn": "AS36459",
  "kind": "external",
  "online": true
}
```

### alert：见 [DETECTIONS.md](DETECTIONS.md#告警消息格式)

## 安全注意

- WebSocket 服务只绑定局域网地址，连接时校验 token。
- 不持久化 payload，只保留元数据。
- 采集程序以最小权限运行（Linux 上可用 `CAP_NET_RAW` 代替 root）。
