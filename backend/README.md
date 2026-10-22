# backend

数据采集、聚合与检测引擎，计划中（路线图 M1）。

第一步目标：
1. 读取本机网卡（或网关 conntrack）的连接；
2. 每 200ms 聚合为 `flow` 消息（格式见 `../docs/ARCHITECTURE.md`）；
3. 通过 WebSocket 推送给前端（仅监听局域网，带 token）。
