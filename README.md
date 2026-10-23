# Vela

> 可视化的家庭网络入侵检测系统 —— 把网络流量变成一片可以观测的宇宙。

- **恒星**：路由器、本机、NAS、云服务器、常用外网服务
- **航道**：IP 之间的连接；流光的速度和密度对应传输速率
- **颜色**：HTTPS 青 · HTTP 白 · DNS 紫 · QUIC 琥珀 · 异常红
- **告警**：端口扫描、新设备接入、信标回连、DNS 隧道、数据外泄……每条告警标注 MITRE ATT&CK 编号

<!-- TODO: 在这里放一张 3 秒内抓住眼球的动图 docs/assets/demo.gif -->

## 快速体验（模拟数据模式）

**在线体验**：<https://silchenn.github.io/vela/>（开启方法见 [docs/DEPLOY.md](docs/DEPLOY.md)）

前端目前有两种视觉风格，最终用哪个还没定，页面左上角可以互相切换：

| 风格 | 文件 | 在线地址 |
|---|---|---|
| 星际航道 | `frontend/index.html` | <https://silchenn.github.io/vela/> |
| 赛博朋克 | `frontend/cyber.html` | <https://silchenn.github.io/vela/cyber.html> |

**本地运行**：不需要安装任何依赖，也不需要抓包环境。

```bash
git clone https://github.com/silchenn/vela.git
```

然后用浏览器打开 `frontend/index.html`（直接双击即可；macOS 也可以在终端运行 `open frontend/index.html`）。

> 页面会从 jsDelivr CDN 加载 Three.js，首次打开需要联网。

星际航道版可以演练「下载大文件 / 4K 视频 / DNS 风暴 / 端口扫描 / NAS 宕机」五个场景；赛博朋克版可以演练「DDoS 攻击 / 高负载 Torrent」。两版都可以点击节点追踪它的进出流量。

## 目录结构

```
vela/
├── frontend/          3D 可视化前端（Three.js 单文件原型）
│   ├── index.html     星际航道风格
│   └── cyber.html     赛博朋克风格
├── backend/           数据采集与推送（Python，用法见 backend/README.md）
└── docs/
    ├── ROADMAP.md     项目定位、路线图与开发建议
    ├── DETECTIONS.md  检测规则设计（含 ATT&CK 映射）
    ├── ARCHITECTURE.md 架构、数据采集位置与前后端消息格式
    └── DEPLOY.md      发布到 GitHub 与在线演示
```

## 状态

| 模块 | 状态 |
|---|---|
| 前端原型（模拟数据） | ✅ 完成 |
| 后端采集：本机抓包 → 聚合 → WebSocket | ✅ 完成 |
| 后端采集：网关 conntrack | ⬜ 计划中 |
| 检测引擎 | ⬜ 计划中 |
| Suricata / Zeek 接入 | ⬜ 计划中 |

## 使用边界

本项目仅用于监控**你自己拥有或获得明确授权**的网络和设备。抓包、端口扫描等攻防演示请只在自己的实验环境中进行。

## 许可证

[MIT](LICENSE)
