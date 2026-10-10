# Local Service Monitor

macOS 本地服务监控与管理工具：自动扫描正在监听的 TCP/UDP 端口，识别对应的进程、应用与服务，按网络访问范围智能分类，并提供新拟态（Neumorphism）风格的本地 Web 管理界面。

A macOS-local service monitor: discovers listening TCP/UDP endpoints, identifies the owning processes and applications, classifies services by access scope, and manages them through a Neumorphism-styled local web UI.

## 功能 Features

- 真实扫描 macOS 监听端口（`lsof` + `psutil` + `ps` 组合，优雅降级）
- 进程 / 应用 / 可执行路径 / 启动命令（自动脱敏敏感参数）识别
- 低风险协议探测：HTTP/HTTPS、SSH、PostgreSQL、MySQL、Redis、WebSocket 等（缓存 + 增量，不重复探测）
- GUI 应用温和探测（默认开启）：对位于 `.app` 包内的图形程序，自动探测只建立连接并读取首包、**不发送任何请求字节**，避免触发应用弹窗；仍可识别 SSH/MySQL/Redis 等首包协议。手动"重新探测"始终执行完整探测，设置中可关闭温和模式
- Web 分类标准：**只有能在浏览器中打开界面的 HTTP(S) 服务（HTML 页面/重定向）才归入本机/局域网/互联网 Web 分类**；纯 JSON API、WebSocket 握手端点（如 HTTP 426）归入非 Web 并保留 REST API / WebSocket 标签
- 访问范围分类：本机 Loopback / 局域网 / 全部接口（通配）/ 公网（需外部验证，默认未验证）
- 一级分类：互联网 Web、局域网 Web、本机 Web、非 Web、未知；二级标签为统一规范 slug（web-ui、rest-api、database、dns、proxy、message-queue、monitoring、container、file-storage、mail、vpn 等 30+ 类），界面随中/英文语言实时翻译标签名
- 通用识别规则库：覆盖数据库/缓存/消息队列/搜索/监控/代理/DNS/邮件/目录服务/文件存储/时间同步/VPN/容器/K8s/Web 服务器/负载均衡等常见服务器服务；常见服务器端口（53、123、3306、5432、6379、9200、27017 等）即使规则未命中也会自动附加领域标签，适合部署在任意服务器上
- 识别置信度（已确认 / 高可信推断 / 低可信推断 / 未知）与识别依据展示
- 实时刷新（关闭/3/5/10/30 秒）、搜索、多条件筛选、排序、卡片/列表双视图
- CPU、内存实时监控与 SVG 历史曲线
- 一键打开服务、复制 URL/IP/端口/PID/路径/命令、重新探测
- 安全停止进程：确认弹窗、PID 复用校验、系统进程保护、禁止自杀、仅 SIGTERM
- SQLite 历史记录（首次发现 / 出现 / 消失 / 监听变化 / 识别变化 / 手动停止）
- 简体中文 / English 实时切换；独立设计的浅色 / 深色主题（深色为纯黑背景）
- 设置持久化：界面偏好走 localStorage，扫描行为设置实时影响后端
- 完全本地运行：仅监听 127.0.0.1，CSRF 令牌 + 同源校验，无任何外部上传

## 安装 Installation

要求：macOS（Apple Silicon 或 Intel），Python 3.9+（推荐 3.10+）。

```bash
cd Local-Service-Monitor
python3 -m pip install -r requirements.txt
```

> 未安装 psutil 时程序仍可运行（降级为 lsof/ps 模式，CPU/内存等字段标记为不可用）。

## 启动 Running

```bash
python3 server.py
```

启动后自动：

1. 在 `127.0.0.1` 上开启管理 HTTP 服务（默认端口 8848，被占用时自动换端口）
2. 打开默认浏览器加载界面
3. 立即执行首次扫描并持续监控

环境变量：

- `LSM_PORT`：指定端口（默认 8848）
- `LSM_NO_BROWSER=1`：不自动打开浏览器

## 权限说明 Permissions

- **不需要 sudo/管理员权限。** 默认只能看到当前用户可访问的进程详情。
- 其他用户的进程、受限进程会显示「权限不足 / 无权限」，不会伪造数据。
- 停止进程需要与该进程相同的用户权限；root 进程无法被停止（会返回权限错误）。
- 协议探测仅向本机监听端点发送少量低风险请求（单连接、单请求、带超时），全部可在设置中关闭。
- 「公网验证」默认关闭：仅监听 0.0.0.0 不会标记为公网可访问；只有你显式配置外部验证地址后才会发起验证请求。

## 常见问题 FAQ / Troubleshooting

**浏览器提示 forbidden / 无法加载数据？**
必须通过 `python3 server.py` 启动并访问它打印出的 `http://127.0.0.1:<port>/` 地址。直接双击打开 `index.html` 文件没有后端与 CSRF 令牌，界面会提示离线——这是设计行为。

**端口被占用？**
程序会自动尝试下一个可用端口；也可 `LSM_PORT=9000 python3 server.py`。

**看不到某些系统服务？**
macOS 上非本用户进程默认不可见详细信息（无 sudo），界面会如实标注权限不足。

**CPU 列一开始显示 “—”？**
CPU 占用率需要两个采样点差值，首次扫描后的下一个刷新周期起即为真实数值。

**历史记录存在哪里？**
同目录 `history.sqlite`；保留天数在设置页调整，可随时清空。设置持久化在 `config.json`。

**如何关闭自动协议探测？**
设置 → 扫描 → 自动协议识别（关闭后只分类，不发送任何探测包）。

**探测会让某些桌面应用自动弹出窗口？**
默认已防护：位于 `.app` 包内的图形应用在自动探测时只连接、只读取，不发送任何请求字节（这类应用的弹窗逻辑通常挂在收到请求之后）。如果仍遇到某应用被连接本身触发弹窗，将其加入温和探测防护范围或关闭自动协议识别即可，服务仍会正常显示。

## 架构 Architecture

- `server.py` — Python 后端：扫描、识别、探测、分类、历史、进程管理、HTTP API（标准库 + psutil）
- `index.html` — 单文件前端：HTML + CSS + JS，内嵌 SVG 图标，无框架、无 CDN、无构建
- `config.json` / `history.sqlite` — 运行时生成

## 安全 Security

- 仅监听回环地址 `127.0.0.1`；非回环请求一律拒绝
- 所有 API 需要随页面注入的一次性 CSRF 令牌；写操作额外校验 Origin/Referer
- 进程停止：确认框 + 进程身份校验（名称 + 启动时间，防 PID 复用）+ 关键系统进程名单保护 + 仅 SIGTERM
- 命令行展示脱敏（API key / token / password 等参数值掩码）
- 不向任何外部服务器上传本地端口、进程或网络信息

## License

本项目代码 MIT；参考了 PortDoc / Portbook / Sloth 的公开实现思路，未复制其代码与 UI（各自 GPL/MIT 许可见其上游仓库）。
