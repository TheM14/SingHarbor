[English](./README.md) | **中文**

# SingHarbor

面向个人用户的跨平台 sing-box 管理 WebUI。

**目标 sing-box**：v1.13.14 &nbsp;|&nbsp; **版本**：v1.1.0

SingHarbor 管理 sing-box 二进制程序及其 JSON 配置。它不会安装系统服务，也不会修改防火墙。
只有在用户明确预览并确认同步时，才会修改 Cloudflare A/AAAA 记录。

## 运行要求

- Python 3.12 或更高版本
- `pip`
- 用于配置校验和运行的 sing-box v1.13 兼容内核

## 获取源码

下载或克隆项目，并在执行后续部署命令前进入项目目录：

```bash
git clone https://github.com/TheM14/SingHarbor.git
cd SingHarbor
```

## Conda 部署

单独创建 Python 3.12 环境，安装依赖并启动 SingHarbor：

```bash
conda create -n singharbor python=3.12 pip -y
conda activate singharbor
python -m pip install -r requirements.txt
python run.py
```

## 标准 venv 部署

### Linux / macOS

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python run.py
```

### Windows PowerShell

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python run.py
```

启动后访问 `http://127.0.0.1:51080`。首次访问需要创建唯一的管理员账户；部署协议前，
请先在“内核”页面配置或下载 sing-box 内核。

修改本地监听端口的示例：

```bash
python run.py --host 127.0.0.1 --port 51081
```

如果没有 HTTPS 反向代理和合适的网络访问控制，不建议监听公网网卡。

## 主要功能

- 管理 sing-box 内核、配置校验、备份及进程状态。
- 通过分步向导或原子化一键部署方案创建协议。
- 为同一入站生成独立的 IPv4、IPv6 和域名客户端变体。
- 支持 Cloudflare WebSocket + TLS 线路及优选 Cloudflare IP。
- 通过 Cloudflare DNS-01 自动签发公开可信的 Let's Encrypt 证书，并原子接管新建或已有的 TLS 直连入站。
- 部署直连 VLESS Reality，并生成兼容的 VLESS 分享链接。
- 生成二维码、复制全部客户端变体、下载完整 JSON 或文本导出。
- 原位编辑已有入站，同时保留 sing-box 未知字段。
- 预览并明确同步 Cloudflare A/AAAA 记录。

## 支持的协议

| 协议 | 类型 | TLS | 分享链接 |
|---|---|---|---|
| Shadowsocks | `shadowsocks` | 不需要 | `ss://` |
| VMess | `vmess` | 可选 | `vmess://` |
| Trojan | `trojan` | 必须 | `trojan://` |
| VLESS / Reality | `vless` | 可选 / Reality | `vless://` |
| Hysteria2 | `hysteria2` | 必须 | `hysteria2://` |
| TUIC | `tuic` | 必须 | `tuic://` |
| ShadowTLS | `shadowtls` | 不需要 | 客户端 JSON |
| Naive | `naive` | 可选 | `naive+https://` |
| Hysteria | `hysteria` | 必须 | `hysteria://` |
| AnyTLS | `anytls` | 必须 | `anytls://` |

Reality 始终是独立直连入口，不会与 Cloudflare 橙云线路混用。先执行
`sing-box generate reality-keypair` 生成密钥对，然后在 VLESS 向导中填写服务端私钥、
客户端公钥、握手目标/SNI、short ID 和客户端指纹。

## 公网入口与 Cloudflare

- 客户端公网地址属于发布元数据，不会替换 sing-box 监听地址。
- VMess、VLESS 和 Trojan 可以通过 Cloudflare 使用 WebSocket + TLS。
- 优选 Cloudflare IPv4 或 IPv6 只替换客户端连接地址；TLS SNI 和 WebSocket Host 仍使用域名。
- Hysteria、Hysteria2 和 TUIC 使用 UDP/QUIC，不能套用标准 Cloudflare 橙云 WebSocket 代理。
- API Token 只使用一次，或从 `CLOUDFLARE_API_TOKEN` 读取，永远不会保存。
- Cloudflare Origin CA 证书只适合 CDN 到源站的流量；TLS 直连应使用可选的 Let's Encrypt 证书或其他公开可信的完整证书链。

## 一键部署逻辑

“一键部署”页面包含三组相互独立的输入：

1. 域名，以及可选的优选 Cloudflare IPv4 或 IPv6。
2. 可选的 CDN 证书目录，以及使用一次性 Cloudflare DNS API Token 和邮箱为 TLS 直连自动签发 Let's Encrypt 证书。
3. 可选的公网直连 IPv4 和 IPv6。

某一组留空时，只跳过依赖该组的线路；非空但无效的输入会停止部署。系统会自动分配端口和凭据，
在一次更新中校验并保存全部入站，最后只重启一次 sing-box。一键部署不会修改 A/AAAA 记录；
Let's Encrypt DNS-01 会由 Certbot 临时创建并清理 `_acme-challenge` TXT 记录。SingHarbor 不保存
Cloudflare Token，因此请在证书到期前再次执行该操作完成续签；`CLOUDFLARE_API_TOKEN` 只免去重复输入，
不会自动创建后台续期计划。
签发成功后，结果页会显示签发机构、有效期、SHA-256 指纹、证书路径和实际接管的 TLS Direct 入站；
同样的信息会写入 `data/letsencrypt/last-issuance.json`，其中不包含 Cloudflare Token。

## 数据位置

| 数据 | 位置 |
|---|---|
| 数据库、设置、备份和日志 | `<project>/data/` |
| sing-box 配置 | `<project>/data/sing-box-config.json` |
| Certbot 账户与已签发证书材料 | `<project>/data/letsencrypt/` |
| 已下载内核 | `<project>/kernels/` |

## 卸载

停止 SingHarbor 后删除项目目录。如果创建了独立 Conda 环境，可另外删除：

```bash
conda env remove -n singharbor
```

## 许可

仅供个人使用。与 sing-box 项目无关（[GPLv3](https://github.com/SagerNet/sing-box)）。
