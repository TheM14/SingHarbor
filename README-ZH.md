[English](./README.md) | **中文**

# SingHarbor

面向个人用户的跨平台 sing-box 管理 WebUI。

**目标版本**: sing-box v1.13.14 &nbsp;|&nbsp; **版本**: v1.0.0

SingHarbor **不会**安装系统服务或修改防火墙。它管理 sing-box 二进制程序和
JSON 配置文件，并可选择显式同步 Cloudflare A/AAAA DNS 记录。

## 运行要求

- Python 3.11 或更高版本
- `pip`

建议使用独立的虚拟环境，但 SingHarbor 不强制使用 Conda 或某一种环境管理工具。

## 快速启动

```bash
# 在当前 Python 环境中安装依赖并启动
python -m pip install -r requirements.txt
python run.py
```

浏览器打开 `http://127.0.0.1:51080`，按引导创建管理员账号。

例如，可以先选择一种方式创建独立环境：

```bash
# Python 自带 venv（Linux/macOS）
python -m venv .venv
source .venv/bin/activate

# 或者使用 Conda
conda create -n singharbor python=3.11 -y
conda activate singharbor
```

## 支持的协议

| 协议 | 类型 | TLS | 分享链接 |
|---|---|---|---|
| Shadowsocks | `shadowsocks` | 不需要 | ss:// |
| VMess | `vmess` | 可选 | vmess:// |
| Trojan | `trojan` | 必须 | trojan:// |
| VLESS | `vless` | 可选 | vless:// |
| Hysteria2 | `hysteria2` | 必须 | hysteria2:// |
| TUIC | `tuic` | 必须 | tuic:// |
| ShadowTLS | `shadowtls` | 不需要 | — |
| Naive | `naive` | 可选 | naive+https:// |
| Hysteria | `hysteria` | 必须 | hysteria:// |
| AnyTLS | `anytls` | 必须 | — |

## 公网入口与 Cloudflare

- 可同时生成 IPv4 直连、IPv6 直连和域名三套客户端配置。
- VMess、VLESS、Trojan 可通过 WebSocket + TLS 使用 Cloudflare 普通橙云代理。
- Hysteria、Hysteria2、TUIC 使用 UDP/QUIC，不能套用普通橙云 WebSocket 代理。
- Cloudflare API Token 仅单次使用，或从 `CLOUDFLARE_API_TOKEN` 读取，不会保存。
- DNS 变更会先预览，必须明确确认后才会执行。

## 一键部署

“一键部署”页面只需要填写域名、服务器证书目录，以及可选的 IPv4/IPv6
地址。系统会自动分配端口和凭据，在一次配置校验与保存中部署所有兼容协议，
只重启一次 sing-box，并集中返回分享链接或客户端 JSON。任意输入块留空时，
只跳过依赖该输入的线路。一键部署不会修改 Cloudflare DNS，域名需要事先正确
指向服务器。

## 数据存储位置

所有数据都在项目目录内。删除项目文件夹即彻底清除。

| 数据 | 位置 |
|---|---|
| 数据库、设置、备份、日志 | `<project>/data/` |
| sing-box 配置文件 | `<project>/data/singbox-config.json` |
| 已下载内核 | `<project>/kernels/` |

## 卸载

```bash
rm -rf path/to/SingHarbor
```

如果依赖安装在项目目录之外的独立虚拟环境中，还需要单独删除该环境。
SingHarbor 本身不会安装系统服务或修改防火墙。

## 许可证

个人使用。与 sing-box 项目无关（[GPLv3](https://github.com/SagerNet/sing-box)）。
