# auto-checkin 通用自动签到面板

多站点、多账号的通用自动签到面板：任意网站的签到接口都可配置（URL/方法/头/体全开放），支持账号密码自动登录换 token、Cookie、固定 Token 三种登录态，每账号独立定时、失败按间隔自动重试、首次失败邮件提醒。纯 Python 标准库实现，零第三方依赖。

## 快速开始

```bash
python checkin_panel.py            # 启动，浏览器打开 http://127.0.0.1:8799
```

无依赖安装步骤，Python ≥ 3.8 即可（Windows / Linux 通用）。

## 常用操作

| 想做什么 | 怎么做 |
| --- | --- |
| 添加站点签到 | 页面「＋ 添加任务」，填签到接口；不确定结构就点「示例 · Hyperdown」参考 |
| 同站加多个号 | 任务列表点「⧉ 复制」，改邮箱密码保存 |
| 手动补签 | 列表「跑一次」；全部补签点「▶ 一键全部签到」 |
| 失败邮件提醒 | 展开「📧 签到失败邮件提醒」卡填 SMTP（QQ 邮箱授权码），点「测发」验证 |

## 目录结构

```
checkin_panel.py       单文件服务（后端 + 内嵌前端页面）
checkin_tasks.json     任务与凭据数据（含密码/token，勿外传）
checkin_panel.log      运行与签到日志
docs/                  项目文档
```

## 环境变量

| 变量 | 用途 | 必填 | 示例 |
| --- | --- | --- | --- |
| `HD_PORT` | 监听端口 | 否（默认 8799） | `8799` |
| `HD_BIND` | 监听地址 | 否（默认 127.0.0.1） | 服务器公网访问时设 `0.0.0.0` |

## 部署

本机常驻或放服务器跑（服务器保持运行才会自动触发定时）。详见 [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)。

## AI 接手指南

1. 先读 [AGENTS.md](AGENTS.md)（行为约定）→ [docs/WIP.md](docs/WIP.md)（当前进度）→ [docs/PROJECT_MEMORY.md](docs/PROJECT_MEMORY.md)（环境/架构/踩坑）
2. 需要理解来龙去脉再读 [docs/BUILD_LOG.md](docs/BUILD_LOG.md)

## 更新规则

- 项目名 / 简介 / 常用命令 / 目录结构 / 环境变量 / 部署地址发生变化时 → 同步更新本文件
