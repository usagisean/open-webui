# Nebula AI (星云 AI) 🌌
**紫祥科技 (Zixiang Digital) - 企业级智能协作中枢**

Nebula AI 是一款专为紫祥数字科技定制的私有化 AI 交互平台。本项目基于高性能异步架构，整合了 **NewAPI** 转发中枢与 **SiliconCloud** 的顶级算力，旨在为公司提供稳定、安全且极速的 AI 助手服务。

## 🏗️ 核心架构 (Architecture)

本系统采用现代化的云原生技术栈，针对后端程序员（C# / Python）的开发习惯进行了深度优化：

* **UI 引擎**: 基于 SvelteKit 的全响应式设计，完美适配 MacBook (M3) 及移动端。
* **API 核心**: 采用 Python FastAPI 异步框架，提供高并发处理能力。
* **模型路由**: 屏蔽底层差异，通过私有化 NewAPI 实例统一调度多种大模型（LLMs）。
* **部署底座**: 全面容器化（Docker Compose），支持一键环境初始化。

## 🛠️ 本地开发环境配置 (Local Development)

针对 Mac (Apple Silicon) 架构及国内网络环境，我们已在 `Dockerfile` 和 `docker-compose.yaml` 中集成了以下优化补丁：

1.  **内存加速**: 强制分配 8GB Node.js 编译内存（`--max-old-space-size=8192`），彻底解决前端构建崩溃问题。
2.  **镜像加速**: 系统包下载自动切换至 **阿里云 (Aliyun)** 镜像源。
3.  **依赖优化**: 使用 `npm install --legacy-peer-deps` 绕过复杂的 Tiptap 依赖版本冲突。

### 快速启动
在项目根目录下执行：
```bash
# 启动星云计划：自动完成构建、编译、部署
docker compose up -d --build

启动后访问：http://localhost:3000

© 2026  | Zixiang Digital Technology Co., Ltd.