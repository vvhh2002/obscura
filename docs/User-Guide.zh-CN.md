# Obscura Release 中文使用手册

本手册面向直接下载 GitHub Release 二进制文件的用户，介绍安装、页面抓取、
最终页面资源归档、批量任务以及 CDP 接入。Obscura 自带 Rust/V8 浏览器运行时，
这些场景不要求本机安装 Chrome 或 Node.js；只有 Puppeteer/Playwright 接入示例
需要 Node.js 客户端。

> 请只访问你有权访问和自动化的页面，并遵守网站条款、robots.txt 以及当地法律。

## 1. 选择下载文件

先按操作系统和 CPU 选择文件名前缀：

| 系统 | CPU | Release 文件名前缀 |
| --- | --- | --- |
| Linux | x86_64 / AMD64 | `obscura-x86_64-linux` |
| Linux | ARM64 / aarch64 | `obscura-aarch64-linux` |
| macOS | Apple Silicon | `obscura-aarch64-macos` |
| macOS | Intel | `obscura-x86_64-macos` |
| Windows | x86_64 / AMD64 | `obscura-x86_64-windows` |

再按功能选择后缀：

| 文件名后缀 | 截图、PDF、响应资源归档 | Stealth TLS 传输与 tracker blocking | 建议用途 |
| --- | --- | --- | --- |
| 无后缀 | 支持 | 不包含 | 一般用途，推荐默认选择 |
| `-stealth` | 支持 | 包含 | 需要一致浏览器指纹或 stealth 传输 |
| `-no-render` | 不支持 | 不包含 | 只需 DOM、JS、原始响应或 CDP 基础能力 |
| `-no-render-stealth` | 不支持 | 包含 | 不截图、不归档，但需要 stealth |

例如，Apple Silicon Mac 的默认包是
`obscura-aarch64-macos.tar.gz`，Windows stealth 包是
`obscura-x86_64-windows-stealth.zip`。

每个压缩包都包含：

- `obscura`（Windows 为 `obscura.exe`）：主程序；
- `obscura-worker`（Windows 为 `obscura-worker.exe`）：并行 `scrape` 使用的工作进程；
- `obscura-user-guide-zh-CN.md`：本手册。

运行 `scrape` 时不要把两个可执行文件分开。Linux 官方包要求 glibc 2.35 或
更新版本；它不是 musl 全静态包。

同一 Release 页面还会提供单独的 `ai_slide_matcher-v*` 五平台附件，用于离线
计算滑块图片的目标坐标。matcher 不会重复放进四种 Obscura 变体压缩包；请按
操作系统和 CPU 另行下载。matcher 平台包只包含原生可执行文件、运行说明、示例
图片、`LICENSE` 和 `THIRD_PARTY_NOTICES`，不包含源代码或实现文档压缩包。
它也不会自动拖动或提交验证码；调用方仍需在获得授权的系统中处理交互。
Release 根目录中的 `ai_slide_matcher-TEST-REPORT.json` 与
`ai_slide_matcher-PROVENANCE.txt` 提供公开测试门禁结论和固定源码 revision，
但不包含私有源码内容。

## 2. 校验、解压与首次运行

Release 同时提供 `SHA256SUMS`。建议先下载它，再校验所选压缩包。

Linux：

```bash
grep 'obscura-x86_64-linux.tar.gz$' SHA256SUMS | sha256sum -c -
tar xzf obscura-x86_64-linux.tar.gz
chmod +x obscura obscura-worker
./obscura --version
```

macOS Apple Silicon：

```bash
shasum -a 256 obscura-aarch64-macos.tar.gz
# 将输出与 SHA256SUMS 中的对应值比较
tar xzf obscura-aarch64-macos.tar.gz
chmod +x obscura obscura-worker
./obscura --version
```

Windows PowerShell：

```powershell
Get-FileHash .\obscura-x86_64-windows.zip -Algorithm SHA256
# 将输出与 SHA256SUMS 中的对应值比较，然后解压
Expand-Archive .\obscura-x86_64-windows.zip -DestinationPath .\obscura
.\obscura\obscura.exe --version
```

最小可用性检查：

```bash
./obscura fetch https://example.com --eval 'document.title'
```

Windows 下把后续示例中的 `./obscura` 换成 `.\obscura.exe`。

## 3. 单页抓取：`fetch`

### 3.1 获取不同形式的页面内容

```bash
# 最终 DOM 的 HTML（默认）
./obscura fetch https://example.com

# 纯文本、链接或 Markdown
./obscura fetch https://example.com --dump text
./obscura fetch https://example.com --dump links
./obscura fetch https://example.com --dump markdown --output page.md

# 原始 HTTP 响应体；二进制安全，并绕过 DOM/JS 层
./obscura fetch https://example.com/image.png --dump original --output image.png

# 等待 CSS 选择器出现后再输出页面文本（当前不会裁剪到该区域）
./obscura fetch https://example.com --selector 'main' --dump text
```

### 3.2 执行 JavaScript

```bash
./obscura fetch https://example.com \
  --eval '({title: document.title, url: location.href})'
```

对象、数组等表达式结果以 JSON 输出，字符串直接输出。可用 `--timeout 60`
调整导航和表达式各自的超时。

### 3.3 截图

截图要求默认包或 `-stealth` 包：

```bash
./obscura fetch https://example.com --screenshot page.png
```

`-no-render` 变体会明确拒绝截图，不会生成空白文件。

### 3.4 等待条件

```bash
./obscura fetch https://example.com --wait-until load
```

| `--wait-until` 值 | 返回时机 |
| --- | --- |
| `domcontentloaded` | HTML 解析达到 DOMContentLoaded 边界；可能早于后续脚本完成 |
| `load` | 标准 Window load 阻塞集合完成并触发 `window.load`（默认） |
| `networkidle2` | load 后活动请求不超过 2 个并持续 500 ms |
| `networkidle0` | load 后没有活动请求并持续 500 ms |

`--wait N` 是选择等待边界后的观察时间。显式提供时是固定等待；未提供时，
普通抓取使用最多 5 秒的自适应 settle。资源归档未提供 `--wait` 时使用固定
5 秒观察窗口。

## 4. 归档最终页面及其资源

资源归档不需要 CDP 或 Chrome，但必须使用带渲染能力的默认包或 `-stealth`
包。下面的命令会跟随 HTTP 重定向和观察窗口内的 JavaScript 顶层导航，并只
保留最终 document generation 所属的响应：

```bash
./obscura --stealth fetch https://example.com/app \
  --dump assets \
  --assets-dir ./example-assets \
  --output ./example-assets.ndjson \
  --wait-until load \
  --wait 5 \
  --timeout 60
```

不需要 stealth 时删除 `--stealth`。目标目录必须不存在或为空，并且不能是
符号链接；`--output` 与 `--screenshot` 必须放在归档目录之外。

归档结构如下：

```text
example-assets/
├── manifest.json       # 机器可读清单与完整性结论
├── page.html           # 最终顶层 DOM
├── frames/             # 可序列化的实时子 frame DOM
└── resources/          # 按 SHA-256 内容寻址的原始响应体
```

`manifest.json` 中最重要的字段：

- `final_url`：最终提交页面的 URL；
- `complete`：在配置的捕获边界和限制内是否发现已知缺失；
- `incomplete_reasons`：失败、超时、安全上限或未完成工作的诊断；
- `assets`：请求 URL、最终 URL、重定向链、frame、类型、状态、MIME、大小、
  SHA-256 和归档路径。

自动化程序应同时检查进程退出码、manifest `version` 和 `complete`，不要通过
解析 `incomplete_reasons` 文本做稳定协议判断。

```bash
jq '{version, final_url, complete, incomplete_reasons}' \
  example-assets/manifest.json
```

`--dump assets` 输出的 NDJSON 是兼容性 URL 清单；`--assets-dir` 中的 manifest
才是按实际网络响应记录的权威归档。可用以下选项限制空间：

```bash
--assets-max-resources 4096
--assets-max-bytes 536870912
```

## 5. Stealth、代理与持久状态

只有 `-stealth` 或 `-no-render-stealth` 包包含 stealth 传输特性。启用方式：

```bash
./obscura --stealth fetch https://example.com
./obscura --proxy http://127.0.0.1:8080 fetch https://example.com
./obscura --proxy socks5://127.0.0.1:1080 fetch https://example.com
```

Cookie 可跨运行保存：

```bash
./obscura --storage-dir ./browser-profile fetch https://example.com
```

默认禁止访问 loopback、RFC1918 和 link-local 地址，以降低 SSRF 风险。仅在
明确需要访问可信本地服务时启用：

```bash
./obscura --allow-private-network fetch http://127.0.0.1:3000
```

如需遵守 `robots.txt`，增加全局选项 `--obey-robots`。

## 6. 批量抓取：`scrape`

`scrape` 并行执行同一段 JavaScript；`obscura-worker` 必须与主程序位于同一
目录。

```bash
./obscura scrape \
  https://example.com https://example.org \
  --eval '({url: location.href, title: document.title})' \
  --concurrency 2
```

从标准输入读取 URL：

```bash
cat urls.txt | ./obscura scrape - \
  --eval 'document.title' \
  --concurrency 10
```

每个 URL 的默认超时为 60 秒，可用 `--timeout` 修改。

## 7. 启动 CDP 服务

```bash
./obscura serve --host 127.0.0.1 --port 9222
```

默认 WebSocket 地址为 `ws://127.0.0.1:9222`。不要无认证地把 CDP 端口暴露到
公网；CDP 客户端几乎等同于拥有浏览器进程控制权。

Puppeteer 使用 `puppeteer-core`：

```js
const puppeteer = require('puppeteer-core');
const browser = await puppeteer.connect({
  browserWSEndpoint: 'ws://127.0.0.1:9222',
});
const page = await browser.newPage();
await page.goto('https://example.com', { waitUntil: 'load' });
console.log(await page.title());
await browser.disconnect();
```

Playwright 必须使用 `connectOverCDP`，不能使用它自己的 `connect` 协议：

```js
const { chromium } = require('playwright');
const browser = await chromium.connectOverCDP('ws://127.0.0.1:9222');
const context = browser.contexts()[0] || await browser.newContext();
const page = await context.newPage();
await page.goto('https://example.com', { waitUntil: 'load' });
console.log(await page.title());
await browser.close();
```

原始 CDP `Page.navigate` 未指定 `waitUntil` 时默认等待
`domcontentloaded`。需要生命周期事件的客户端应先启用 Page domain，并调用
`Page.setLifecycleEventsEnabled({enabled: true})` 后监听事件；Obscura 也接受原始
`Page.navigate` 的扩展字段 `waitUntil: "load"`。

## 8. MCP 服务

默认 stdio 传输：

```bash
./obscura mcp
```

HTTP 传输：

```bash
./obscura mcp --http --host 127.0.0.1 --port 3000
```

只有确实需要远程连接时才绑定 `0.0.0.0`，并配置允许的 Origin。带渲染能力的
包会额外提供截图和 PDF 工具。

## 9. 常见问题

### 截图或资源归档提示缺少 render

你下载了 `-no-render` 变体。改用无后缀默认包或 `-stealth` 包。

### `scrape` 找不到 worker

确认 `obscura-worker`（Windows 为 `obscura-worker.exe`）和主程序在同一目录，
并且两者来自同一个 Release 压缩包。

### Linux 报 GLIBC 版本过低

官方 Linux Release 要求 glibc 2.35+。升级发行版，或在目标环境中按仓库的
`docs/Build-from-source.md` 自行构建。

### 本地地址被拒绝

这是默认 SSRF 防护。只对可信目标增加 `--allow-private-network`，不要对不可信
用户提供的 URL 全局开放私网访问。

### 归档已经生成，但命令返回失败

读取 `manifest.json`。当资源失败、超时、超过数量/字节上限、frame 无法序列化
或仍有已知未完成工作时，Obscura 会保留可诊断的部分归档，将
`complete` 设为 `false` 并返回非零退出码，不会把不完整结果伪装成成功。

## 10. 当前边界

- Service Worker、原生音视频播放和部分长尾 Web API 尚未实现；
- 音视频会做资源选择和元数据加载，但不做编解码或播放；
- PDF 是栅格输出，文本不可选择，也不支持完整 CSS paged media；
- frame 内 async classic 的网络完成竞态、module 准备并发度以及部分复杂 CSS/
  compositor 效果与 Chromium 仍有差异；
- 页面可以把工作推迟到未来 timer、用户手势或 lazy-scroll；任何有限等待策略
  都不能证明页面将来永远不再发起请求。

查看当前二进制的精确参数时，以内置帮助为准：

```bash
./obscura --help
./obscura fetch --help
./obscura scrape --help
./obscura serve --help
./obscura mcp --help
```
