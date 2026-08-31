# 滑块验证码图形与 URL 提取

Obscura `fetch` 提供只读的滑块验证码适配器，用于提取当前页面及其活动子 frame 中正在展示的背景图和拼图块。适配器只观察 DOM、已捕获的页面响应和 canvas 来源，不计算答案，不模拟点击或拖放，也不提交验证码。

## 支持范围

| `--captcha-adapter` | 支持的类型 | 输出角色 |
| --- | --- | --- |
| `tianai` | Tianai `SLIDER` | `background`、`puzzle` |
| `go-captcha` | GoCaptcha `Slide`、`SlideRegion` | `background`、`puzzle` |
| `aj-captcha` | AJ-Captcha `blockPuzzle` | `background`、`puzzle` |
| `slider-captcha-js` | slider-captcha-js `slider` | `background`、`puzzle` |
| `auto` | 自动检测以上页面组件 | 按检测到的类型输出 |

不在本适配范围内的类型包括 Tianai `ROTATE`、`CONCAT`、`WORD_IMAGE_CLICK`，AJ-Captcha `clickWord`，以及 GoCaptcha 的点击和旋转模式。

CLI 会在导航前自动安装适配器所需的只读预载。直接使用
`obscura-browser` API 时，调用方必须先执行
`install_captcha_capture_preload(&mut page)`，再导航并启用资源捕获，最后调用
`extract_captcha`。漏装预载会得到 `evidence_complete: false`，且不会退回到可能属于旧题的 API 响应。

## 分别输出图形或 URL

输出图形文件：

```bash
obscura fetch https://example.com/login \
  --captcha-adapter tianai \
  --captcha-images-dir /tmp/captcha-images
```

`--captcha-images-dir` 必须指向不存在或为空的目录。目录中包含解码后的图片，以及 `manifest.json`。图片名形如 `000-tianai-slider-background.png`；清单记录适配器、类型、提取期内生成的非敏感 `challenge_id`、角色、证据来源、frame、MIME、字节数、SHA-256、完整图像对数量和诊断计数，但不会复制诊断正文、页面 URL、接口 URL 或 data URI。新建目录在 Unix 上使用 `0700`，文件使用 `0600`。

只输出 URL/来源报告：

```bash
obscura fetch https://example.com/login \
  --captcha-adapter aj-captcha \
  --captcha-urls-output /tmp/captcha-urls.json
```

使用 `--captcha-urls-output -` 可将 JSON 写到标准输出。目标文件必须尚不存在。报告中的每个 `images[]` 项包含：

- `source_kind` 和 `source_value`：组件原始来源；可能是 HTTP(S)、相对 URL、`data:`、`blob:` 或内联 Base64；
- `challenge_id`：只在本次提取内有效的非敏感分组 ID，用于区分同一 frame 中多个同类组件；
- `resolved_url`：仅在来源能解析为真实的绝对 HTTP(S) 图片 URL 时设置；
- `response_url`：发现该图片字段的 API 响应地址，它不等同于图片 URL；
- `page_frame`：图片所属的 `frame_id` 与 `frame_url`；
- `bytes`、`sha256`、`mime_type`：页面资源捕获或 data URI 解码成功时的材料信息。

顶层 `challenge_groups` 包含已挂载但缺少某个角色的活动组件，`evidence_complete` 表示最终 DOM/响应证据是否完整，`diagnostics` 记录缺失、超限、刷新竞态或仅能部分提取的详细原因。诊断正文只进入用户明确请求的 URL 报告；默认 stderr 和去敏图形清单只显示计数。

AJ-Captcha 的 `/captcha/get` 属于 `response_url`，其 `originalImageBase64` 和 `jigsawImageBase64` 是图片来源；适配器不会把接口地址伪装成图片 URL，也不会输出 `token` 或 `secretKey`。

两种输出可以同时请求：

```bash
obscura fetch https://example.com/login \
  --captcha-adapter go-captcha \
  --captcha-images-dir /tmp/captcha-images \
  --captcha-urls-output /tmp/captcha-urls.json
```

此时 URL 报告中的 `image_path` 会关联已写入的图形文件。URL 报告必须位于图形目录之外。`--captcha-adapter` 至少需要一个输出参数，且验证码输出模式不能与常规 `--dump`、`--file`、`--output`、`--assets-dir`、`--screenshot` 或可执行任意页面脚本的 `--eval` 同时使用。

默认最多保留 64 MiB、512 个响应资源，可用 `--captcha-max-bytes` 和 `--captcha-max-resources` 调整。达到限制时结果会在 `diagnostics` 中说明；为避免刷新后同 URL 的旧响应被误作当前图形，发生任何捕获省略、最终快照时仍有资源请求，或当前 DOM 图片尚未成功解码时，不会用旧响应记录补全对应图片/API 来源。当前 DOM 中的 URL 仍可进入 URL 报告。适配器不会绕过页面自身的网络策略另行下载图片。

如果同一 frame 和 URL 出现内容不同的多次图片响应，或没有 DOM 时捕获到多个不同的 API challenge generation，完成顺序不足以证明哪一个属于当前题目。验证码接口即使只改变 timestamp/nonce 查询参数，也按同一 origin/path 的刷新端点进行竞态检查。适配器会保守返回 `evidence_complete: false` 和非零状态，而不会猜测“最后完成”的响应就是最新题目。即使只捕获到一个完整 API 图形对，只要最终没有对应的活动 DOM，材料也会作为未验证的 partial 输出并返回非零状态：完全卸载的旧组件与真正 API-only 集成在最终快照中不可区分。页面中识别到的同厂商隐藏残留组件或可见非滑块组件会直接抑制 API-only 回退，避免旧的滑块响应在弹窗关闭后复活，或覆盖当前点击/旋转题。

GoCaptcha 的 `Slide` 与 `SlideRegion` 使用相同响应字段；当活动 DOM 可见时适配器会准确输出 `slide` 或 `slide_region`。仅有 API 响应、没有可识别 DOM 时，显式 `go-captcha` 模式会保守标记为 `slide_or_slide_region`，不会猜测具体变体，并按上述规则标为未验证的 partial。

## URL 报告属于敏感数据

URL 报告可能包含完整 data URI、带签名或会话参数的图片 URL、页面/frame URL，以及验证码 API 地址。它应按凭据或会话材料管理：限制文件权限和日志可见性，避免提交到版本库，不要直接粘贴到公开问题或 CI 日志。只需要图形时，优先仅使用 `--captcha-images-dir`；其中的 `manifest.json` 是去敏清单。验证码模式默认抑制普通页面 URL/标题日志，并在未传 `--verbose` 时忽略 `RUST_LOG`，防止环境变量重新开启含 URL 的内部日志。显式启用 `--verbose` 会恢复详细运行日志，因此同样应视为可能包含敏感 URL。

## slider-captcha-js local canvas 限制

slider-captcha-js 的 request/server 模式会把 `bgUrl` 与 `puzzleUrl` 作为两个 `<img>` 插入页面，通常可以完整输出图形和来源。

local `imageUrl`/default 模式则通过一个临时 `Image` 绘制三个 canvas。当前 Obscura 渲染器不能可靠地把 `HTMLImageElement` 经 `drawImage` 栅格化到 canvas，且 puzzle path/clip 仍不完整。预加载的只读 provenance 钩子可以保留原始背景来源，资源捕获也可能取得背景字节，但适配器不会把不完整 canvas 伪装成生成后的拼图图形。遇到这种情况，输出会是 partial：URL 报告保留可取得的背景材料和详细 `diagnostics`，去敏图形清单保留背景文件与诊断计数；因为没有完整的 `background+puzzle` 图形对，命令返回非零状态。

该限制不改变只读边界：适配器不会截图求解、生成拖动轨迹、点击或提交挑战。
