# 旧系统登录与滑块验证码转换网关

`legacy-gateway` 用于把一个管理员预先配置的旧系统登录页转换为新的登录界面。它识别旧页面中的用户名、密码和一种活动滑块验证码，让用户在新界面中输入账号并手动拖动；登录成功后，同一个 Obscura `BrowserContext + Page` 继续保存旧系统 Cookie，并通过新页面中的同源 iframe 显示可交互的远程视口。

支持下表四类组件，且只支持它们的 slide（滑动）模式；点选、文字、旋转、拼图点击、API-only 和仅存在于隐藏 DOM 的模式均不在转换范围内：

| 组件 | 支持模式 | 原控件事件入口 |
| --- | --- | --- |
| Tianai | `SLIDER` | `#tianai-captcha-slider-move-btn` |
| GoCaptcha | `Slide` | `.gc-drag-block` |
| AJ-Captcha | `blockPuzzle` | `.verify-move-block` |
| slider-captcha-js | `slider`（server/local live widget） | `.slider-captcha-thumb` |

GoCaptcha `SlideRegion` 是允许纵横移动的二维 drag-drop 模式，不属于本次仅支持的水平 slide 范围；网关会明确拒绝它，而不会把 `.gc-tile` 误识别为普通滑块。

网关不计算答案，也没有“提交最终距离”接口。新 UI 把一次真实操作产生的 `down → move+ → up` 样本作为一个有界批次发送；批次携带当前验证码 `generation`、严格递增的序号、归一化坐标和相对时间。服务端先验证 generation 与当前 lease 一致，再按受限的原始样本间隔把整条轨迹重放到旧页面中已保留的原控件。它不会根据终点补点、平滑轨迹或推导缺口距离。这样 Tianai 的轨迹校验、AJ-Captcha 的 AES/二次校验，以及 GoCaptcha、slider-captcha-js 的应用回调仍由旧系统原代码完成。

## 两阶段接入：发现后按配置运行

需要长期集成时建议运行两次，但只需要做一次发现，不是每次用户登录都运行两次。

第一次以发现模式启动，管理员在转换 UI 中完成一次真实登录：

```bash
obscura legacy-gateway https://legacy.example/login \
  --discover-output ./legacy-login.json \
  --success-selector '#application-shell' \
  --subject-selector '.current-user'
```

发现模式按以下顺序建立可持久化结果：

1. 在登录前状态中，要求 `--success-selector` 在同一文档代次连续两次均“无可见匹配且不存在多匹配歧义”。单个隐藏候选允许作为登出基线（`matched=false`），但两个及以上候选会 fail closed；这里不要求该 selector 对应的节点从 DOM 中完全不存在。
2. 管理员输入凭据并手动完成滑块后，要求 success selector 在全部 frame 中恰好有一个连接且可见的匹配，并在同一文档代次连续两次命中；配置了 subject selector 时，它也必须与认证状态一致。
3. 认证成立后，网关另建一个全新的、没有 Cookie 和存储的登出 `BrowserContext + Page`，重新加载登录 URL 做 preflight。该页面必须得到完全相同的具体验证码 adapter/mode、字段标签和稳定唯一 selector；success selector 也必须再次连续两次“无可见匹配且不存在多匹配歧义”，同样允许一个隐藏候选、拒绝多个候选。
4. 在把稳定元数据交给 JSON 写入器之前，网关销毁已认证的发现上下文和 fresh-context preflight 上下文，并换入空白隔离上下文。因此发现时取得的 Cookie、页面状态和验证码不会进入第二阶段；即使写文件失败，也不能继续使用发现会话，必须重新运行发现。
5. 通过全部检查后，以 create-new 的原子方式写入 schema version 1 JSON。`--discover-output` 的父目录必须存在，目标文件必须不存在；同名普通文件、目录或符号链接都不会被截断或覆盖。

审核 JSON 后，第二次直接按配置启动：

```bash
obscura legacy-gateway --config ./legacy-login.json
```

此后每个用户会话仍实时打开旧登录页并获取当次新验证码。JSON 不是登录会话快照，也不复用发现阶段的验证码或 Cookie。

### version 1 JSON 的内容边界

发现结果的结构如下；具体 selector 和标签来自实际旧页面：

```json
{
  "schemaVersion": 1,
  "loginUrl": "https://legacy.example/login",
  "captchaAdapter": "gocaptcha-slide",
  "selectors": {
    "username": "input[name=\"username\"]",
    "password": "input[name=\"password\"]",
    "submit": "button[type=\"submit\"]"
  },
  "authentication": {
    "successSelector": "#application-shell",
    "subjectSelector": ".current-user"
  },
  "detection": {
    "captchaMode": "slide",
    "usernameLabel": "账号",
    "passwordLabel": "密码",
    "submitLabel": "登录"
  },
  "origins": {
    "navigation": ["https://legacy.example"],
    "resources": ["https://legacy.example", "https://static.example"]
  },
  "viewport": { "width": 1280, "height": 720 },
  "sessionTtlSeconds": 1800,
  "allowInsecureLegacyHttp": false,
  "userAgent": "Legacy Browser/1.0"
}
```

JSON 保存：

- 固定登录 URL；
- 发现出的具体 adapter 及其 mode，`captchaAdapter` 不会保存为 `auto`；
- 用户名、密码和可选提交控件的稳定唯一 selector，以及对应的显示标签；
- success selector 和可选的 subject selector；
- 完整、规范化并按 scheme、host、有效端口精确匹配的 navigation/resource origin 集合；
- 固定 viewport、绝对 session TTL、HTTP 明示 opt-in，以及发现时有效的可选 User-Agent。

JSON 不保存：

- 用户名、密码或其他凭据；
- Cookie、Web Storage、启动 bearer、session/provider token、`secretKey`、`captchaVerification`；
- 动态验证码获取/校验 URL、nonce、ticket 或请求体；
- 验证码图片、Canvas 内容或图片/画布指纹。

动态 URL 和图片指纹仍只属于当前题目的内存 lease，刷新后立即失效。manifest 对未知字段和非法值采用拒绝策略，不能通过自行增加字段把运行时秘密塞入配置。

### `--config` 的固定项与运行时项

serve 模式在接收任何凭据之前，会把新加载的登出页与 JSON 中的 adapter、mode、标签和 selector 做精确比对。节点缺失、结果不唯一、组件换型或标签/selector 漂移都会 fail closed 并报告配置漂移；它不会退回 `auto`、静默接受新页面或就地改写 JSON。旧系统改版后应生成一个新的目标文件，审核后再切换配置。

`--config FILE` 与以下参数互斥：`LEGACY_URL`、`--discover-output`、`--captcha-adapter`、`--username-selector`、`--password-selector`、`--submit-selector`、`--success-selector`、`--subject-selector`、`--allowed-navigation-origin`、`--allowed-resource-origin`、`--allow-insecure-legacy-http`、`--viewport-width`、`--viewport-height`、`--session-ttl`，以及写在子命令后的本地 `--user-agent`。

`--host` 和 `--port` 仍是第二阶段的运行时参数。进程级网络参数 `--proxy`、`--allow-private-network` 也仍可使用。若确实需要临时覆盖 manifest 中的可选 UA，可把顶层 `--user-agent` 放在子命令之前，例如 `obscura --user-agent 'UA/1.0' legacy-gateway --config ./legacy-login.json`；该值优先于 JSON。`--stealth` 仍因绕过精确资源 origin 拦截器而被拒绝。

如果既不传 `--discover-output`，也不传 `--config`，原有一次性行为保持不变：仍使用 `obscura legacy-gateway LEGACY_URL --success-selector ...`，启动时实时识别页面，在本进程中保留登录后的上下文，不读取也不生成 JSON。

## 为什么 iframe 显示的是远程视口

Obscura 登录取得的 HttpOnly/Domain/SameSite Cookie 属于服务端的 CookieJar。新系统域名不能替旧系统域名写入这些 Cookie；直接加载旧 URL 的跨域 iframe 还可能被 `X-Frame-Options`、CSP `frame-ancestors` 或第三方 Cookie 策略阻止。因此新 UI 中的同源 iframe 默认加载网关自己的 `/view` 页面，而不是旧系统 URL：它轮询同一个 Obscura `BrowserContext + Page` 的远程 PNG 视口并转发点击、拖动和文本输入。登录、登录后页面以及 iframe 画面始终复用这一份 Obscura 会话，所以旧系统在登录过程中设置的 Cookie 和页面状态自然延续；这不是把 Cookie “同步”或复制到新系统浏览器。旧 Cookie、验证码 token、`secretKey` 和 `captchaVerification` 都不会发给前端。

认证后的远程视口也会把有界、限频并按显示比例换算的鼠标滚轮样本转发给固定旧页面；命中子 frame 或 `overflow` 滚动容器时沿用 Obscura 的 wheel 命中与滚动语义，因此长页面和嵌套滚动区域无需暴露旧 URL 即可操作。

如果必须让浏览器 iframe 直接加载真实旧 URL，旧系统需要提供一次性 SSO/session-handoff：由旧域消费一次性 code 并自行设置 Cookie。网关不会复制 Cookie、剥离 CSP/XFO，也不会实现通用 HTML 反向代理。

## 识别与失效规则

登录自动识别要求页面中只有一个可见、启用的密码输入框，并能在同一 form 中唯一确定用户名字段和提交控件。复杂旧页可通过启动参数提供三个固定 CSS selector；selector 由管理员配置，HTTP 客户端不能提交任意 selector、URL、header 或脚本。

一次交互 lease 绑定：

- 当前 `document_generation` 和稳定 frame id；
- 原登录字段、form、验证码根节点和 drag 起点的对象身份；
- 组件类型、图片/画布指纹和根布局；
- 服务端随机 nonce。

页面导航、frame detach、控件替换、验证码图片刷新、根布局变化或轨迹顺序错误会立即使 lease 失效。此时 UI 必须重新扫描，不能继续使用旧题或旧节点。API-only、隐藏残留、非 slide 模式、缺少活动控件、多个登录表单或多个验证码均 fail closed。

## 登录状态

验证码 `mouseup` 或供应商接口返回 200 不等于登录成功。部署时必须配置只有登录后才唯一可见的 selector；它必须在全部 frame 中只有一个连接且可见的匹配，并在同一文档代次连续两次探测成功。满足这些条件后，网关才把新界面状态切换为 `authenticated`、轮换新的网关会话并启用 iframe 远程视口；隐藏的预渲染 shell 或瞬时插入不会开放会话。可选的 subject selector 仅用于显示，不能据此授予新系统角色；生产环境应把同源、已认证的身份接口返回值映射到预先绑定的新系统账号。

## 安全边界

- 启动配置只允许一个固定 HTTP(S) URL；默认要求 HTTPS、拒绝 URL 内嵌账号密码和 fragment。
- 网关默认且强制绑定 loopback。生产接入应放在有 TLS、身份认证和逐应用 egress allowlist 的受控前置服务后。
- 启动 URL 和每次顶层文档导航必须属于精确 navigation-origin allowlist。脚本、样式、图片、字体、子 frame 文档、fetch/XHR 及其重定向跳转必须属于独立的精确 resource-origin allowlist；允许一个 SSO 导航 origin 不会同时允许它提供资源或接收接口请求。两类 origin 均按 scheme、host 和有效端口匹配。`--allow-private-network` 是 Obscura 的宽泛开发开关，不可替代逐应用 CIDR/DNS 校验和主机层 egress 防火墙。
- 启动 token 只存在 URL fragment，API 还要求精确 Origin、HttpOnly/SameSite 会话 Cookie 和自定义 token header；页面与图片响应使用 `no-store` 和严格 CSP。
- 请求头、请求体、连接数、轨迹点数、坐标、时长和速率都有硬上限；密码、旧 Cookie、provider secret、HTML 和截图不会写入日志或持久化目录。
- 转发的是合成 DOM 事件，不能在密码学意义上证明“真人”。如供应商或合规规则要求浏览器原生可信用户激活，应使用旧系统原生页面或其官方 SSO/handoff，而不是把 `isTrusted` 当作证明。

该功能需要带 `render` feature 的构建，以获得真实布局几何和 PNG 远程视口。

## 本地确定性 E2E 页面

仓库内的 `crates/obscura-legacy-gateway/fixtures/legacy-login.html` 是一个不依赖外网的 Tianai slide 风格页面。它包含唯一登录表单、真实 `mousedown/mousemove/mouseup` 监听、登录后的唯一 `#authenticated` 探针、`#legacy-subject` 显示身份，以及可在远程视口中验证点击和文本输入的控件。可在仓库根目录用两个终端启动：

```bash
python3 -m http.server 38080 --directory crates/obscura-legacy-gateway/fixtures

cargo run --release --features render -p obscura-cli -- \
  legacy-gateway http://127.0.0.1:38080/legacy-login.html \
  --allow-insecure-legacy-http \
  --allow-private-network \
  --captcha-adapter tianai \
  --success-selector '#authenticated' \
  --subject-selector '#legacy-subject'
```

`--session-ttl` 是绝对期限，不会因轮询或输入而滑动续期；首次打开 UI 时开始计时，并在认证成功轮换本机会话时重新开始。到期后的第一个请求会永久注销该进程的启动 token、丢弃原 `BrowserContext + Page`（包括旧 Cookie 与存储）、换入空白隔离上下文并返回 HTTP 410。旧启动 URL 不能重新签发会话；需要重新运行 `legacy-gateway` 才能再次登录。
