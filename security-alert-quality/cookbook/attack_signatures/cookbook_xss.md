
# XSS注入误报识别 Cookbook

## 目录

- [快速判定摘要](#快速判定摘要)
- [技能概述](#技能概述)
- [角色定位](#角色定位)
- [分析输入](#分析输入)
  - [数据来源](#数据来源)
  - [编码绕过识别](#编码绕过识别)
- [误报判定场景](#误报判定场景)
  - [场景检查优先级](#场景检查优先级)
  - [场景1：现代前端框架转义](#场景1现代前端框架转义)
  - [场景2：业务逻辑阻断](#场景2业务逻辑阻断)
  - [场景3：富文本编辑器](#场景3富文本编辑器)
  - [场景4：安全DOM操作](#场景4安全dom操作)
  - [场景5：严格CSP策略](#场景5严格csp策略)
  - [场景6：第三方回调/特殊格式](#场景6第三方回调特殊格式)
  - [场景7：服务端模板语法](#场景7服务端模板语法)
  - [场景8：不可达代码路径](#场景8不可达代码路径)
  - [场景9：Cookie属性误判](#场景9cookie属性误判)
  - [场景10：JSONP回调注入](#场景10jsonp回调注入)
  - [场景11：Content-Type不匹配](#场景11content-type不匹配)
  - [场景12：浏览器XSS过滤器](#场景12浏览器xss过滤器)
  - [场景13：JavaScript字符串/模板字面量中的内容](#场景13javascript字符串模板字面量中的内容)
  - [场景14：CSS样式中的content属性](#场景14css样式中的content属性)
  - [场景15：SVG/MathML合法标签](#场景15svgmathml合法标签)
  - [场景16：URL片段标识符](#场景16url片段标识符)
  - [场景17：数据URI schemes](#场景17数据uri-schemes)
  - [场景18：iframe sandbox限制](#场景18iframe-sandbox限制)
  - [场景19：表单action合法跳转](#场景19表单action合法跳转)
  - [场景20：meta refresh合法跳转](#场景20meta-refresh合法跳转)
  - [场景21：图片alt/title属性](#场景21图片alttitle属性)
  - [场景22：文件名/路径中的特殊字符](#场景22文件名路径中的特殊字符)
  - [场景23：WebSocket消息数据](#场景23websocket消息数据)
  - [场景24：LocalStorage/SessionStorage数据](#场景24localstoragesessionstorage数据)
  - [场景25：HTTP参数污染（HPP）](#场景25http参数污染hpp)
  - [场景26：GraphQL参数误报](#场景26graphql参数误报)
  - [场景27：WebAssembly模块注入误报](#场景27webassembly模块注入误报)
  - [场景28：JSON解析错误场景](#场景28json解析错误场景)
  - [场景29：文件上传MIME类型混淆](#场景29文件上传mime类型混淆)
  - [场景30：文件名未被渲染到HTML属性](#场景30文件名未被渲染到html属性)
- [非误报判定标准](#非误报判定标准)
  - [真实XSS告警特征](#真实xss告警特征)
- [判定流程图](#判定流程图)
- [判定示例](#判定示例)
  - [示例1：误报 - Vue框架转义](#示例1误报---vue框架转义)
  - [示例2：误报 - Content-Type不匹配](#示例2误报---content-type不匹配)
  - [示例3：误报 - 严格CSP策略](#示例3误报---严格csp策略)
  - [示例4：真实告警 - 反射型XSS](#示例4真实告警---反射型xss)
  - [示例5：真实告警 - DOM型XSS](#示例5真实告警---dom型xss)
  - [示例6：真实告警 - 存储型XSS](#示例6真实告警---存储型xss)
- [分析报告输出](#分析报告输出)
  - [判定结果格式](#判定结果格式)
  - [使用说明](#使用说明)
- [注意事项](#注意事项)

## 快速判定摘要

以下为脚本/LLM自动判定使用的结构化规则，详细分析见后续章节。

### 真阳性指标

| 置信度 | 特征 | 说明 |
|--------|------|------|
| 高 | 请求含 `<script>` 标签 + `alert(`/`prompt(`/`confirm(` | 经典XSS验证payload |
| 高 | 请求含 `onerror=`/`onload=` + `javascript:` 或表达式 | 事件处理器注入 |
| 高 | 请求含 `<img.*onerror=` / `<svg.*onload=` | HTML标签事件注入 |
| 高 | 请求含 `document.cookie` / `document.write` | 信息窃取/DOM操作 |
| 高 | 请求含 `String.fromCharCode` + 编码字符串 | JS编码绕过 |
| 中 | 请求含 `<iframe`, `<object`, `<embed` 标签 | HTML注入（可能用于XSS） |
| 中 | 响应体中回显了 `<script>` 标签或事件处理器 | 反射型XSS确认 |
| 低 | 请求含HTML标签但响应为404 | 扫描探测非实际漏洞 |

### 误报指标

| 置信度 | 特征 | 说明 |
|--------|------|------|
| 高 | `<script>` 出现在JSON/XML数据传输中 | 结构化数据中的字面量 |
| 高 | 正常WAF/CDN页面自身的`<script>`标签 | CDN/WAF安全页 |
| 中 | `onerror=`/`onload=` 出现在合法JS框架代码中 | 前端框架正常代码 |
| 中 | 搜索引擎爬虫缓存页面中的XSS payload | 爬虫缓存的攻击页面 |
| 低 | 请求体中含HTML标签但URL是静态资源路径 | 可能是误触发 |

### 判定优先级

1. 先查 `<script>` + `alert(` → 最经典的XSS探测，高置信度真阳性
2. 再查事件处理器（`onerror`, `onload`） → 需结合上下文判断
3. 检查响应体是否回显 → 反射型XSS的关键证据
4. 区分JSON中的字面量 vs 实际注入参数值

## 技能概述

网络安全设备通过内置规则检测XSS注入攻击，但由于规则配置、检测逻辑、业务场景等因素，容易产生大量误报。本cookbook提供系统化的XSS注入误报识别方法，帮助分析人员准确判定告警真实性。

## 角色定位

你是一名专业的安全告警研判分析师，专注于XSS类告警的误报识别与判定。

## 分析输入

### 数据来源

从网络安全设备告警日志CSV中提取以下关键字段：

| 字段 | 用途 | 说明 |
|------|------|------|
| 请求体 | 分析注入Payload | 包含用户输入的参数内容 |
| 响应体 | 判断注入结果 | 包含服务器返回内容，用于验证注入是否成功 |
| 响应码 | 判断请求状态 | 200/404/500等状态码分析 |
| 响应头 | 分析安全策略 | CSP、Content-Type等安全相关头部 |
| 载荷 | 分析流量特征 | 网络流量中的原始数据 |

### 编码绕过识别

在分析请求体时，必须检测以下编码方式（按检测优先级排序）：

| 优先级 | 编码类型 | 检测规则 | 解码方法 | 示例 |
|--------|----------|----------|----------|------|
| 1 | URL编码 | `/%[0-9A-Fa-f]{2}/` | urldecode | `%3Cscript%3E` → `<script>` |
| 2 | Base64 | `/^[A-Za-z0-9+/]+=*$/` 且len%4==0 | base64_decode | `PHNjcmlwdD4=` → `<script>` |
| 3 | Hex编码 | `\\x[0-9A-Fa-f]{2}` | hex2bin | `\x3C\x73\x63\x72\x69\x70\x74\x3E` → `<script>` |
| 4 | Unicode编码 | `\\u[0-9A-Fa-f]{4}` | unicode_decode | `\u003C\u0073\u0063\u0072\u0069\u0070\u0074\u003E` → `<script>` |
| 5 | HTML实体编码 | `/&#\d+;|&#x[0-9A-Fa-f]+;/` | html_entity_decode | `&#60;script&#62;` → `<script>` |
| 6 | JavaScript编码 | `\\x[0-9A-Fa-f]{2}` 或 `\\u[0-9A-Fa-f]{4}` | unescape | `\x3Cscript\x3E` → `<script>` |
| 7 | UTF-7编码 | `/^\+[\w\+-]*-\s*$/` | UTF-7解码 | `+ADw-script+AD4-` → `<script>` |
| 8 | 八进制编码 | `\\[0-7]{3}` | octal解码 | `\074script\076` → `<script>` |
| 9 | 混淆Unicode | `\\u\s*[0-9A-Fa-f]{4}\s*` | unicode_decode | `\u 0 0 3 C` → `<` |
| 10 | 双重/多重编码 | 多层编码特征 | 多次解码 | `%253C` → `%3C` → `<` |

**检测流程：**
1. 从请求体提取参数值
2. 按优先级依次检测编码特征
3. 如果匹配，进行解码
4. 记录已解码内容，如解码结果与之前相同则停止（防止解码循环）
5. 对解码后的内容再次检测（处理多重编码）
6. 最多解码10层或直到内容不再变化

**编码检测优先级说明：**
- URL编码优先：Web应用中最常见的编码方式，也是XSS绕过的首选
- Base64次之：常用于参数加密传输，解码后可能触发XSS规则
- Hex编码：常见于JavaScript字符串中的转义
- Unicode编码：常用于绕过关键字过滤
- UTF-7编码：较少见但可能被用于绕过某些过滤机制

## 误报判定场景

### 场景检查优先级

**场景分类说明：**
- **直接验证类**：可通过单次请求响应直接判定，无需额外推断
- **推断类**：需要根据响应特征间接推断前端处理方式，判定置信度相对较低
- **上下文依赖类**：需要结合多个请求或业务上下文判断

当多个误报场景特征同时出现时，按以下优先级判定：

| 优先级 | 场景 | 类型 | 判定依据强度 |
|--------|------|------|-------------|
| 1 | 场景1：现代前端框架转义 | 直接验证 | 最强：框架特征明显 |
| 2 | 场景2：业务逻辑阻断 | 直接验证 | 强：响应码明确 |
| 3 | 场景3：富文本编辑器 | 直接验证 | 强：上下文明确 |
| 4 | 场景4：安全DOM操作 | 直接验证 | 强：API调用明确 |
| 5 | 场景5：严格CSP策略 | 直接验证 | 强：响应头明确 |
| 6 | 场景6：第三方回调/特殊格式 | 直接验证 | 中：来源特征 |
| 7 | 场景7：服务端模板语法 | 直接验证 | 中：语法特征 |
| 8 | 场景8：不可达代码路径 | 推断类 | 中-弱：需分析代码 |
| 9 | 场景9：Cookie属性误判 | 直接验证 | 中：特征明确 |
| 10 | 场景10：JSONP回调注入 | 直接验证 | 中：响应格式明确 |
| 11 | 场景11：Content-Type不匹配 | 直接验证 | 强：响应头明确 |
| 12 | 场景12：浏览器XSS过滤器 | 推断类 | 弱：需浏览器行为 |
| 13 | 场景13：JavaScript字符串/模板字面量 | 直接验证 | 中：语法特征 |
| 14 | 场景14：CSS样式中的content属性 | 直接验证 | 中：CSS语法 |
| 15 | 场景15：SVG/MathML合法标签 | 直接验证 | 中：标签特征 |
| 16 | 场景16：URL片段标识符 | 直接验证 | 中：URL结构 |
| 17 | 场景17：数据URI schemes | 直接验证 | 中：URI格式 |
| 18 | 场景18：iframe sandbox限制 | 直接验证 | 中：属性特征 |
| 19 | 场景19：表单action跳转 | 直接验证 | 中：表单特征 |
| 20 | 场景20：meta refresh合法跳转 | 直接验证 | 中：标签特征 |
| 21 | 场景21：图片alt/title属性 | 直接验证 | 中：属性特征 |
| 22 | 场景22：文件名/路径特殊字符 | 直接验证 | 中：路径特征 |
| 23 | 场景23：WebSocket消息数据 | 推断类 | 弱：需协议分析 |
| 24 | 场景24：LocalStorage数据 | 推断类 | 弱：需存储分析 |
| 25 | 场景25：HTTP参数污染（HPP） | 直接验证 | 中：参数特征 |
| 26 | 场景26：GraphQL参数误报 | 直接验证 | 中：协议特征 |
| 27 | 场景27：WebAssembly模块注入误报 | 直接验证 | 中：格式特征 |
| 28 | 场景28：JSON解析错误场景 | 直接验证 | 中：错误特征 |
| 29 | 场景29：文件上传MIME类型混淆 | 直接验证 | 中：MIME特征 |
| 30 | 场景30：文件名未被渲染到HTML | 直接验证 | 中：使用特征 |

**冲突处理规则：**
- 如果同时匹配多个场景，选择优先级最高的场景
- 如果优先级相同，检查特征是否更加明确
- 对于明显匹配多个场景的情况，标记为"误报（多场景匹配）"并列出所有匹配场景
- 推断类场景的判定结果置信度建议标记为"中"，并在报告中说明推断依据

---

### 场景1：现代前端框架转义

**特征识别：**
- 响应体包含前端框架的插值表达式标记
- 用户输入出现在`{{ }}`、`{ }`、`[()]`等插值表达式中
- 未使用`v-html`、`dangerouslySetInnerHTML`等不安全渲染方式

**误报判定依据：**
1. 检查响应体：包含现代前端框架特征

| 框架 | 插值标记 | 安全属性 | 危险属性 |
|------|----------|---------|---------|
| Vue.js | `{{ }}` | v-text | v-html |
| React | `{ }` | JSX自动转义 | dangerouslySetInnerHTML |
| Angular | `{{ }}` | [()] | innerHTML |
| Svelte | `{ }` | 自动转义 | {@html} |

2. 渲染方式验证：确认使用安全的插值表达式
3. 无危险属性：未使用`v-html`、`dangerouslySetInnerHTML`等

**典型示例：**
```
响应体:
<div>{{ userInput }}</div>
<script>
  const userInput = '<script>alert(1)</script>';
</script>
说明: Vue的插值表达式会自动转义，不会执行XSS
```

**判定逻辑：**
```
IF 响应体包含前端框架插值标记
AND 用户输入出现在插值表达式中
AND 未使用危险渲染属性（v-html、dangerouslySetInnerHTML等）
THEN 误报 = True
```

### 场景2：业务逻辑阻断

**特征识别：**
- 用户输入包含XSS Payload
- 请求被业务逻辑阻断
- 响应码为404/400/403等拒绝状态

**误报判定依据：**
1. 检查响应码：为40x系列或500系列错误
2. 检查响应体：显示参数验证失败或资源不存在
3. 检查输入：Payload未被回显或存储

**阻断类型：**

| 阻断类型 | 典型响应 | 误报原因 |
|----------|----------|---------|
| 参数验证失败 | {"error": "Invalid parameter"} | 输入被拒绝 |
| 资源不存在 | 404 Not Found | URL被拒绝 |
| 权限不足 | 403 Forbidden | 访问被拒绝 |
| 请求过频 | 429 Too Many Requests | 限流触发 |
| 业务规则 | {"error": "Operation not allowed"} | 业务逻辑拒绝 |

**判定逻辑：**
```
IF 请求包含XSS Payload
AND 响应码为40x/50x系列
AND 响应体显示验证失败/拒绝信息
AND Payload未被回显或存储
THEN 误报 = True
```

### 场景3：富文本编辑器

**特征识别：**
- 请求来自富文本编辑功能
- 允许HTML标签输入
- 响应包含`<code>`、技术片段等合法内容

**误报判定依据：**
1. 功能识别：URL路径或参数名包含`editor`、`content`、`article`、`post`等
2. 允许的HTML标签：`<b>`、`<i>`、`<u>`、`<code>`、`<pre>`等
3. 安全处理：使用白名单过滤（如DOMPurify库）或前端沙箱

**典型示例：**
```
请求: POST /api/article/save
请求体: {"content": "<code>alert('Hello')</code>", "type": "article"}
响应: {"success": true, "content": "<code>alert('Hello')</code>"}
说明: 保存技术文档，code标签为合法HTML标签
```

**富文本编辑器特征：**

| 编辑器 | 允许标签 | 安全机制 |
|--------|----------|---------|
| TinyMCE | 白名单标签 | DOMPurify |
| CKEditor | 白名单标签 | ACES |
| Quill | 格式化标签 | Delta格式 |
| Summernote | 白名单标签 | Bootstrap过滤 |

**判定逻辑：**
```
IF 请求来自富文本编辑功能
AND HTML标签为允许的白名单标签（如b、i、code、pre等）
AND 响应经过安全过滤或使用白名单
THEN 误报 = True
```

### 场景4：安全DOM操作

**特征识别：**
- JavaScript使用安全的DOM操作API
- 内容被作为文本而非HTML处理

**误报判定依据：**
1. 检查JavaScript代码：使用安全的DOM操作方法
2. 操作方式：内容被安全处理，不会执行HTML

| 安全操作 | 示例 | 说明 |
|----------|------|------|
| textContent | `el.textContent = userInput` | 作为纯文本插入 |
| innerText | `el.innerText = userInput` | 作为纯文本插入 |
| setAttribute | `el.setAttribute('data-value', userInput)` | 设置属性值 |
| text() jQuery | `$('#el').text(userInput)` | 作为纯文本插入 |
| createElement | 创建元素后设置textContent | 安全构建DOM |

| 危险操作 | 示例 | 说明 |
|----------|------|------|
| innerHTML | `el.innerHTML = userInput` | 作为HTML解析 |
| insertAdjacentHTML | `el.insertAdjacentHTML(..., userInput)` | 作为HTML解析 |
| outerHTML | `el.outerHTML = userInput` | 作为HTML解析 |
| document.write | `document.write(userInput)` | 作为HTML解析 |

**判定逻辑：**
```
IF JavaScript使用安全DOM操作（textContent、innerText等）
AND 用户输入未直接赋值给innerHTML等危险属性
THEN 误报 = True
```

### 场景5：严格CSP策略

**特征识别：**
- 响应头包含Content-Security-Policy
- CSP策略限制脚本执行

**误报判定依据：**
1. 检查响应头：存在`Content-Security-Policy`
2. 策略分析：限制内联脚本和外部脚本

| CSP指令 | 示例 | 限制效果 |
|---------|------|---------|
| script-src | `script-src 'self'` | 只允许同源脚本 |
| script-src-elem | `script-src-elem 'self'` | 限制script元素 |
| default-src | `default-src 'none'` | 禁止所有资源 |
| object-src | `object-src 'none'` | 禁止插件 |
| style-src | `style-src 'self'` | 限制样式 |
| img-src | `img-src 'self' data:` | 限制图片 |
| unsafe-hashes | `'unsafe-hashes'` | 允许特定属性（如onload） |
| require-trusted-types | `require-trusted-types-for` | 要求Trusted Types |

**典型示例：**
```
响应头:
Content-Security-Policy: default-src 'self'; script-src 'self'
说明: 即使注入<script>标签，浏览器也会拒绝执行
```

**判定逻辑：**
```
IF 响应头包含Content-Security-Policy
AND CSP策略限制内联脚本执行（script-src不含'unsafe-inline'）
THEN 误报 = True
```

### 场景6：第三方回调/特殊格式

**特征识别：**
- 请求来源为第三方平台（支付、社交等）
- 数据格式为XML/CDATA/Base64

**误报判定依据：**
1. 来源识别：源IP或域名属于第三方平台
2. 格式识别：数据格式为合法的业务格式

| 格式类型 | 特征 | 示例 |
|----------|------|------|
| XML CDATA | `<![CDATA[ ... ]]>` | 正常XML数据 |
| Base64 | 编码字符串 | 加密传输数据 |
| 支付回调 | 特定格式 | 支付平台通知 |
| 社交分享 | 分享参数 | 社交平台回调 |

**典型示例：**
```
请求体:
<notification>
  <![CDATA[
    <script>onPaymentCallback()</script>
  ]]>
</notification>
说明: 支付回调的XML数据，CDATA中的内容不会被解析
```

**判定逻辑：**
```
IF 请求来源为可信第三方平台
AND 数据格式为合法的业务格式（XML CDATA、Base64等）
THEN 误报 = True
```

### 场景7：服务端模板语法

**特征识别：**
- 响应体包含服务端模板语法
- 模板语法在服务器端渲染

**误报判定依据：**
1. 检查响应体：包含模板语法标记
2. 模板引擎识别：来自服务器端渲染

| 模板引擎 | 语法标记 | 说明 |
|----------|----------|------|
| Thymeleaf | `th:text`、`th:utext` | 服务器端渲染 |
| Freemarker | `${}` | 服务器端渲染 |
| JSP | `<% %>` | 服务器端渲染 |
| Velocity | `$!{}` | 服务器端渲染 |
| Mustache | `{{ }}` | 服务器端渲染 |

**典型示例：**
```
响应体:
<div th:text="${userInput}"></div>
说明: Thymeleaf模板，服务器端渲染后发送纯HTML
```

**判定逻辑：**
```
IF 响应体包含服务端模板语法标记
AND 语法来自模板引擎（非客户端模板）
AND 使用安全的模板属性（如th:text而非th:utext）
THEN 误报 = True
```

### 场景8：不可达代码路径

**特征识别：**
- 危险代码在注释中
- 函数未被导出或调用

**误报判定依据：**
1. 代码位置：危险代码在注释中
2. 函数状态：函数未被导出、未定义或未被调用

| 不可达类型 | 特征 | 示例 |
|------------|------|------|
| 注释代码 | `//`、`/* */`、`<!-- -->` | `// alert('test')` |
| 未导出函数 | 未export | `function internal() { eval(...); }` |
| 死代码 | 条件永假 | `if (false) { eval(...); }` |
| 未定义函数 | 未声明或声明后未赋值 | `var fn; fn();` |

**判定逻辑：**
```
IF 危险代码在注释中
OR 危险代码所在的函数未被导出/未定义/未被调用
THEN 误报 = True
```

### 场景9：Cookie属性误判

**特征识别：**
- 告警仅涉及Cookie的HttpOnly/Secure属性
- 无实际的XSS注入点

**误报判定依据：**
1. 检查告警内容：仅提及Cookie属性
2. 注入点检查：响应体无XSS注入特征

**说明：**
- Cookie的HttpOnly/Secure属性用于防御会话劫持
- 与XSS注入点存在是不同维度的问题
- 无注入点时，即使Cookie未设置HttpOnly，也不构成XSS漏洞

**判定逻辑：**
```
IF 告警仅涉及Cookie属性（HttpOnly/Secure）
AND 响应体无XSS注入点
AND 无Payload回显或存储
THEN 误报 = True
```

### 场景10：JSONP回调注入

**特征识别：**
- 响应为JSONP格式
- 回调函数名包含XSS特征

**误报判定依据：**
1. 响应格式：`callback({...})`格式
2. 回调限制：现代应用通常限制回调函数名格式
3. 执行条件：需要特定的函数定义

| 安全机制 | 说明 |
|----------|------|
| 回调名白名单 | 只允许字母数字下划线 |
| 回调名长度限制 | 限制回调函数名长度 |
| 响应头限制 | Content-Type: application/javascript |

**典型示例：**
```
请求: GET /api/data?callback=alert(1)
响应: Content-Type: application/javascript; charset=utf-8
alert(1)({"data": "test"})
说明: 需要名为alert(1)的函数定义才能执行，实际不存在
```

**判定逻辑：**
```
IF 响应为JSONP格式
AND 回调函数名包含XSS特征
AND 无对应的函数定义
AND 现代应用已限制回调函数名格式
THEN 误报 = True
```

### 场景11：Content-Type不匹配

**特征识别：**
- 响应头Content-Type非HTML
- 响应体包含HTML/JS标签

**误报判定依据：**
1. 检查响应头：Content-Type为`application/json`、`text/plain`、`image/*`等
2. 浏览器解析：浏览器不会执行HTML/JS代码

| Content-Type | 解析行为 |
|--------------|----------|
| application/json | 作为JSON解析 |
| text/plain | 作为纯文本 |
| image/* | 作为图片 |
| application/octet-stream | 下载而非显示 |

**典型示例：**
```
响应头:
Content-Type: application/json
响应体:
{"content": "<script>alert(1)</script>"}
说明: 浏览器按JSON解析，不会执行script标签
```

**判定逻辑：**
```
IF 响应头Content-Type非HTML（如application/json、text/plain等）
AND 响应体包含HTML/JS标签
AND 浏览器不会执行该内容
THEN 误报 = True
```

### 场景12：浏览器XSS过滤器

**特征识别：**
- 现代浏览器内置XSS过滤器
- 过滤器拦截恶意脚本

**误报判定依据：**
1. 浏览器特征：现代浏览器（Chrome、Firefox、Edge等）
2. 过滤器激活：XSS Auditor已启用
3. 防护效果：即使有注入点，浏览器也会拦截

**浏览器XSS过滤器：**

| 浏览器 | 过滤器 | 状态 |
|--------|--------|------|
| Chrome | XSS Auditor | 已弃用（历史功能） |
| Firefox | Built-in XSS filter | 已移除 |
| Safari | XSS Auditor | 已弃用 |
| Edge | XSS Auditor | 已弃用 |

**注意：** 现代浏览器已移除XSS过滤器，此场景适用于历史告警分析。

**判定逻辑：**
```
IF 浏览器版本支持XSS过滤器（历史版本）
AND 注入会被浏览器过滤器拦截
THEN 误报 = True
```

### 场景13：JavaScript字符串/模板字面量中的内容

**特征识别：**
- 用户输入出现在JavaScript字符串中
- 字符串未使用eval或Function执行

**误报判定依据：**
1. 检查JavaScript代码：输入在字符串中
2. 执行方式：未使用eval、Function等动态执行

| 安全用法 | 示例 | 说明 |
|----------|------|------|
| 字符串字面量 | `const str = '<script>'` | 纯字符串 |
| 模板字面量 | `const str = \`<script>\`` | 纯字符串 |
| JSON.stringify | `JSON.stringify(userInput)` | 转义为JSON |

| 危险用法 | 示例 | 说明 |
|----------|------|------|
| eval | `eval(userInput)` | 执行代码 |
| Function | `new Function(userInput)()` | 执行代码 |
| setTimeout | `setTimeout(userInput, 0)` | 执行代码 |

**判定逻辑：**
```
IF 用户输入在JavaScript字符串或模板字面量中
AND 未使用eval/Function/setInterval/setTimeout等执行
THEN 误报 = True
```

### 场景14：CSS样式中的content属性

**特征识别：**
- 用户输入出现在CSS的content属性中
- 不执行JavaScript代码

**误报判定依据：**
1. 检查CSS代码：输入在content属性中
2. CSS限制：content属性不支持JavaScript执行

**典型示例：**
```
CSS:
.badge::after {
  content: attr(data-badge);
}
HTML:
<div data-badge="<script>alert(1)</script>"></div>
说明: CSS content属性只显示文本，不执行JS
```

**判定逻辑：**
```
IF 用户输入在CSS content属性或attr()函数中
AND 属性在CSS伪元素中使用
THEN 误报 = True
```

### 场景15：SVG/MathML合法标签

**特征识别：**
- 响应包含SVG或MathML标签
- 标签内容为合法的图形或数学公式

**误报判定依据：**
1. 标签类型：SVG/MathML合法标签
2. 内容验证：内容为图形或数学公式
3. 安全检查：无事件处理器（onload、onerror等）

**危险特征（不判定为误报）：**
- SVG中包含事件处理器（onload、onerror、onclick等）
- SVG中使用`<script>`标签
- SVG中使用`<foreignObject>`嵌入HTML

| 合法标签 | 安全属性 | 危险特征 |
|----------|---------|---------|
| <svg> | xmlns、viewBox | onload、onerror |
| <path> | d、fill | onclick |
| <circle> | cx、cy、r | onmouseover |
| <rect> | x、y、width、height | onmouseout |
| <math> | xmlns | 事件处理器 |
| <foreignObject> | - | 嵌入HTML，危险 |

**典型示例（误报）：**
```
响应体:
<svg xmlns="http://www.w3.org/2000/svg">
  <path d="M0,0 L10,10 L10,0 Z" fill="red"/>
</svg>
说明: 合法的SVG图形标签，无事件处理器
```

**典型示例（真实告警）：**
```
响应体:
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)">
  <path d="M0,0 L10,10"/>
</svg>
说明: 包含onload事件处理器，真实XSS
```

**判定逻辑：**
```
IF 响应包含SVG/MathML标签
AND 标签结构合法
AND 内容为合法的图形或数学公式（path、circle、rect、mi、mo等）
AND 无事件处理器（onload、onerror、onclick、onmouseover等）
AND 无<script>标签
AND 无<foreignObject>嵌入HTML
THEN 误报 = True
```

### 场景16：URL片段标识符

**特征识别：**
- XSS Payload出现在URL的片段部分（#后）
- 片段标识符不会发送到服务器

**误报判定依据：**
1. URL结构：Payload在`#`之后
2. 浏览器行为：片段标识符仅用于客户端导航

**典型示例：**
```
URL: https://example.com/page#<script>alert(1)</script>
说明: #后的内容不会发送到服务器，仅用于客户端定位
```

**判定逻辑：**
```
IF XSS Payload在URL的片段标识符中（#之后）
AND 片段内容不会发送到服务器
THEN 误报 = True
```

### 场景17：数据URI schemes

**特征识别：**
- URL使用data: scheme
- 内容被编码处理

**误报判定依据：**
1. URI格式：`data:[<mediatype>][;base64],<data>`
2. 浏览器限制：受CSP策略限制
3. 加载方式：未被iframe/embed/object等元素加载

| data URI类型 | 示例 | 限制 |
|-------------|------|------|
| image | `data:image/png;base64,...` | 仅图片，安全 |
| text/html | `data:text/html,<script>` | 需CSP允许，需iframe加载 |
| javascript | `data:text/javascript,alert(1)` | 需CSP允许，需script加载 |

**危险加载方式（不判定为误报）：**
- iframe src中使用data: URI
- embed src中使用data: URI
- object data中使用data: URI

**典型示例（误报）：**
```
响应体:
<img src="data:image/png;base64,iVBORw0KG..."/>
说明: 图片data URI，安全
```

**典型示例（真实告警）：**
```
响应体:
<iframe src="data:text/html,<script>alert(1)</script>"></iframe>
说明: iframe加载data HTML，可能绕过CSP
```

**判定逻辑：**
```
IF Payload在data: URI中
AND (严格的CSP策略限制内联脚本 AND 禁止script-src)
AND 未被iframe/embed/object等元素加载
AND 媒体类型为安全类型（如image、application/json）
THEN 误报 = True
```

### 场景18：iframe sandbox限制

**特征识别：**
- iframe使用sandbox属性
- 沙箱限制脚本执行

**误报判定依据：**
1. iframe属性：存在sandbox属性
2. 限制效果：禁止脚本执行

| sandbox值 | 效果 |
|-----------|------|
| `sandbox` | 禁止所有功能 |
| `sandbox="allow-scripts"` | 允许脚本但限制其他 |
| `sandbox="allow-scripts allow-same-origin"` | 相对宽松但仍有限制 |

**判定逻辑：**
```
IF iframe使用sandbox属性
AND sandbox值不包含allow-scripts或allow-same-origin
THEN 误报 = True
```

### 场景19：表单action合法跳转

**特征识别：**
- XSS Payload在form的action属性中
- 跳转URL为合法目标且在白名单内

**误报判定依据：**
1. form action：Payload在action属性中
2. URL验证：跳转URL在白名单内
3. 协议安全：使用https://等安全协议

**危险特征（不判定为误报）：**
- 使用`javascript:`伪协议
- 使用`data:` URI
- URL不在白名单内
- 使用`vbscript:`等危险协议

**典型示例（误报）：**
```
<form action="https://example.com/submit">
  <input type="submit"/>
</form>
说明: 跳转到HTTPS白名单URL，安全
```

**典型示例（真实告警）：**
```
<form action="javascript:alert(1)">
  <input type="submit"/>
</form>
说明: javascript:伪协议，真实XSS（需用户点击）
```

**判定逻辑：**
```
IF Payload在form action属性中
AND action URL使用安全协议（https://、http://）
AND action URL在白名单内
AND 不使用javascript:、data:、vbscript:等危险协议
THEN 误报 = True
```

### 场景20：meta refresh合法跳转

**特征识别：**
- meta refresh标签用于页面跳转
- 跳转URL为合法目标且在白名单内

**误报判定依据：**
1. 标签用途：用于页面跳转
2. URL验证：跳转URL在白名单内
3. 协议安全：使用https://等安全协议

**危险特征（不判定为误报）：**
- 使用`javascript:`伪协议
- 使用`data:` URI
- 使用`vbscript:`等危险协议
- URL不在白名单内

**典型示例（误报）：**
```
<meta http-equiv="refresh" content="0; url=https://example.com/page">
说明: 跳转到HTTPS白名单URL，安全
```

**典型示例（真实告警）：**
```
<meta http-equiv="refresh" content="0; url=javascript:alert(1)">
说明: javascript:伪协议，真实XSS
```

**判定逻辑：**
```
IF Payload在meta refresh的url参数中
AND url使用安全协议（https://、http://）
AND url在白名单内
AND 不使用javascript:、data:、vbscript:等危险协议
THEN 误报 = True
```

### 场景21：图片alt/title属性

**特征识别：**
- XSS Payload在img标签的alt或title属性中
- 属性内容仅显示为文本

**误报判定依据：**
1. 标签属性：Payload在alt或title属性中
2. 浏览器行为：属性内容作为文本显示

**典型示例：**
```
<img src="logo.png" alt="<script>alert(1)</script>">
说明: alt属性内容仅显示为文本，不执行JS
```

**判定逻辑：**
```
IF Payload在img标签的alt或title属性中
AND 属性内容仅作为文本显示
THEN 误报 = True
```

### 场景22：文件名/路径中的特殊字符

**特征识别：**
- XSS Payload出现在文件名或路径中
- 用于文件操作，非HTML渲染

**误报判定依据：**
1. 参数类型：文件名或路径参数
2. 使用场景：文件上传/下载、路径导航
3. 渲染验证：文件名未被渲染到HTML属性或URL参数回显

**典型示例：**
```
请求: GET /api/download?filename=<script>alert(1)</script>.txt
响应: 下载文件
说明: 文件名仅用于文件操作，不会渲染为HTML
```

**判定逻辑：**
```
IF Payload在文件名或路径参数中
AND 用于文件操作（上传/下载/导航）
AND 文件名未被渲染到HTML属性或URL参数回显
THEN 误报 = True
```

### 场景23：WebSocket消息数据

**特征识别：**
- XSS Payload出现在WebSocket消息中
- 消息仅用于数据传输

**误报判定依据：**
1. 协议类型：WebSocket通信
2. 消息用途：数据传输，非HTML渲染

**典型示例：**
```
WebSocket消息: {"type": "chat", "content": "<script>alert(1)</script>"}
说明: 消息由客户端处理，不自动执行HTML
```

**判定逻辑：**
```
IF Payload在WebSocket消息中
AND 消息由客户端JavaScript安全处理（如textContent）
THEN 误报 = True
```

### 场景24：LocalStorage/SessionStorage数据

**特征识别：**
- XSS Payload存储在LocalStorage或SessionStorage中
- 存储值仅用于数据存储

**误报判定依据：**
1. 存储位置：LocalStorage或SessionStorage
2. 使用方式：值仅用于数据读取，非HTML渲染

**典型示例：**
```
localStorage.setItem('userInput', '<script>alert(1)</script>');
说明: 存储的值需要显式读取和渲染，不会自动执行
```

**判定逻辑：**
```
IF Payload在LocalStorage/SessionStorage中
AND 存储值未被传递给eval/innerHTML等危险函数
THEN 误报 = True
```

### 场景25：HTTP参数污染（HPP）

**特征识别：**
- 同参数多次出现在请求中
- 应用只取第一个或最后一个参数值
- 所有参数值都被过滤或忽略

**误报判定依据：**
1. 参数重复：同一参数名在请求中出现多次
2. 应用行为：应用只取第一个或最后一个值
3. 过滤验证：所有值都经过安全过滤

**典型示例：**
```
请求: GET /api/search?q=<script>alert(1)</script>&q=test
响应: 应用取第一个值但经过HTML转义
说明: HPP场景，但值被过滤
```

**判定逻辑：**
```
IF 同一参数名在请求中出现多次
AND 应用只取特定位置的值（如第一个或最后一个）
AND 取值经过安全过滤或转义
THEN 误报 = True
```

### 场景26：GraphQL参数误报

**特征识别：**
- 参数在GraphQL query/mutation中
- GraphQL框架有内置输入验证

**误报判定依据：**
1. 协议类型：GraphQL请求
2. 框架验证：GraphQL框架有类型检查和输入验证
3. 参数处理：参数被安全处理

**典型示例：**
```
请求: POST /graphql
请求体: {"query": "query { search(name: \"<script>alert(1)</script>\") { id } }"}
响应: 返回查询结果
说明: GraphQL有内置类型检查，参数不会作为HTML渲染
```

**判定逻辑：**
```
IF 请求为GraphQL协议
AND 参数在query/mutation中
AND GraphQL框架处理参数
AND 参数值经过类型验证和安全处理
THEN 误报 = True
```

### 场景27：WebAssembly模块注入误报

**特征识别：**
- Payload在WebAssembly binary或text format中
- Wasm有严格格式验证

**误报判定依据：**
1. 格式类型：WASM binary或text format
2. 格式验证：Wasm有严格的格式验证
3. 执行限制：HTML标签在Wasm中无效

**典型示例：**
```
请求: POST /api/wasm
请求体: (module (func $alert (param i32)))
响应: Wasm模块加载
说明: Wasm格式严格，HTML标签无效
```

**判定逻辑：**
```
IF Payload在WebAssembly模块中
AND WebAssembly有严格格式验证
AND HTML标签/JS代码在Wasm中无效
THEN 误报 = True
```

### 场景28：JSON解析错误场景

**特征识别：**
- Payload导致JSON解析错误
- 错误被安全处理

**误报判定依据：**
1. 请求格式：预期JSON格式
2. 解析失败：Payload导致JSON解析失败
3. 错误处理：错误被安全处理，未回显

**典型示例：**
```
请求: POST /api/data
请求体: {"data": "<script>alert(1)</script>"}
响应: {"error": "Invalid JSON format"}
说明: JSON解析失败，错误被安全处理
```

**判定逻辑：**
```
IF 请求预期JSON格式
AND Payload导致JSON解析失败
AND 错误被安全处理，未回显Payload
THEN 误报 = True
```

### 场景29：文件上传MIME类型混淆

**特征识别：**
- Payload在文件上传中
- 文件被按MIME类型处理，非HTML

**误报判定依据：**
1. 上传场景：文件上传功能
2. MIME类型：文件按正确MIME类型处理
3. 安全处理：文件不被作为HTML渲染

**典型示例：**
```
请求: POST /api/upload
请求体: 文件名: <script>alert(1)</script>.txt
响应: 文件存储成功
说明: 文件按text/plain处理，不会渲染为HTML
```

**判定逻辑：**
```
IF Payload在文件上传中
AND 文件按非HTML MIME类型处理（如text/plain、application/octet-stream）
AND 文件不被作为HTML渲染
THEN 误报 = True
```

### 场景30：文件名未被渲染到HTML属性

**特征识别：**
- 文件名包含特殊字符
- 文件名未被渲染到HTML属性或URL参数回显

**误报判定依据：**
1. 文件名特征：包含XSS特殊字符
2. 使用场景：文件名仅用于内部处理
3. 渲染验证：文件名未被渲染到HTML属性或URL

**典型示例：**
```
请求: POST /api/upload
请求体: 文件名: <img src=x onerror=alert(1)>.jpg
响应: 文件存储成功，内部名称为随机UUID
说明: 文件名被内部重命名，不会回显
```

**判定逻辑：**
```
IF 文件名包含XSS特殊字符
AND 文件名被内部重命名或处理
AND 原始文件名未被渲染到HTML属性或URL
THEN 误报 = True
```

## 非误报判定标准

### 真实XSS告警特征

若不满足上述任何误报场景，且存在以下明确注入证据，则判定为**真实告警**：

#### 1. 反射型XSS成功

**特征：**
- Payload通过URL参数注入
- 响应原样回显并执行

**判定：**
```
IF Payload在URL参数中
AND 响应体原样回显Payload
AND 响应Content-Type为HTML
AND 无安全转义或CSP限制
AND Payload在浏览器中执行
THEN 真实告警 = True
```

#### 2. 存储型XSS成功

**特征：**
- Payload存储到服务器
- 后续访问时执行

**判定：**
```
IF Payload存储到数据库或文件
AND 后续请求返回包含Payload的HTML
AND Payload在浏览器中执行
THEN 真实告警 = True
```

#### 3. DOM型XSS成功

**特征：**
- Payload通过URL片段或参数
- JavaScript使用innerHTML等危险操作渲染

**判定：**
```
IF Payload在URL片段或参数中
AND JavaScript使用innerHTML等危险操作
AND Payload被渲染并执行
THEN 真实告警 = True
```

#### 4. 自执行XSS成功

**特征：**
- Payload包含自执行代码（如`onerror=`、`onload=`）
- 事件处理器触发执行

**判定：**
```
IF Payload包含事件处理器（onerror、onload等）
AND 响应包含对应元素
AND 事件触发并执行Payload
THEN 真实告警 = True
```

#### 5. 链接注入成功

**特征：**
- Payload在href或src属性中
- 使用`javascript:`伪协议

**判定：**
```
IF Payload在href或src属性中
AND 使用javascript:伪协议
AND 点击链接执行Payload
THEN 真实告警 = True
```

## 判定流程图

```
开始分析XSS注入告警
    │
    ▼
提取请求体、响应体和响应头
    │
    ▼
识别编码方式并解码（最多3层）
    │
    ▼
检查响应头和响应码
    │
    ▼
┌─────────────────────────────────────────────────────────────┐
│ 检查误报场景（按优先级1-30）                                 │
├─────────────────────────────────────────────────────────────┤
│ 高优先级（特征明确，直接验证）                               │
│ ├─ 场景1: 现代前端框架转义                                  │
│ ├─ 场景2: 业务逻辑阻断                                      │
│ ├─ 场景3: 富文本编辑器                                      │
│ ├─ 场景4: 安全DOM操作                                       │
│ ├─ 场景5: 严格CSP策略                                       │
│ ├─ 场景7: 服务端模板语法                                    │
│ ├─ 场景9: Cookie属性误判                                    │
│ ├─ 场景10: JSONP回调注入                                    │
│ ├─ 场景11: Content-Type不匹配                               │
│ └─ 场景17: 数据URI schemes                                  │
│                                                              │
│ 中优先级（特定格式/位置明确）                                │
│ ├─ 场景6: 第三方回调/特殊格式                               │
│ ├─ 场景8: 不可达代码路径                                    │
│ ├─ 场景12: 浏览器XSS过滤器                                  │
│ ├─ 场景13: JS字符串/模板字面量                              │
│ ├─ 场景14: CSS content属性                                  │
│ ├─ 场景15: SVG/MathML合法标签                               │
│ ├─ 场景16: URL片段标识符                                    │
│ ├─ 场景18: iframe sandbox限制                               │
│ ├─ 场景19: 表单action合法跳转                               │
│ ├─ 场景20: meta refresh合法跳转                             │
│ ├─ 场景21: 图片alt/title属性                                │
│ ├─ 场景22: 文件名/路径特殊字符                              │
│ ├─ 场景25: HTTP参数污染（HPP）                              │
│ ├─ 场景26: GraphQL参数误报                                  │
│ ├─ 场景27: WebAssembly模块注入误报                          │
│ ├─ 场景28: JSON解析错误场景                                 │
│ ├─ 场景29: 文件上传MIME类型混淆                             │
│ └─ 场景30: 文件名未被渲染到HTML                             │
│                                                              │
│ 低优先级（需推断分析）                                       │
│ ├─ 场景23: WebSocket消息数据                                │
│ └─ 场景24: LocalStorage数据                                 │
└─────────────────────────────────────────────────────────────┘
    │
    ├─ 匹配任一误报场景 ──► 误报 = True ──► 记录匹配场景和置信度
    │
    └─ 无匹配 ──► 检查真实XSS特征
                      │
        ┌─────────────┴─────────────┐
        │                           │
    匹配真实特征              无真实特征
        │                           │
        ▼                           ▼
  真实告警 = True         无法判定（需人工复核）
        │                           │
        ▼                           ▼
      结束                       标记待复核
```

**流程说明：**
1. 首先检查响应头和响应码（Content-Type、CSP、响应状态）
2. 检测并解码编码内容（最多3层）
3. 按优先级从高到低检查误报场景
4. 匹配到第一个场景即判定为误报，记录场景编号和置信度
5. 如无匹配，检查真实XSS特征
6. 如仍无法判定，标记为待人工复核

## 判定示例

### 示例1：误报 - Vue框架转义

```
请求: GET /api/user?name=<script>alert(1)</script>
响应:
<div>
  <p>用户名: {{ name }}</p>
</div>
分析: 使用Vue插值表达式，自动转义HTML
判定: 误报（场景1）
```

### 示例2：误报 - Content-Type不匹配

```
请求: GET /api/data?q=<script>alert(1)</script>
响应头: Content-Type: application/json
响应体: {"query": "<script>alert(1)</script>"}
分析: 响应为JSON格式，浏览器不执行HTML
判定: 误报（场景11）
```

### 示例3：误报 - 严格CSP策略

```
请求: GET /api/page?x=<script>alert(1)</script>
响应头: Content-Security-Policy: default-src 'self'; script-src 'self'
响应体: <div><script>alert(1)</script></div>
分析: CSP策略禁止内联脚本执行
判定: 误报（场景5）
```

### 示例4：真实告警 - 反射型XSS

```
请求: GET /api/search?q=<script>alert(1)</script>
响应头: Content-Type: text/html
响应体: <div>搜索结果: <script>alert(1)</script></div>
分析: Payload原样回显在HTML中，无CSP限制
判定: 真实告警（反射型XSS）
```

### 示例5：真实告警 - DOM型XSS

```
请求: GET /api/page?data=<img src=x onerror=alert(1)>
响应JavaScript:
var data = getParameter('data');
document.getElementById('result').innerHTML = data;
分析: 使用innerHTML渲染用户输入
判定: 真实告警（DOM型XSS）
```

### 示例6：真实告警 - 存储型XSS

```
请求1: POST /api/comment
请求体: {"content": "<script>alert(1)</script>"}
响应: {"success": true}

请求2: GET /api/comments
响应体: <div><script>alert(1)</script></div>
分析: Payload存储后，后续访问时执行
判定: 真实告警（存储型XSS）
```

## 分析报告输出

### 判定结果格式

```json
{
  "alert_id": "告警唯一标识",
  "判定结果": "误报/真实告警/无法判定",
  "误报场景": "场景X: 场景名称（若为误报）",
  "场景类型": "直接验证类/推断类/上下文依赖类（若为误报）",
  "真实特征": "真实特征描述（若为真实告警）",
  "判定依据": [
    "依据1",
    "依据2"
  ],
  "推断依据": "推断分析说明（推断类场景必填）",
  "请求分析": {
    "原始请求": "请求内容",
    "编码类型": "Base64/URL等",
    "解码后": "解码内容",
    "参数值": "提取的参数值"
  },
  "响应分析": {
    "响应码": "HTTP状态码",
    "响应头": {
      "Content-Type": "响应类型",
      "Content-Security-Policy": "CSP策略（如有）"
    },
    "响应内容摘要": "关键响应内容",
    "是否包含错误": "true/false",
    "错误类型": "错误类型（如有）"
  },
  "XSS类型": "反射型/存储型/DOM型（若为真实告警）",
  "置信度": "高/中/低"
}
```

### 使用说明

1. **触发条件**：当用户需要分析XSS注入类告警时使用此cookbook
2. **分析步骤**：
   - 提取请求体、响应体和响应头
   - 识别并解码编码内容
   - 首先检查响应头（Content-Type、CSP）
   - 按优先级检查误报场景
   - 如无匹配，检查真实XSS特征
   - 输出判定结果和依据

3. **置信度评估**：
   - 高：明确匹配误报场景或真实XSS特征，响应头和响应码明确
   - 中：部分匹配，需要额外上下文确认或推断类场景
   - 低：无明确特征，需要人工复核

## 注意事项

1. **编码识别优先级**：按URL编码 → Base64 → Hex → Unicode → HTML实体 → JavaScript编码 → UTF-7 → 多重编码的顺序检测
2. **编码检测流程**：最多解码10层或直到内容不再变化，防止解码循环
3. **响应头优先检查**：Content-Type和CSP是快速判定误报的重要依据
4. **上下文分析**：结合URL路径、参数名、业务场景综合判断
5. **响应分析**：重点分析响应体的渲染方式和执行环境
6. **误报场景覆盖**：确保覆盖所有30个误报场景
7. **场景优先级**：高优先级场景优先匹配，低优先级场景需要更多上下文验证
8. **无法判定处理**：对于无法判定的告警，标记为"待人工复核"并记录原因
9. **场景冲突处理**：多场景匹配时选择优先级最高的，或标记为"多场景匹配"
10. **现代浏览器特性**：注意现代浏览器的安全特性（如已弃用XSS过滤器）
11. **框架特性**：熟悉现代前端框架（Vue、React、Angular）的自动转义机制
12. **CSP策略分析**：仔细分析CSP策略是否真的限制了脚本执行
