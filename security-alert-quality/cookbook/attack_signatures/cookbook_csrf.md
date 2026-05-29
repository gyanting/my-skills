
# CSRF注入误报识别 Cookbook

## 目录

- [技能概述](#技能概述)
- [角色定位](#角色定位)
- [分析输入](#分析输入)
  - [数据来源](#数据来源)
  - [编码绕过识别](#编码绕过识别)
- [误报判定场景](#误报判定场景)
  - [场景检查优先级](#场景检查优先级)
  - [场景1：双重提交Cookie（SPA+Axios）](#场景1双重提交cookiespaaxios)
  - [场景2：只读操作（无状态变更）](#场景2只读操作无状态变更)
  - [场景3：二次验证/来源校验](#场景3二次验证来源校验)
  - [场景4：扫描器会话/Token不同步](#场景4扫描器会话token不同步)
  - [场景5：Same-Site Cookie](#场景5same-site-cookie)
  - [场景6：自定义请求头防御](#场景6自定义请求头防御)
  - [场景7：JWT/无状态Token](#场景7jwt无状态token)
  - [场景8：验证码前置](#场景8验证码前置)
  - [场景9：幂等操作](#场景9幂等操作)
  - [场景10：合理禁用的框架防护](#场景10合理禁用的框架防护)
  - [场景11：API网关/微服务架构](#场景11api网关微服务架构)
  - [场景12：移动应用请求](#场景12移动应用请求)
  - [场景13：IP白名单限制](#场景13ip白名单限制)
  - [场景14：时间窗口验证](#场景14时间窗口验证)
  - [场景15：GraphQL mutation幂等](#场景15graphql-mutation幂等)
  - [场景16：API密钥认证](#场景16api密钥认证)
  - [场景17：敏感操作二次确认](#场景17敏感操作二次确认)
- [非误报判定标准](#非误报判定标准)
  - [真实CSRF告警特征](#真实csrf告警特征)
- [判定流程图](#判定流程图)
- [判定示例](#判定示例)
  - [示例1：误报 - 双重提交Cookie](#示例1误报---双重提交cookie)
  - [示例2：误报 - 只读操作](#示例2误报---只读操作)
  - [示例3：误报 - Same-Site Cookie](#示例3误报---same-site-cookie)
  - [示例4：误报 - JWT认证](#示例4误报---jwt认证)
  - [示例5：误报 - 验证码前置](#示例5误报---验证码前置)
  - [示例6：误报 - 移动应用请求](#示例6误报---移动应用请求)
  - [示例7：真实告警 - 缺少CSRF防护](#示例7真实告警---缺少csrf防护)
  - [示例8：真实告警 - SameSite=None不安全](#示例8真实告警---samesitenone不安全)
- [分析报告输出](#分析报告输出)
  - [判定结果格式](#判定结果格式)
  - [使用说明](#使用说明)
- [注意事项](#注意事项)

## 快速判定摘要

以下为脚本/LLM自动判定使用的结构化规则，详细分析见后续章节。

### 真阳性指标

| 置信度 | 特征 | 说明 |
|--------|------|------|
| 高 | 跨域请求含敏感操作（转账/改密/删数据）且无CSRF Token | 典型CSRF攻击 |
| 高 | Referer头缺失 + POST请求修改关键资源 | CSRF攻击链 |
| 中 | `<form>` action指向外部域名 + method=POST | 表单劫持 |
| 中 | 请求含 `XMLHttpRequest`/`fetch(` + 跨域 | JS发起的跨域请求 |
| 低 | 短时间内大量同源POST请求 + 不同Referer | 可能的CSRF批量利用 |

### 误报指标

| 置信度 | 特征 | 说明 |
|--------|------|------|
| 高 | 跨域请求来自已知CDN/API网关域名 | 正常跨域API调用 |
| 高 | CORS头正确配置的跨域请求 | 合法跨域资源共享 |
| 中 | 移动端APP/单页应用的跨域请求 | 正常APP通信 |
| 中 | OAuth/SSO回调请求 | 认证流程跨域 |

### 判定优先级

1. 先查请求是否修改资源（POST/PUT/DELETE） → GET请求通常是误报
2. 再查CSRF Token是否存在 → 有Token=正常
3. 最后查Referer/Origin是否合法 → 同源或白名单域名=正常

## 技能概述

网络安全设备通过内置规则检测CSRF注入攻击，但由于规则配置、检测逻辑、业务场景等因素，容易产生大量误报。本cookbook提供系统化的CSRF注入误报识别方法，帮助分析人员准确判定告警真实性。

## 角色定位

你是一名专业的安全告警研判分析师，专注于CSRF类告警的误报识别与判定。

## 分析输入

### 数据来源

从网络安全设备告警日志CSV中提取以下关键字段：

| 字段 | 用途 | 说明 |
|------|------|------|
| 请求体 | 分析CSRF Token | 包含POST参数、自定义请求头 |
| 响应体 | 判断Token验证结果 | 包含服务器返回内容 |
| 响应码 | 判断请求状态 | 200/403/401/419等状态码分析 |
| 响应头 | 分析Cookie策略 | Set-Cookie、SameSite、CSRF Token等 |
| 请求头 | 分析防御机制 | X-CSRF-TOKEN、X-Requested-With、Origin、Referer等 |
| 载荷 | 分析流量特征 | 网络流量中的原始数据 |

### 编码绕过识别

在分析请求体时，必须检测以下编码方式（按检测优先级排序）：

| 优先级 | 编码类型 | 检测规则 | 解码方法 | 示例 |
|--------|----------|----------|----------|------|
| 1 | URL编码 | `%[0-9A-Fa-f]{2}` | urldecode | `%3Cscript%3E` → `<script>` |
| 2 | Base64 | `/^[A-Za-z0-9+/]+=*$/` 且len%4==0 | base64_decode | `eyJ0b2tlbiI6Inh5eiJ9` → `{"token":"xyz"}` |
| 3 | Hex编码 | `\\x[0-9A-Fa-f]{2}` | hex2bin | `\x22\x78\x79\x7A\x22` → `"xyz"` |
| 4 | Unicode编码 | `\\u[0-9A-Fa-f]{4}` | unicode_decode | `\u0022\u0078\u0079\u007A\u0022` → `"xyz"` |
| 5 | HTML实体编码 | `&#\d+;|&#x[0-9A-Fa-f]+;` | html_entity_decode | `&#34;xyz&#34;` → `"xyz"` |
| 6 | JSON编码 | JSON转义 | JSON.parse | `\"` → `"` |
| 7 | 双重/多重编码 | 多层编码特征 | 多次解码 | `%2522` → `%22` → `"` |

**检测流程：**
1. 从请求体提取CSRF Token值
2. 按优先级依次检测编码特征
3. 如果匹配，进行解码
4. 记录已解码内容，如解码结果与之前相同则停止（防止解码循环）
5. 对解码后的内容再次检测（处理多重编码）
6. 最多解码10层或直到内容不再变化

## 误报判定场景

### 场景检查优先级

**场景分类说明：**
- **直接验证类**：可通过单次请求响应直接判定，无需额外推断
- **推断类**：需要根据响应特征或业务逻辑推断
- **上下文依赖类**：需要结合多个请求或业务上下文判断

当多个误报场景特征同时出现时，按以下优先级判定：

| 优先级 | 场景 | 类型 | 判定依据强度 |
|--------|------|------|-------------|
| 1 | 场景1：双重提交Cookie | 直接验证 | 最强：防御机制明确 |
| 2 | 场景7：JWT/无状态Token | 直接验证 | 最强：认证方式明确 |
| 3 | 场景5：Same-Site Cookie | 直接验证 | 最强：响应头明确 |
| 4 | 场景2：只读操作 | 直接验证 | 强：业务语义明确 |
| 5 | 场景6：自定义请求头防御 | 直接验证 | 强：请求头特征 |
| 6 | 场景8：验证码前置 | 直接验证 | 强：验证码特征 |
| 7 | 场景3：二次验证/来源校验 | 直接验证 | 强：校验特征 |
| 8 | 场景9：幂等操作 | 推断类 | 中：需分析操作效果 |
| 9 | 场景11：API网关/微服务架构 | 推断类 | 中：架构特征 |
| 10 | 场景12：移动应用请求 | 直接验证 | 中：User-Agent特征 |
| 11 | 场景10：合理禁用的框架防护 | 推断类 | 中：需架构确认 |
| 12 | 场景16：API密钥认证 | 直接验证 | 中：认证特征 |
| 13 | 场景15：GraphQL mutation幂等 | 推断类 | 中：操作特征 |
| 14 | 场景4：扫描器会话/Token不同步 | 推断类 | 弱：扫描器特征 |
| 15 | 场景13：IP白名单限制 | 推断类 | 中：配置特征 |
| 16 | 场景14：时间窗口验证 | 推断类 | 中：时间特征 |
| 17 | 场景17：敏感操作二次确认 | 推断类 | 中-弱：流程特征 |

**冲突处理规则：**
- 如果同时匹配多个场景，选择优先级最高的场景
- 如果优先级相同，检查特征是否更加明确
- 对于明显匹配多个场景的情况，标记为"误报（多场景匹配）"并列出所有匹配场景
- 推断类场景和上下文依赖类场景的判定结果置信度建议标记为"中"，并在报告中说明推断依据

---

### 场景1：双重提交Cookie（SPA+Axios）

**特征识别：**
- 请求包含自定义请求头（如X-CSRF-TOKEN）
- Cookie中有同名Token值

**误报判定依据：**
1. 检查请求头：存在X-CSRF-TOKEN、X-XSRF-TOKEN等自定义请求头
2. 检查Cookie：存在同名或关联的Token值
3. 请求方法：POST/PUT/DELETE等状态变更请求

**防御原理：**
- 前端从Cookie读取Token
- 通过自定义请求头发送给后端
- 后端验证两者匹配
- 由于浏览器同源策略，攻击者无法同时伪造Cookie和自定义请求头

**典型示例：**
```
请求头:
X-CSRF-TOKEN: abc123xyz
Cookie: csrftoken=abc123xyz
说明: 双重提交Cookie模式，防御有效
```

**框架特征：**

| 框架 | 请求头名 | Cookie名 |
|------|----------|---------|
| Laravel | X-CSRF-TOKEN | XSRF-TOKEN |
| Django | X-CSRFToken | csrftoken |
| Spring Security | X-CSRF-TOKEN | - |
| Angular | X-XSRF-TOKEN | XSRF-TOKEN |

**判定逻辑：**
```
IF 请求包含自定义CSRF Token请求头（X-CSRF-TOKEN等）
AND Cookie中存在同名或关联Token值
AND 请求方法为POST/PUT/DELETE/PATCH
THEN 误报 = True
```

### 场景2：只读操作（无状态变更）

**特征识别：**
- HTTP方法为POST/PUT但业务语义为查询
- 无数据库写入操作

**误报判定依据：**
1. 请求方法：POST/PUT/DELETE等非GET方法
2. 业务语义：查询、搜索、获取数据等只读操作
3. 无副作用：请求不产生状态变更

**只读操作类型：**

| 操作类型 | 示例 | 特征 |
|----------|------|------|
| 复杂查询 | POST /api/search | 参数较多，但仅查询 |
| 数据导出 | POST /api/export | 生成文件，无状态变更 |
| 批量获取 | POST /api/batch-get | 获取多个资源 |
| 报表查询 | POST /api/report | 生成报表 |

**只读操作识别特征：**

| 识别特征 | URL路径示例 | 参数名示例 |
|----------|-------------|-----------|
| 查询关键字 | /api/search、/api/query | query、search、filter |
| 获取关键字 | /api/get、/api/list | get、list |
| 导出关键字 | /api/export | export |

**典型示例：**
```
请求: POST /api/search
请求体: {"query": "user", "filters": {...}}
响应: {"results": [...]}
说明: 虽然是POST，但仅为复杂查询，无状态变更
```

**判定逻辑：**
```
IF 请求方法为POST/PUT/DELETE
AND (URL路径包含查询/获取/导出等关键字
     OR 参数名包含query/search/filter/get/list/export等)
AND 响应成功返回数据
THEN 误报 = True
```

### 场景3：二次验证/来源校验

**特征识别：**
- 请求包含密码/验证码字段
- Origin/Referer校验通过

**误报判定依据：**
1. 二次验证：请求包含password、captcha、verify_code等字段
2. 来源校验：Origin或Referer在白名单内
3. 校验通过：请求成功返回200

**校验方式：**

| 校验方式 | 特征 | 防御效果 |
|----------|------|---------|
| 密码确认 | password字段 | 需用户主动输入 |
| 验证码 | captcha/verify_code字段 | 需用户主动输入 |
| Origin白名单 | Origin在白名单 | 跨站请求无法伪造 |
| Referer白名单 | Referer在白名单 | 跨站请求无法伪造 |

**典型示例：**
```
请求: POST /api/settings/change-password
请求头:
Origin: https://example.com
Referer: https://example.com/settings
请求体: {"new_password": "...", "captcha": "AB12"}
说明: 有验证码和来源校验，CSRF攻击无法完成
```

**判定逻辑：**
```
IF 请求包含二次验证字段（password、captcha、verify_code等）
OR (Origin或Referer在白名单内且请求成功)
THEN 误报 = True
```

### 场景4：扫描器会话/Token不同步

**特征识别：**
- 多线程扫描触发403/419
- Token不匹配错误

**误报判定依据：**
1. 响应码：403（Forbidden）或419（Authentication timeout）
2. 响应内容：Token过期、无效、不匹配等错误信息
3. 扫描特征：短时间大量请求，Token不同

**框架Token刷新机制：**

| 框架 | Token过期时间 | 刷新时机 |
|------|-------------|---------|
| Laravel | 2小时 | 每次表单渲染 |
| Django | 默认无限或自定义 | 表单渲染 |
| Spring Security | 可配置 | 会话创建 |

**典型示例：**
```
请求1: GET /api/form → Token: abc123
请求2: GET /api/form → Token: xyz456（新Token）
请求3: POST /api/submit → Token: abc123（旧Token）
响应3: 419 Page Expired
说明: 扫描器多线程导致Token不同步，这是正常防御
```

**扫描器特征识别：**

| 识别特征 | 说明 | 示例 |
|----------|------|------|
| User-Agent | 包含扫描器标识 | "Mozilla/5.0 (compatible; scanner/1.0)" |
| 请求频率 | 短时间大量请求 | 1秒内10+个请求 |
| 请求顺序 | 非正常用户行为模式 | 并发GET多个表单 |
| 请求头缺失 | 缺少正常浏览器头 | 无Accept、User-Agent等 |
| Referer缺失 | POST请求无Referer | 正常浏览器通常有Referer |

**判定逻辑：**
```
IF 响应码为403或419
AND 响应内容包含Token过期/无效/不匹配错误
AND (User-Agent包含扫描器标识 OR 请求频率异常 OR 并发请求模式异常)
THEN 误报 = True
```

### 场景5：Same-Site Cookie

**特征识别：**
- Set-Cookie包含SameSite=Lax或Strict
- 无CSRF Token

**误报判定依据：**
1. 检查响应头：Set-Cookie包含SameSite属性
2. SameSite值：Lax或Strict
3. Cookie作用域：会话Cookie或认证Cookie

**SameSite值说明：**

| 值 | 行为 | 防御效果 |
|----|------|---------|
| Strict | 所有跨站请求不发送Cookie | 完全防御CSRF |
| Lax | 安全的GET请求发送Cookie | 防御大多数CSRF |
| None | 所有请求发送Cookie | 不防御CSRF（需Secure） |
| 未设置 | 兼容旧浏览器 | 不防御CSRF |

**跨站请求识别方法：**

| 识别方法 | 说明 | 判定条件 |
|----------|------|---------|
| Origin与目标域名对比 | 比较Origin头与目标URL域名 | Origin域名 != 目标域名 |
| Referer与目标域名对比 | 比较Referer头与目标URL域名 | Referer域名 != 目标域名 |
| 缺少Origin/Referer | 正常跨站请求通常有Referer | POST请求无Origin且无Referer |

**典型示例：**
```
响应头:
Set-Cookie: sessionid=abc123; SameSite=Lax; Secure; HttpOnly
请求头:
Origin: https://evil.com
目标域名: https://example.com
说明: SameSite=Lax阻止跨站POST请求携带Cookie
```

**判定逻辑：**
```
IF 响应头Set-Cookie包含SameSite=Lax或Strict
AND Cookie为会话或认证Cookie
AND (Origin域名 != 目标域名 OR Referer域名 != 目标域名 OR POST请求无Origin且无Referer)
AND 请求方法为POST/PUT/DELETE/PATCH
THEN 误报 = True
```

### 场景6：自定义请求头防御

**特征识别：**
- 请求包含X-Requested-With等非标准头
- 跨域请求无法设置

**误报判定依据：**
1. 检查请求头：存在X-Requested-With、X-Requested-By等
2. 同源策略：非简单请求需CORS预检
3. 跨站限制：跨站请求无法设置自定义请求头

**自定义请求头：**

| 请求头名 | 用途 | 防御原理 |
|----------|------|---------|
| X-Requested-With | 标识AJAX请求 | 跨站无法设置 |
| X-CSRF-Protection | CSRF防护标识 | 跨站无法设置 |
| X-Requested-By | 自定义防御 | 跨站无法设置 |

**典型示例：**
```
请求头:
X-Requested-With: XMLHttpRequest
说明: 浏览器同源策略阻止跨站请求设置此头
```

**判定逻辑：**
```
IF 请求包含自定义请求头（X-Requested-With、X-Requested-By等）
AND 请求方法为POST/PUT/DELETE/PATCH
AND 响应成功（200系列状态码，非403/401错误）
THEN 误报 = True
```

### 场景7：JWT/无状态Token

**特征识别：**
- Authorization: Bearer Token
- 无Session Cookie

**误报判定依据：**
1. 认证方式：使用JWT或Bearer Token
2. Token传递：通过Authorization请求头
3. 浏览器行为：跨站请求不会自动携带Token

**JWT认证特征：**

| 特征 | 示例 | 说明 |
|------|------|------|
| Authorization头 | Authorization: Bearer eyJ... | Token在请求头 |
| 无Session Cookie | Cookie中无会话ID | 无状态认证 |
| Token格式 | JWT三段式 | header.payload.signature |

**典型示例：**
```
请求头:
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
说明: JWT Token在请求头中，跨站请求无法携带
```

**判定逻辑：**
```
IF 请求包含Authorization: Bearer头
AND 使用JWT或无状态Token认证
AND 无Session Cookie或Token在Cookie中
THEN 误报 = True
```

### 场景8：验证码前置

**特征识别：**
- 请求包含captcha/verify_code字段
- 验证码验证通过

**误报判定依据：**
1. 验证码字段：请求包含captcha、verify_code、code等字段
2. 验证通过：请求成功返回200
3. 人工交互：需要用户主动输入

**验证码类型：**

| 验证码类型 | 字段名 | 特征 |
|-----------|--------|------|
| 图片验证码 | captcha、verify_code | 需识别图片 |
| 短信验证码 | sms_code、phone_code | 需接收短信 |
| 邮箱验证码 | email_code | 需接收邮件 |
| 滑块验证 | slider_token | 需滑动验证 |

**典型示例：**
```
请求: POST /api/transfer
请求体: {"to_account": "123", "amount": 100, "captcha": "AB12"}
响应: {"success": true}
说明: 验证码验证通过，CSRF攻击无法自动完成
```

**判定逻辑：**
```
IF 请求包含验证码字段（captcha、verify_code、sms_code等）
AND 验证码验证通过（响应成功）
THEN 误报 = True
```

### 场景9：幂等操作

**特征识别：**
- 重复请求不产生累积影响
- 操作为PUT或特定业务逻辑

**误报判定依据：**
1. 请求方法：PUT或可重复的操作
2. 操作效果：重复执行不产生额外危害
3. 业务语义：状态更新而非状态创建/删除

**幂等操作类型：**

| 操作类型 | HTTP方法 | 幂等性 | 特征 |
|----------|----------|--------|------|
| 更新资源 | PUT | 是 | 路径包含资源ID |
| 部分更新 | PATCH | 可能 | 路径包含资源ID |
| 激活/禁用 | POST | 是（同状态） | 参数包含status、activate等 |
| 状态切换 | POST | 是（状态可逆） | 参数包含toggle、switch等 |

**幂等操作识别特征：**

| 识别特征 | URL路径示例 | 参数名示例 |
|----------|-------------|-----------|
| 资源ID模式 | /api/user/123 | 路径包含ID |
| 状态关键字 | /api/activate | activate、deactivate、toggle、switch |
| 更新关键字 | /api/update | update、modify、change |

**典型示例：**
```
请求: PUT /api/user/123/status
请求体: {"status": "active"}
说明: 多次执行结果相同，不会产生累积危害
```

**判定逻辑（置信度：中）：**
```
IF 请求方法为PUT或PATCH
OR (请求方法为POST AND URL路径包含资源ID模式)
OR (请求方法为POST AND URL路径或参数包含activate/deactivate/toggle/switch/update等关键字)
AND 操作为状态更新而非状态创建/删除
THEN 误报 = True
```

**注意：** 幂等操作判定需要结合业务上下文，如操作涉及金额转账、发送通知等副作用，则不应判定为误报。

### 场景10：合理禁用的框架防护

**特征识别：**
- API服务
- 框架CSRF被主动关闭

**误报判定依据：**
1. 服务类型：纯API服务，非浏览器客户端
2. 框架配置：CSRF防护被禁用
3. 客户端类型：移动应用、桌面应用等

**API服务特征：**

| 特征 | 示例 | 说明 |
|------|------|------|
| 响应格式 | application/json | API特征 |
| URL路径 | /api/v1/ | API路径模式 |
| 认证方式 | API Key、JWT | 独立认证 |
| 无HTML内容 | 响应体无HTML标签 | API特征 |

**典型示例：**
```
请求: POST /api/v1/resource
请求头:
User-Agent: MyApp/1.0
Authorization: Bearer api_key_abc
响应: Content-Type: application/json
说明: API服务，使用独立认证，禁用CSRF防护是合理的
```

**判定逻辑（置信度：中）：**
```
IF URL路径符合API模式（严格匹配/api/v1/等版本化模式）
AND 响应Content-Type为application/json
AND 响应体为纯JSON格式（无HTML标签）
AND 使用独立认证（API Key、JWT、Bearer Token）
AND 无Session Cookie或Cookie仅用于状态管理（如保持状态）
THEN 误报 = True
```

### 场景11：API网关/微服务架构

**特征识别：**
- 内部服务通信
- 服务间调用

**误报判定依据：**
1. 调用来源：内网IP或可信来源
2. 服务标识：请求包含服务标识
3. 通信协议：内部服务间通信

**微服务特征：**

| 特征 | 示例 | 说明 |
|------|------|------|
| 来源IP | 10.0.0.0/8、172.16.0.0/12 | 内网IP |
| 服务标识 | X-Service-Name、X-Source-Service | 服务标识 |
| 请求头 | Authorization内部签名 | 服务间认证 |

**典型示例：**
```
请求: POST /api/internal/notify
请求头:
X-Service-Name: payment-service
X-Internal-Secret: shared_secret
说明: 内部服务间通信，无需CSRF防护
```

**判定逻辑：**
```
IF 请求来自内网IP或可信来源
AND 请求包含服务标识或内部认证
AND 为内部服务间通信
THEN 误报 = True
```

### 场景12：移动应用请求

**特征识别：**
- User-Agent标识移动应用
- 非浏览器环境

**误报判定依据：**
1. User-Agent：包含移动应用标识
2. 设备特征：移动设备标识
3. 非浏览器：不使用浏览器Cookie

**移动应用特征：**

| 特征 | 示例 | 说明 |
|------|------|------|
| User-Agent | MyApp/1.0 (iOS) | 应用标识 |
| 设备ID | X-Device-ID: xxx | 设备标识 |
| Token位置 | Authorization头 | 非Cookie |

**典型示例：**
```
请求: POST /api/user/update
请求头:
User-Agent: MyApp/1.0 (iOS 15.0)
Authorization: Bearer mobile_token_abc
说明: 移动应用请求，非浏览器环境，无需CSRF防护
```

**判定逻辑：**
```
IF User-Agent标识为移动应用（如MyApp/1.0）
AND Token通过请求头而非Cookie传递
AND 请求来自移动设备
THEN 误报 = True
```

### 场景13：IP白名单限制

**特征识别：**
- 请求来源在IP白名单内
- 管理员操作或受限操作

**误报判定依据：**
1. 来源IP：在白名单内
2. 操作类型：管理员操作或受限操作
3. IP限制：白名单外的IP无法访问

**典型示例：**
```
请求: POST /api/admin/settings
来源IP: 192.168.1.100
说明: IP在管理员白名单内，外部IP无法访问
```

**判定逻辑：**
```
IF 请求来源IP在白名单内
AND 操作为管理员操作或受限操作
THEN 误报 = True
```

### 场景14：时间窗口验证

**特征识别：**
- 请求包含时间戳
- 时间窗口内有效

**误报判定依据：**
1. 时间戳字段：请求包含timestamp、time、nonce等字段
2. 签名字段：请求包含signature、sign、hmac等字段
3. 响应成功：时间验证和签名验证通过

**典型示例：**
```
请求: POST /api/payment
请求体: {"amount": 100, "timestamp": 1700000000, "signature": "abc123"}
说明: 时间窗口验证和签名验证，重放攻击无效
```

**判定逻辑：**
```
IF 请求包含时间戳字段（timestamp、time、nonce等）
AND 请求包含签名字段（signature、sign、hmac等）
AND 响应成功（时间验证和签名验证通过）
THEN 误报 = True
```

### 场景15：GraphQL mutation幂等

**特征识别：**
- GraphQL mutation操作
- 操作为幂等或只读

**误报判定依据：**
1. 请求协议：GraphQL
2. 操作类型：mutation
3. 业务语义：幂等或只读操作

**GraphQL操作识别特征：**

| 识别特征 | URL路径示例 | mutation关键字 |
|----------|-------------|----------------|
| GraphQL路径 | /graphql、/api/graphql | URL包含graphql |
| mutation关键字 | mutation { ... } | 请求体以mutation开头 |

**典型示例：**
```
请求: POST /graphql
请求体:
{
  "query": "mutation { updateUserStatus(id: 123, status: ACTIVE) { id status } }"
}
说明: GraphQL mutation，但为幂等操作
```

**判定逻辑：**
```
IF URL路径包含graphql
OR 请求体包含mutation关键字
AND 操作为幂等或只读操作（通过mutation名称或参数判断）
AND 重复执行不产生额外危害
THEN 误报 = True
```

### 场景16：API密钥认证

**特征识别：**
- 使用API Key认证
- 无Session Cookie

**误报判定依据：**
1. 认证方式：API Key或API Token
2. 传递方式：通过请求头传递
3. 无Cookie：不使用Cookie认证

**API密钥认证特征：**

| 识别特征 | 请求头示例 | 说明 |
|----------|-----------|------|
| X-API-Key | X-API-Key: sk_test_abc | API密钥 |
| Authorization | Authorization: Bearer sk_test_abc | Bearer Token |
| x-api-token | x-api-token: abc | API Token |

**典型示例：**
```
请求: POST /api/v1/resource
请求头:
X-API-Key: sk_test_abc123
说明: API Key认证，无CSRF风险
```

**判定逻辑：**
```
IF 请求使用API Key认证（X-API-Key、x-api-token等）
AND Key通过请求头传递
AND 不使用Cookie认证（无Session Cookie或Cookie仅用于状态管理）
THEN 误报 = True
```

### 场景17：敏感操作二次确认

**特征识别：**
- 需要输入确认信息
- 密码或特殊验证

**误报判定依据：**
1. 确认字段：请求包含confirm_password、confirm_code、verification_code等字段
2. 响应成功：确认信息验证通过
3. 敏感操作：高危操作

**敏感操作识别特征：**

| 识别特征 | URL路径示例 | 确认字段示例 |
|----------|-------------|-------------|
| 删除操作 | /api/delete、/api/remove | confirm_password |
| 密码修改 | /api/change-password、/api/password | old_password、new_password、confirm_password |
| 邮箱修改 | /api/change-email、/api/email | verify_code |
| 支付操作 | /api/transfer、/api/payment | payment_password、verify_code |

**典型示例：**
```
请求: POST /api/account/delete
请求体: {"confirm_password": "xxx", "reason": "xxx"}
响应: {"success": true}
说明: 需要密码确认，CSRF攻击无法自动完成
```

**判定逻辑：**
```
IF URL路径包含delete、remove、change-password、change-email、transfer、payment等敏感操作关键字
AND 请求包含确认字段（confirm_password、old_password、verify_code、verification_code等）
AND 响应成功（确认信息验证通过）
THEN 误报 = True
```

## 非误报判定标准

### 真实CSRF告警特征

若不满足上述任何误报场景，且存在以下明确CSRF漏洞特征，则判定为**真实告警**：

#### 1. 缺少CSRF防护

**特征：**
- 状态变更请求无CSRF Token
- 无SameSite Cookie
- 无来源验证
- 无二次验证

**判定：**
```
IF 请求为状态变更操作（POST/PUT/DELETE/PATCH）
AND 请求无CSRF Token
AND Cookie无SameSite=Lax/Strict
AND 无Origin/Referer白名单验证
AND 无自定义请求头防御
AND 无验证码或二次验证
AND 使用Session Cookie认证
THEN 真实告警 = True
```

#### 2. CSRF Token无效

**特征：**
- 请求包含CSRF Token
- Token验证失败但仍接受请求
- 或Token可预测

**判定：**
```
IF 请求包含CSRF Token
AND Token验证失败但请求成功
OR Token可预测或静态不变
THEN 真实告警 = True
```

#### 3. 跨站请求成功

**特征：**
- 模拟跨站请求
- 请求成功执行状态变更
- 无任何CSRF防护

**判定：**
```
IF 模拟跨站请求（无Cookie、无Origin/Referer）
AND 请求成功执行状态变更
AND 无CSRF防护措施
THEN 真实告警 = True
```

#### 4. SameSite=None不安全

**特征：**
- Set-Cookie: SameSite=None但缺少Secure属性
- 或Cookie可在跨站请求中使用

**判定：**
```
IF Cookie设置SameSite=None
AND 缺少Secure属性
OR Cookie可在跨站请求中使用
AND 存在状态变更操作
THEN 真实告警 = True
```

## 判定流程图

```
开始分析CSRF注入告警
    │
    ▼
提取请求头、响应头和请求体
    │
    ▼
识别编码方式并解码（最多10层）
    │
    ▼
检查请求方法和业务语义
    │
    ▼
┌─────────────────────────────────────────────────────────────┐
│ 检查误报场景（按优先级1-17）                                 │
├─────────────────────────────────────────────────────────────┤
│ 高优先级（防御机制明确，直接验证）                           │
│ ├─ 场景1: 双重提交Cookie（SPA+Axios）                        │
│ ├─ 场景7: JWT/无状态Token                                   │
│ └─ 场景5: Same-Site Cookie                                  │
│                                                              │
│ 中高优先级（业务语义或防御特征明确）                         │
│ ├─ 场景2: 只读操作（无状态变更）                            │
│ ├─ 场景6: 自定义请求头防御                                  │
│ ├─ 场景8: 验证码前置                                       │
│ ├─ 场景3: 二次验证/来源校验                                │
│ ├─ 场景12: 移动应用请求                                    │
│ └─ 场景16: API密钥认证                                     │
│                                                              │
│ 中优先级（需分析操作效果或架构特征）                         │
│ ├─ 场景9: 幂等操作                                         │
│ ├─ 场景11: API网关/微服务架构                              │
│ ├─ 场景10: 合理禁用的框架防护                              │
│ ├─ 场景15: GraphQL mutation幂等                            │
│ ├─ 场景13: IP白名单限制                                    │
│ └─ 场景14: 时间窗口验证                                    │
│                                                              │
│ 低优先级（需推断或上下文依赖）                              │
│ ├─ 场景4: 扫描器会话/Token不同步                           │
│ └─ 场景17: 敏感操作二次确认                                │
└─────────────────────────────────────────────────────────────┘
    │
    ├─ 匹配任一误报场景 ──► 误报 = True ──► 记录匹配场景和置信度
    │
    └─ 无匹配 ──► 检查真实CSRF特征
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
1. 首先检查请求方法和业务语义
2. 检测并解码编码内容（最多10层）
3. 按优先级从高到低检查误报场景
4. 匹配到第一个场景即判定为误报，记录场景编号和置信度
5. 如无匹配，检查真实CSRF特征
6. 如仍无法判定，标记为待人工复核

## 判定示例

### 示例1：误报 - 双重提交Cookie

```
请求: POST /api/user/update
请求头:
X-CSRF-TOKEN: abc123xyz
Cookie: XSRF-TOKEN=abc123xyz
响应: {"success": true}
分析: 双重提交Cookie模式，防御有效
判定: 误报（场景1）
```

### 示例2：误报 - 只读操作

```
请求: POST /api/search
请求体: {"query": "test", "filters": {"type": "user"}}
响应: {"results": [...]}
分析: 虽然是POST，但仅为复杂查询，无状态变更
判定: 误报（场景2）
```

### 示例3：误报 - Same-Site Cookie

```
请求: POST /api/settings/update
Cookie: sessionid=abc123; SameSite=Lax; Secure
响应: {"success": true}
分析: SameSite=Lax防御大多数CSRF攻击
判定: 误报（场景5）
```

### 示例4：误报 - JWT认证

```
请求: POST /api/resource/create
请求头:
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9...
Cookie: 无会话Cookie
响应: {"success": true}
分析: JWT Token在请求头中，跨站请求无法携带
判定: 误报（场景7）
```

### 示例5：误报 - 验证码前置

```
请求: POST /api/transfer
请求体: {"to_account": "123", "amount": 100, "captcha": "AB12"}
响应: {"success": true}
分析: 验证码验证通过，CSRF攻击无法自动完成
判定: 误报（场景8）
```

### 示例6：误报 - 移动应用请求

```
请求: POST /api/user/update
请求头:
User-Agent: MyApp/1.0 (iOS 15.0)
Authorization: Bearer mobile_token_abc
响应: {"success": true}
分析: 移动应用请求，非浏览器环境
判定: 误报（场景12）
```

### 示例7：真实告警 - 缺少CSRF防护

```
请求: POST /api/user/delete
请求头:
Cookie: sessionid=abc123
响应: {"success": true}
分析: 状态变更请求，无CSRF Token、无SameSite Cookie、无来源验证
判定: 真实告警（缺少CSRF防护）
```

### 示例8：真实告警 - SameSite=None不安全

```
请求: POST /api/settings/update
Cookie: sessionid=abc123; SameSite=None
响应: {"success": true}
分析: SameSite=None但缺少Secure属性
判定: 真实告警（SameSite=None不安全）
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
    "请求方法": "POST/PUT/DELETE",
    "请求头": {
      "X-CSRF-TOKEN": "Token值",
      "Authorization": "认证信息",
      "Origin": "来源",
      "Referer": "来源"
    },
    "Cookie": "Cookie内容",
    "请求体": "请求体内容",
    "业务语义": "操作描述"
  },
  "响应分析": {
    "响应码": "HTTP状态码",
    "响应头": {
      "Set-Cookie": "Cookie设置",
      "Content-Security-Policy": "CSP策略（如有）"
    },
    "响应内容摘要": "关键响应内容",
    "防御机制": "CSRF防御机制描述"
  },
  "CSRF类型": "传统Token/双重提交Cookie/SameSite/自定义请求头/JWT（若适用）",
  "置信度": "高/中/低"
}
```

### 使用说明

1. **触发条件**：当用户需要分析CSRF注入类告警时使用此cookbook
2. **分析步骤**：
   - 提取请求头、响应头和请求体
   - 识别并解码编码内容
   - 首先检查高优先级场景（防御机制明确）
   - 按优先级检查误报场景
   - 如无匹配，检查真实CSRF特征
   - 输出判定结果和依据

3. **置信度评估**：
   - 高：明确匹配误报场景或真实CSRF特征，防御机制或漏洞明确
   - 中：部分匹配，需要额外上下文确认或推断类场景
   - 低：无明确特征，需要人工复核

## 注意事项

1. **编码识别优先级**：按URL编码 → Base64 → Hex → Unicode → HTML实体 → JSON编码 → 多重编码的顺序检测
2. **编码检测流程**：最多解码10层或直到内容不再变化，防止解码循环
3. **请求方法分析**：重点分析POST/PUT/DELETE/PATCH等状态变更请求
4. **业务语义分析**：结合URL路径、参数名判断操作是否为只读
5. **防御机制分析**：优先检查现代防御机制（SameSite、双重提交Cookie、JWT）
6. **响应头优先检查**：Set-Cookie、CSP等响应头是快速判定的重要依据
7. **误报场景覆盖**：确保覆盖所有17个误报场景
8. **场景优先级**：高优先级场景优先匹配，低优先级场景需要更多上下文验证
9. **无法判定处理**：对于无法判定的告警，标记为"待人工复核"并记录原因
10. **场景冲突处理**：多场景匹配时选择优先级最高的，或标记为"多场景匹配"
11. **现代防御机制**：注意SameSite Cookie、JWT、双重提交Cookie等现代防御方式
12. **非浏览器环境**：注意移动应用、API服务等非浏览器环境，这些环境天然防御CSRF
13. **业务上下文**：结合具体业务场景判断，如只读操作、幂等操作等
14. **扫描器特征**：识别扫描器请求（短时间大量请求、User-Agent特征）
