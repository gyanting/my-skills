---
name: security-alert-analysis
description: 对绿盟（NSFOCUS）、微步（ThreatBook）等网络安全设备的告警 CSV 做深度对比分析——能力差异、四元组对齐、微步独有告警的误报判定、改进建议、最终输出 Word 报告。只要用户提到"告警对比"、"日志对比"、"误报判定"、"误报率"、"绿盟微步"、"NSFOCUS / ThreatBook"、"IDS/IPS 对比"、"安全设备 CSV"、"四元组对齐"、"漏洞检测能力差异"，或拿来两个安全设备的 CSV/日志希望知道差在哪，都必须使用此技能，即便用户没明说"对比"二字。
---

# Security Alert Analysis

把绿盟和微步两家安全设备的告警 CSV 对齐后做深度对比，目的：

1. 量化两家的检测能力差异
2. 对微步独有告警逐条做误报判定（高/中/低置信度）
3. 针对绿盟未覆盖的真实漏洞给出补规则建议
4. 输出 Word 分析报告

**角色定位：** 你是一名网络安全数据分析师，专注安全设备告警日志的对比分析。

## 输入与文件结构

CSV 字段定义、列差异、设备来源字段提取规则见 [references/csv_schema.md](references/csv_schema.md)。需要了解时再读，不必每次加载。

要点速记：
- 编码 **GB18030**（中文乱码的根因）
- 单文件**典型** ≤ 6000 条；超过 **10000 条** 或 **5 MB** 即视为"大文件"，走 [大文件分片处理流程](#大文件分片处理流程)
- 厂商识别：CSV "设备来源"字段优先，文件名前缀兜底
- 四元组 = (源IP, 源端口, 目的IP, 目的端口)，是告警对齐的索引

## 核心分析流程

### 第一步：时间关联判定

```bash
python scripts/time_correlation.py <绿盟文件> <微步文件>
```

判定两个文件是否覆盖同一段流量。判定规则详见 [references/time_correlation_rules.md](references/time_correlation_rules.md)。

输出 JSON：`is_related`、`relation_type`（完全包含/部分重叠/首尾相接/时间断层/完全分离）、`analysis`。

### 第二步：根据时间关联结果分流

**关联 →** 对比分析

```bash
python scripts/compare_alerts.py <绿盟文件> <微步文件>
```

以四元组为索引，对齐绿盟和微步的告警，比较：
- 告警一致性：同一四元组下，事件名称、事件类型、攻击结果判定是否一致
- 差异分析：流量归属判定、攻击事件归属、检测能力差异

**不关联 →** 分别独立分析

```bash
python scripts/analyze_single_vendor.py <文件> <厂商名>
```

不做四元组对比——双方看的本就不是同一段流量。

### 第三步：微步独有告警误报判定

对**仅微步检测到、绿盟漏检**的告警逐条判定真伪。通用规则（业务流量识别、置信度分级、编码绕过总表、输出字段）见 [references/false_positive_rules.md](references/false_positive_rules.md)。

**按攻击类型调度专项 Cookbook：** 针对每条微步独有告警，根据其"事件类型"或"事件名称"读取**对应的一本** cookbook（不要全部加载，每本 900-1300 行）：

| 告警事件类型关键词 | 读取的 cookbook |
|---|---|
| SQL 注入 / SQLi / `union select` / `or 1=1` 等特征 | [references/cookbook_sql_injection.md](references/cookbook_sql_injection.md) |
| XSS / 跨站脚本 / `<script>` / 反射型/存储型 | [references/cookbook_xss.md](references/cookbook_xss.md) |
| CSRF / 跨站请求伪造 | [references/cookbook_csrf.md](references/cookbook_csrf.md) |
| SSRF / 服务器端请求伪造 / 内网探测 | [references/cookbook_ssrf.md](references/cookbook_ssrf.md) |
| 命令注入 / RCE / 远程命令执行 / Shell 注入 | [references/cookbook_command_injection.md](references/cookbook_command_injection.md) |
| 爬虫 / Bot / 异常 UA / 自动化扫描 | [references/cookbook_web_crawler.md](references/cookbook_web_crawler.md) |

事件类型不在上表的，使用 false_positive_rules.md 的通用规则；若专项 cookbook 与通用规则冲突，以专项为准（专项更贴近该攻击类型的真实特征）。

### 第四步：绿盟改进建议

针对"微步报了、绿盟漏了、且经判定为真阳性"的漏洞，按三档给建议：

| 建议等级 | 标准 | 响应时效 |
|----------|----------|----------|
| 强烈建议 | 漏洞影响大、破坏度高、已在野利用或被广泛利用 | 1–2 周内补规则 |
| 建议 | 漏洞影响中等、有一定利用难度、影响范围有限 | 1 个月内补规则 |
| 可以忽略 | 影响小、利用条件苛刻、已过时或极少出现 | 酌情处理 |

评估维度：CVSS 评分、攻击复杂度、权限要求、是否需要交互、EXP 成熟度、是否在 CISA KEV 目录。

### 第五步：生成 Word 报告

```bash
python scripts/generate_report.py <分析结果.json> <输出.docx>
```

## 输出报告结构

### 一、分析总览

| 统计项 | 说明 |
|--------|------|
| 绿盟独有告警事件总数 | 微步未检测到的告警 |
| ├─ 中高风险事件 | CVSS ≥ 7.0 |
| └─ 可忽略事件 | CVSS < 4.0 |
| 微步独有告警事件总数 | 绿盟未检测到的告警 |
| ├─ 中高风险事件 | 需重点关注的安全缺口 |
| └─ 可忽略事件 | 优先级较低 |
| 交叉告警事件总数 | 双方均检测到 |
| 四元组匹配总数 | 参与对比的唯一连接数 |

### 二、微步独有告警数据质量分析

对每条微步独有告警输出：置信度、是否误报、误报原因说明、编码绕过检测、判定证据。

统计：微步独有告警总数 / 误报数 / 真阳性数 / 需人工审核数 / 误报率。

### 三、微步独有告警详细分析与建议

针对绿盟未覆盖的每个漏洞类型，给出：

1. **漏洞基本信息** — 名称、CVE、CVSS、影响系统
2. **攻击原理** — 技术原理、攻击链阶段、真实案例（如有）
3. **绿盟缺口分析** — 缺失原因、当前检测盲区
4. **改进建议** — 等级 + 理由 + 检测规则示例 / 特征提取方式

## 关键约束

### 文件配对：严格一对一

每个文件最多与一个时间关联的文件配对。**为什么：** 让"独有告警数 = 对方未检测到的告警数"严格成立。允许一对多会让同一份流量被多对重复计入，差异统计虚高。

正确：A ↔ B（仅一次）
错误：A 同时和 B、C 对比；或 A↔B 之后又 A↔C

> **大文件分片场景下的约束语义**：从"文件级一对一"变为"chunk 级一对一"——每个时间窗口内绿盟分片与微步分片仍然严格一对一配对，由 `split_by_time_pair.py` 共享时间桶天然保证。**不要**误以为分片让约束失效。

### 完成前自查

| 校验项 | 含义 |
|--------|------|
| 时间一致性 | 对比的两个文件时间必须关联，不跨时间段 |
| 会话一致性 | 仅比较相同四元组的告警，不同连接不混比 |
| 分析严谨性 | 漏洞分析客观有据，不模板化，不误判攻击类型 |
| 建议可行性 | 改进建议可落地，含技术实现参考 |
| 配对合规性 | 不出现 A 文件同时配对 B 厂商多个文件 |
| 误报分析完整性 | 微步告警必须含完整误报判定字段 |
| 误报范围 | 误报判定仅针对设备来源含"微步"的告警 |
| 不确定标注 | 无法判定的标"需人工审核"，不胡乱选边 |
| 分片完整性 | 大文件场景：sum(chunk_rows) + unparsed_rows + corrupt_rows == 源文件总行数 |
| 裂痕二次研判 | 大文件场景：`boundary_seam_candidates` 已全部走过主代理 LLM 二次研判（或显式标记为空候选） |

## 执行流程

```
开始 → 扫描/读入文件 → 判超阈（行 > 10000 或 > 5MB？）
                            │
        ┌───────────────────┴───────────────────┐
        ▼                                       ▼
       否                                      是
        │                                       │
   时间关联判定                          大文件分片处理流程
        │                                  （见下方专章）
  ┌─────┴─────┐
  ▼           ▼
关联       不关联
  │           │
四元组对齐    各厂商独立分析
+ 误报判定       │
  │          输出各自 JSON
生成 Word 报告
```

## 批量目录处理流程

面对一个含多个 CSV 的目录时（典型场景：用户扔来一整批日志），由你亲自编排以下步骤——不要找现成的 all-in-one 入口脚本。这样做的关键好处：配对完成后你能停下来逐条按 cookbook 做误报判定，而不是被脚本一口气跑完跳过第三步。

### 1. 扫描 + 厂商识别

- 列出目录下所有 `*.csv`
- 对每个文件用 `pandas.read_csv(..., encoding='gb18030', nrows=1)` 读出 "设备来源" 字段，按 [references/csv_schema.md](references/csv_schema.md) 的剥离规则提取厂商；为空或得 "未知厂商" 时回退文件名前缀（`绿盟事件研判→绿盟`、`微步事件研判→微步`）
- 用 `scripts/time_correlation.py` 的 `parse_time_from_filename` 解析每个文件的时间范围
- 产出一张"文件 → 厂商 → 起止时间"映射表

### 2. 文件配对（两轮策略）

**为什么分两轮：** 跨厂商配对的信息量最大（同一段流量两家设备各看到什么），优先消化；同厂商配对仅用于补全分析覆盖面。

**第一轮 — 跨厂商配：** 遍历每个未配对文件，找一个**不同厂商**且时间关联的最佳对手；多个候选时按下表评分取最高者。

| 关联类型 | 评分 |
|----------|------|
| 完全包含 | 3 |
| 部分重叠 | 2 |
| 首尾相接 | 1 |

**第二轮 — 同厂商配：** 第一轮剩下的文件之间互相配，同上评分规则。

约束：每个文件最多被配一次（严格一对一，见下方"关键约束"）。

### 3. 逐对分析

为每一对建一个子目录（建议命名 `配对1/`、`配对2/`...），然后：

- `is_related=true` → 走"核心分析流程"第二步起：`compare_alerts.py` → 第三步逐条按 cookbook 判定 → `generate_report.py`
- `is_related=false` → 各跑一遍 `analyze_single_vendor.py`，分别输出 JSON，不生成联合报告

### 4. 未配对文件 + 回填

剩余未配对的文件用 `analyze_single_vendor.py` 单独分析，输出到 `单独分析_厂商名/厂商名_analysis_result.json`。

**回填语义：** 若某未配对文件的厂商也参与了别的配对（比如绿盟有 3 个文件，其中 2 个配上微步、1 个落单），把这份落单文件的分析作为该厂商的"优势项"附加到对应配对的 `compare_result.json` 后重跑 `generate_report.py`——目的是让最终报告完整反映该厂商的检测覆盖，而不是只看配对的那一段流量。

### 推荐输出目录结构

```
report/
├── 配对1/
│   ├── 绿盟_vs_微步_分析报告.docx
│   ├── compare_result.json
│   └── time_correlation_result.json
├── 配对2/
│   └── ...
└── 单独分析_绿盟/
    └── 绿盟_analysis_result.json
```

## 大文件分片处理流程

当一对绿盟/微步 CSV 出现"1 小时 ~10 万条"这种生产级规模（**行数 > 10000** 或 **文件大小 > 5 MB**）时，单次喂 `compare_alerts.py` 会让微步独有告警的误报判定环节超出单代理的上下文与时间预算。

**核心思想是 map-reduce**：脚本按**时间窗口**共享桶切两厂商 CSV → 每对子分片 dispatch 一个独立子代理跑完整 skill 流程 → 聚合脚本重算全局统计、识别裂痕 → 主代理对裂痕做二次研判 → 调用现有 `generate_report.py` 出最终 Word 报告。

**为什么按时间窗口切而不是按行数顺序切：** 两厂商共享同一组时间桶 → 绿盟分片与微步分片**天然按 chunk_id 配对**，不需要人工对齐；行数顺序切会破坏四元组对齐语义。

### 1. 时间关联前置

```bash
python scripts/time_correlation.py <绿盟.csv> <微步.csv>
```

**不关联** → 分片流程**不适用**，直接走 `analyze_single_vendor.py` 双独立路径，结束。

### 2. 分片

```bash
python scripts/split_by_time_pair.py <绿盟.csv> <微步.csv> \
    --window-sec 300 --max-rows 10000 --outdir chunks/
```

- `--window-sec 300`（5 分钟）一个桶；某桶超 `--max-rows` 时**优先按时间二分**递归细切，极端"同秒上万条"才按行数硬切并标 `hard_split=true`
- 解析失败的行进 `chunks/__unparsed__/`；设备来源损坏的行进 `chunks/__corrupt__/`——**不丢弃**，供事后回查
- 两文件时间不重叠 → 写 `should_split=false, reason="no_overlap"`，调用方应回退到 single_vendor 路径
- 产物：`chunks/manifest_pair.json` + `chunks/cNNNN/{绿盟,微步}_..._to_....csv`

`manifest_pair.json` 每个 chunk 记录：`chunk_id`、`window`、两个子分片路径、行数、`hard_split`、`likely_cookbook`（基于事件名预判主要攻击主题）、左右邻居 chunk_id。

### 3. 并行 dispatch 子代理

读 `manifest_pair.json`，**每批 ≤ 4 个**子代理（避免每代理重复加载 cookbook + fp_rule_base.yaml 把父代理 context 撑爆），按 chunks 列表分批跑完。

子代理 prompt 套用 [references/subagent_chunk_prompt.md](references/subagent_chunk_prompt.md) 模板，按字面注入 `chunk_id`、两个子分片路径、`window`、`likely_cookbook`、`skill_root`。

**子代理必须只回结构化短摘要**（不返回 JSON 内容）：

```json
{"chunk_id":"c0003","result_path":"chunks/c0003/compare_result.json","stats":{"lvmeng":8432,"weibu":9991}}
```

**失败恢复**：超时 / 返回非法路径 → 重试 1 次；二次失败 → 该 chunk 在聚合阶段当空对处理（行数计入 `failed_chunks`），**绝不**因单片失败终止整流。

### 4. 聚合

```bash
python scripts/aggregate_chunk_results.py \
    --manifest chunks/manifest_pair.json \
    --chunks-dir chunks/ \
    -o final_compare_result.json
```

整合规则（**禁止简单加权或加和**，必须重算）：

- `*_total_alerts` 直接求和
- `unique_four_tuples / common_four_tuples` 用全量 set 操作重算
- `lvmeng_only_alerts / weibu_only_alerts` 按（四元组 + 事件名 + 生成时间）去重；重复保留 `confidence` 最高那条，并记录 `_seen_in_chunks`
- `weibu_fp_stats` 与 `false_positive_rate` 在去重后样本上**重算**——若加权平均会被分片样本量差异扭曲
- 全局 TOP-N（源 IP / 事件名 / 威胁分布）在去重后全集上 `Counter.most_common(N)`

**跨片同四元组+同事件名结论合并裁决**（按优先级从高到低）：

1. 任一片标 `requires_manual_review=True` → 升级为 manual_review
2. 任一片判 `is_false_positive=False` 且 `confidence='高'` → TP
3. 全部片判 FP 且 `confidence ∈ {高, 中}` → FP
4. 其他冲突 → manual_review，理由字段拼"片 X 判 FP / 片 Y 判 TP，结论冲突"

冲突记录写入 `aggregation_audit.json`，每条一行，便于事后人审。

`final_compare_result.json` **字段与现有 `compare_result.json` 同构** → `generate_report.py` 零改动直接消费。追加字段：`aggregation_meta`、`boundary_seam_candidates`、`boundary_seam_reassessment`、`campaign_groups`。

### 5. 分片裂痕二次研判（主代理 LLM 自己做，不再 dispatch）

候选识别已在聚合脚本里完成（写入 `boundary_seam_candidates`），命中条件：

- 当前判 FP 且 `confidence ∈ {中, 低}`
- 生成时间距分片任一端 ≤ `window_sec * 0.1`（默认 30 秒缓冲带）
- 相邻分片中存在同源 IP 告警，间隔 ≤ 60 秒

主代理对每条候选**重新判定**，参照同源 IP 在相邻 chunk 的告警快照看是否形成跨片 campaign。结论按 `four_tuple + event_name + generate_time` 主键 update 进 `final_compare_result.json.weibu_only_alerts`，变更摘要写入 `boundary_seam_reassessment`。

**为什么主代理自己做不再 dispatch**：候选量小（典型 < 5%）、需要跨片全局视角、避免重复加载 cookbook。

**附加机制——campaign 重判**：`campaign_groups` 列出同源 IP 横跨 ≥ 3 个分片的告警序列，主代理把它们当一组慢攻击 campaign 重审，挽回"低速攻击被每片单独判 FP"的退化。

### 6. 生成 Word 报告

```bash
python scripts/generate_report.py final_compare_result.json final_report.docx
```

报告结构与小文件流程一致，仅在页脚附加：分片数、`hard_split` 数、跨片冲突数、`failed_chunks`、裂痕二次研判变更条数。

### 端到端命令串

```bash
# 1. 时间关联
python scripts/time_correlation.py 绿盟.csv 微步.csv
# is_related=true 才继续

# 2. 分片
python scripts/split_by_time_pair.py 绿盟.csv 微步.csv --outdir chunks/

# 3. 你（主代理）：读 chunks/manifest_pair.json，按 ≤4 个/批 dispatch 子代理，每个跑：
#    python scripts/compare_alerts.py <chunk_lvmeng.csv> <chunk_weibu.csv>
#    把产物 mv 到 chunks/cNNNN/compare_result.json

# 4. 聚合
python scripts/aggregate_chunk_results.py \
    --manifest chunks/manifest_pair.json \
    --chunks-dir chunks/ -o final_compare_result.json

# 5. 你（主代理）：对 final_compare_result.json.boundary_seam_candidates 做二次研判，
#    把更新后的 alerts 回写到 final_compare_result.json，并填 boundary_seam_reassessment

# 6. 生成 Word
python scripts/generate_report.py final_compare_result.json final_report.docx
```

## 脚本接口速查

```bash
# 时间关联判定 → JSON: is_related / relation_type / analysis
python scripts/time_correlation.py 绿盟.csv 微步.csv

# 关联场景：对比分析 → compare_result.json
# 内含 weibu_fp_stats + weibu_false_positive_analysis（误报率字段已就绪）
python scripts/compare_alerts.py 绿盟.csv 微步.csv

# 不关联场景：分别独立分析
python scripts/analyze_single_vendor.py 绿盟.csv 绿盟
python scripts/analyze_single_vendor.py 微步.csv 微步

# 生成 Word 报告（读 compare_result.json 或 final_compare_result.json）
python scripts/generate_report.py compare_result.json 分析报告.docx

# === 大文件分片场景专用 ===

# 按时间窗口切一对大 CSV → chunks/manifest_pair.json
python scripts/split_by_time_pair.py 绿盟.csv 微步.csv \
    --window-sec 300 --max-rows 10000 --outdir chunks/

# 聚合所有分片结果 → final_compare_result.json（字段同构 compare_result.json）
python scripts/aggregate_chunk_results.py \
    --manifest chunks/manifest_pair.json --chunks-dir chunks/ \
    -o final_compare_result.json
```

## 脚本依赖

`pandas`、`python-docx`、`python-dateutil`，可选 `chardet`。

## 易踩的坑

1. **编码**：CSV 必须用 `gb18030` 读，否则中文字段（事件名称、设备来源等）会乱码或解析失败
2. **时间解析**：时间在**文件名**里，不在 CSV 内部——别去 CSV 字段里找。**例外**：大文件分片流程里 `split_by_time_pair.py` 才需要读 CSV 内的「生成时间」字段
3. **四元组标准化**：IP 字段可能带括号或内部 IP 标注，比对前需要规范化
4. **载荷字段含多行**：解析时注意 CSV 引号转义和换行处理
5. **报告别模板化**：每个漏洞分析要基于具体载荷/响应体写，不要套话
6. **分片配对必须共享时间桶**：大文件场景下绿盟分片与微步分片必须使用**同一组时间窗口**切分，否则四元组对齐语义被破坏。这一点由 `split_by_time_pair.py` 自动保证——**不要**用其它方式分别切两个厂商的文件
7. **大文件聚合阶段统计必须重算**：合并多个分片的 `compare_result.json` 时，`*_unique_four_tuples`、`*_only_alert_count`、`weibu_fp_stats`、`false_positive_rate`、TOP-N 必须在**去重后**的全量集合上重新计算，**禁止**简单求和或加权平均——分片样本量差异会让加权平均严重失真
