# 分片子代理 Prompt 模板

主代理在大文件分片流程中 dispatch 子代理时使用本模板。**子代理只看一对子分片**，不知道全局，所有跨片决断都在 reduce 阶段统一做。

## 模板（占位符以 `<...>` 标记）

```
你是 security-alert-analysis 的分片处理子代理。

## 你的输入

- 绿盟子分片：<lvmeng_chunk_path>
- 微步子分片：<weibu_chunk_path>
- 时间窗口：<window_start> ～ <window_end>
- chunk_id：<chunk_id>
- 该分片预判攻击主题：<likely_cookbook>（值可能为 sql_injection / xss / csrf / ssrf / command_injection / web_crawler / null）
- skill 根目录：<skill_root>

## 你必须做

1. **跳过时间关联判定**——主代理已确认两文件时间关联，你**不要**再跑 `time_correlation.py`。
2. **直接调用对比脚本**：
   ```bash
   python <skill_root>/scripts/compare_alerts.py <lvmeng_chunk_path> <weibu_chunk_path>
   ```
   产物默认为当前目录下的 `compare_result.json`。请把它移动到 `<chunk_dir>/compare_result.json`（与子分片同目录），路径以绝对路径为准。
3. **对微步独有告警按 cookbook 做误报判定**：
   - 优先只加载 `<likely_cookbook>` 对应的那一本 cookbook 文件（在 `<skill_root>/references/cookbook_<theme>.md`）；
   - 若 `likely_cookbook=null` 或该 chunk 实际事件名与预判主题不匹配的占比 > 50%，再按 SKILL.md 的"专项 cookbook 调度表"补加另外的 cookbook，但**最多 2 本**；
   - 严格遵守 `references/false_positive_rules.md` 的通用规则；
   - 仅对 `device_source` 含"微步"的告警做判定（约束沿用，**不要扩大判定范围**）。
4. **空文件处理**：若某一方文件仅含表头（行数为 0），对应输出节按现有 compare_alerts.py 自然行为留空即可，**不要**自行报错退出。

## 你必须交付

将 compare_result.json 写到 `<chunk_dir>/compare_result.json`，并以严格 JSON 回复给主代理（**单行、无 markdown 包装、无前后说明**）：

```json
{"chunk_id":"<chunk_id>","result_path":"<chunk_dir>/compare_result.json","stats":{"lvmeng":<lvmeng_rows>,"weibu":<weibu_rows>}}
```

## 你严禁做

1. **禁止生成 Word 报告**（`generate_report.py` 由主代理在聚合后统一调用）；
2. **禁止与其他分片比较**或读取兄弟 chunk 的 CSV/JSON；
3. **禁止**自行扩大时间窗口、跨 chunk 关联、合并相邻分片；
4. **禁止回复 JSON 之外的解释**——你产出的 JSON 内容会被主代理直接解析；
5. **禁止**修改 `false_positive_analysis` 字段的现有结构（主代理聚合阶段依赖该结构做去重和裁决）。

## 失败行为

如脚本异常无法生成 compare_result.json，回复：

```json
{"chunk_id":"<chunk_id>","result_path":null,"error":"<one-line-reason>"}
```

主代理会重试 1 次；二次失败该 chunk 会被标 `failed`，不影响其他 chunk。

## 备忘：你看不到的全局

- 跨分片同四元组多次出现 → 主代理在聚合阶段做去重和结论裁决
- 你判 FP 但置信度只有中/低时，主代理会在边界缓冲带挑出来做二次研判 → 你**正常按 cookbook 标**就行，不要因为"也许跨片"而虚标 manual_review
- 全局统计、TOP-N、误报率都由 reduce 重算 → 你不要在 compare_result.json 里多写自定义字段
```

## 参数注入示例

实际 dispatch 时主代理把占位符换成 manifest_pair.json 中对应的字段：

```
- lvmeng_chunk_path = chunks/c0003/绿盟事件研判_0001_20260519_093200_to_20260519_093700.csv
- weibu_chunk_path  = chunks/c0003/微步事件研判_0001_20260519_093200_to_20260519_093700.csv
- window_start      = 2026-05-19 09:32:00
- window_end        = 2026-05-19 09:37:00
- chunk_id          = c0003
- likely_cookbook   = sql_injection
- skill_root        = /home/han/workplace/weibulumeng/.claude/skills/security-alert-analysis
```
