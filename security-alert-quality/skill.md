---
name: security-alert-quality
description: 分析网络安全设备告警日志质量。当用户要求评估安全厂商告警质量、交叉对比多厂商日志、分析误报漏报、基于CSV/JSON日志生成质量报告、或评估单一厂商告警可信度时调用。支持单厂商和多厂商两种场景，由项目经理Agent统筹6个阶段专家Agent串行执行，关键决策节点强制人工确认。
user-invocable: true
allowed-tools:
  - Read
  - Write
  - Edit
  - Bash
  - Agent
  - WebFetch
  - WebSearch
---

# /security-alert-quality — 网络安全设备告警日志质量分析

评估单厂商或多厂商网络安全设备的告警日志质量（误报率、攻击验证、规则质量），输出结构化分析报告。

Arguments passed: `$ARGUMENTS`

---

## 架构概览

本项目采用**项目经理 + 阶段专家**的双层架构：

```
用户请求
    │
    ▼
┌──────────────────┐
│  SKILL.md (入口)  │  ← 你在这里：解析用户意图，启动项目经理
└──────────────────┘
    │
    ▼
┌──────────────────┐
│   PM Agent       │  ← 项目经理：分配任务、监督执行、人工确认
│  agent/pm.md     │
└──────────────────┘
    │
    ├──→ Phase 1 Agent (数据加载)     agent/phase1_data_loader.md
    ├──→ Phase 2 Agent (场景分叉)     agent/phase2_scenario_fork.md
    ├──→ Phase 3 Agent (深度分析)     agent/phase3_deep_analysis.md
    ├──→ Phase 4 Agent (质量审查)     agent/phase4_quality_check.md
    ├──→ Phase 5 Agent (报告生成)     agent/phase5_report_generator.md
    └──→ Phase 6 Agent (改进建议)     agent/phase6_recommendation.md
```

**执行原则**：
- 6 个阶段严格串行，不可并行
- 阶段 4 为强制门控，未通过绝不可进入阶段 5
- 7 个人工确认节点必须逐一与用户交互，不可自动选择
- 所有改进建议仅输出清单，由用户自行执行

## 你的职责（入口层）

你只做三件事：

1. **解析用户意图**：判断用户提供的是单厂商还是多厂商数据、数据路径、特殊要求
2. **启动项目经理**：读取 `agent/pm.md`，将解析后的任务参数传递给 PM Agent
3. **展示状态**：在各阶段切换时向用户展示项目状态板

**你不做**：数据分析、编码解码、特征匹配、误报判定、报告撰写。这些都由阶段 Agent 执行。

## 启动流程

### Step 1: 收集必要信息

向用户确认：
- CSV 文件所在目录路径（推荐），或单个 CSV 文件路径
- 是否指定厂商名称（覆盖自动识别）
- 分析目标：单厂商质量评估 / 多厂商交叉对比

### Step 2: 启动项目经理

读取 `agent/pm.md` 并按其工作流执行。

项目经理将依次：
1. 启动 Phase 1 Agent 读取 `agent/phase1_data_loader.md`
2. 接收交接单，检查数据质量
3. 启动 Phase 2 Agent 读取 `agent/phase2_scenario_fork.md`
4. 接收交接单，检查切片完整性
5. 启动 Phase 3 Agent 读取 `agent/phase3_deep_analysis.md`
6. 接收交接单，处理"需人工审核"比例
7. 启动 Phase 4 Agent 读取 `agent/phase4_quality_check.md`
8. 接收审查报告，决定通过/退回
9. 启动 Phase 5 Agent 读取 `agent/phase5_report_generator.md`
10. 接收报告文件
11. 启动 Phase 6 Agent 读取 `agent/phase6_recommendation.md`
12. 接收建议清单
13. 最终交付

### Step 3: 交付

向用户交付：
- `report.docx` — 完整分析报告
- `recommendations.json` — 改进建议清单
- `manual_review_list.json` — 需人工审核的告警清单

## 文件索引

> 完整 Agent 文件清单见 [`agent/index.md`](agent/index.md)，误报场景库见 [`cookbook/index.md`](cookbook/index.md)。

| 文件 | 用途 |
|------|------|
| `SKILL.md` | 项目入口：解析用户意图，启动项目经理 |
| `agent/pm.md` | 项目经理 Agent（唯一调度中心） |
| `agent/index.md` | Agent 文件完整索引 |
| `agent/phase1_data_loader.md` ~ `agent/phase6_recommendation.md` | 阶段一~六 |
| `agent/sql_inject.md` ~ `agent/web_crawler.md` | 6 种攻击类型的主动探针协议 |
| `cookbook/index.md` | 误报场景库入口 |
| `scripts/parse_csv.py` | CSV 解析脚本（阶段一调用） |
| `references/csv_schema.md` | 绿盟/微步 CSV 字段定义参考 |
