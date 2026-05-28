#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
告警对比分析脚本 v2
用于对比绿盟和微步的安全告警日志
v2: 加载 fp_rule_base.yaml 外挂配置，事件名称驱动的 FP 判定
"""

import json
import re
import sys
import os
import base64
import html
import urllib.parse
from typing import Dict, List, Tuple, Set, Optional
from collections import defaultdict
import pandas as pd

# 尝试加载 YAML 配置（需要 pyyaml），失败则降级为内置规则
try:
    import yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False


def _load_rule_base() -> Dict:
    """加载 FP 判定规则配置，优先从 YAML 文件，失败回退到内置精简规则"""
    # 查找 fp_rule_base.yaml 的路径
    script_dir = os.path.dirname(os.path.abspath(__file__))
    search_paths = [
        os.path.join(script_dir, '..', 'references', 'fp_rule_base.yaml'),
        os.path.join(os.getcwd(), 'references', 'fp_rule_base.yaml'),
        os.path.join(os.getcwd(), '.claude', 'skills', 'security-alert-analysis',
                     'references', 'fp_rule_base.yaml'),
    ]

    for path in search_paths:
        if os.path.exists(path):
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    if _HAS_YAML:
                        return yaml.safe_load(f)
                    else:
                        # 无 pyyaml 时手动解析简单 YAML（避免引入新依赖）
                        return _parse_yaml_simple(f.read())
            except Exception:
                continue

    # 所有路径都不存在，返回空规则库（后续使用内置降级规则）
    return {}


def _parse_yaml_simple(content: str) -> Dict:
    """简易 YAML 解析器（仅支持本规则库的子集，用于无 pyyaml 场景）"""
    import ast
    result = {}
    current_section = None
    current_list = []
    current_item = {}
    in_list = False

    for line in content.split('\n'):
        stripped = line.strip()
        if not stripped or stripped.startswith('#') or stripped == '---':
            continue

        if not line.startswith(' ') and not line.startswith('\t'):
            # 顶级 key
            if in_list and current_list:
                result[current_section] = current_list
                current_list = []
                in_list = False
            current_section = stripped.rstrip(':').strip()
            if current_section not in result:
                result[current_section] = []
            current_list = result[current_section]
            continue

        if stripped.startswith('- '):
            if current_item:
                current_list.append(current_item)
                current_item = {}
            in_list = True
            # 解析 "- key: value" 或 "- name: value"
            kv = stripped[2:]
            if ':' in kv:
                k, v = kv.split(':', 1)
                current_item[k.strip()] = v.strip().strip('"').strip("'")
            continue

        if ':' in stripped and in_list:
            k, v = stripped.split(':', 1)
            k = k.strip().strip('"').strip("'")
            v = v.strip().strip('"').strip("'")
            if v.startswith('[') and v.endswith(']'):
                v = ast.literal_eval(v)
            current_item[k] = v

    if current_item:
        current_list.append(current_item)

    return result


# 加载规则库
RULE_BASE = _load_rule_base()

# -- 从规则库提取各种判定表（带降级到空列表） --
HIGH_CONFIDENCE_FP_NAMES = {
    item['name']: item
    for item in RULE_BASE.get('high_confidence_fp_names', [])
}

EXPLOIT_NAMES = {
    item['name']: item
    for item in RULE_BASE.get('exploit_names', [])
}

WEAK_PASSWORD_NAMES = {
    item['name']: item
    for item in RULE_BASE.get('weak_password_names', [])
}

MEDIUM_CONFIDENCE_RULES = RULE_BASE.get('medium_confidence_rules', [])

BUSINESS_TRAFFIC_PATTERNS = {
    item.get('name', f'pattern_{i}'): {
        'name': item.get('display_name', item.get('name', '')),
        'patterns': item.get('uri_patterns', []) + item.get('payload_patterns', []),
        'false_positive_msg': [],
        'reason': item.get('reason', '')
    }
    for i, item in enumerate(RULE_BASE.get('business_traffic_patterns', []))
}

ATTACK_FEATURES = {
    k: {'patterns': v.get('patterns', [])}
    for k, v in RULE_BASE.get('attack_features', {}).items()
}

# 如果规则库加载为空，使用内置降级规则
if not HIGH_CONFIDENCE_FP_NAMES:
    BUSINESS_TRAFFIC_PATTERNS = {
        "elasticsearch_monitoring": {
            "name": "Elasticsearch 监控",
            "patterns": ["/_nodes/", "/_cluster/", "/health", "cluster_name"],
            "false_positive_msg": ["Elasticsearch", "未授权访问"],
            "reason": "Elasticsearch 监控/管理接口正常访问"
        },
        "redis_config": {
            "name": "Redis 配置操作",
            "patterns": ["HSET", "nsfocus:", ":configs:", "CONFIG"],
            "false_positive_msg": ["Redis", "配置"],
            "reason": "Redis 正常配置操作"
        },
        "docker_registry": {
            "name": "Docker 镜像仓库",
            "patterns": ["/v2/", "/manifests/"],
            "false_positive_msg": ["RTSP", "LIVE555"],
            "reason": "Docker Registry 正常访问"
        },
        "health_check": {
            "name": "健康检查端点",
            "patterns": ["/health", "/metrics", "/status", "/ping"],
            "false_positive_msg": ["目录遍历", "SQL注入", "XSS", "信息泄露"],
            "reason": "健康检查端点正常访问"
        },
    }
    ATTACK_FEATURES = {
        "sql_injection": {
            "patterns": ["UNION SELECT", " OR 1=1", "' OR '", "information_schema",
                         "SLEEP(", "BENCHMARK("]
        },
        "xss": {
            "patterns": ["<script", "javascript:", "onerror=", "onload=", "alert("]
        },
        "rce": {
            "patterns": [";cat ", ";ls ", ";id", ";whoami", "eval(", "exec(", "system(",
                         "wget", "curl", "__proto__", "constructor"]
        },
        "path_traversal": {
            "patterns": ["../", "/etc/passwd", "/windows/win.ini", "..\\"]
        },
    }


def _hex_decode(text: str) -> str:
    """解码 \\xNN 格式的十六进制编码"""
    def _replace(m):
        try:
            return chr(int(m.group(1), 16))
        except (ValueError, OverflowError):
            return m.group(0)
    return re.sub(r'\\x([0-9a-fA-F]{2})', _replace, text)


def _unicode_decode(text: str) -> str:
    """解码 \\uNNNN 格式的 Unicode 编码"""
    def _replace(m):
        try:
            return chr(int(m.group(1), 16))
        except (ValueError, OverflowError):
            return m.group(0)
    return re.sub(r'\\u([0-9a-fA-F]{4})', _replace, text)


def _html_entity_decode(text: str) -> str:
    """解码 HTML 实体"""
    try:
        return html.unescape(text)
    except Exception:
        return text


def _base64_decode(text: str) -> Optional[str]:
    """尝试 Base64 解码"""
    # 只对看起来像 base64 的短片段做解码
    candidates = re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', text)
    decoded_parts = []
    for c in candidates[:5]:  # 最多尝试5个片段
        try:
            decoded = base64.b64decode(c).decode('utf-8', errors='replace')
            if any(ch.isprintable() or ch in '\n\r\t' for ch in decoded):
                decoded_parts.append(decoded)
        except Exception:
            pass
    return '\n'.join(decoded_parts) if decoded_parts else None


def detect_encoding_bypass(q_body: str, max_depth: int = 3) -> Dict:
    """
    检测编码绕过攻击，支持多级递归解码。
    检测顺序：URL → Hex → Unicode → Base64 → HTML实体 → 双重URL
    最多递归 max_depth 层。

    Returns:
        bypass_info: {
            has_encoding, encoding_types[], decoded_content, is_attack,
            decode_chain[]  # 解码链路记录
        }
    """
    bypass_info = {
        "has_encoding": False,
        "encoding_types": [],
        "decoded_content": q_body,
        "is_attack": False,
        "decode_chain": [],
        "original_content": q_body
    }

    if not q_body:
        return bypass_info

    current = q_body
    encodings_found = set()

    for depth in range(max_depth):
        changed = False

        # 1. 双重URL编码 (先检测，避免被单层URL误处理)
        if re.search(r'%25[0-9a-fA-F]{2}', current):
            try:
                decoded = urllib.parse.unquote(current)
                if decoded != current:
                    current = decoded
                    encodings_found.add("双重URL编码")
                    bypass_info["decode_chain"].append(
                        f"Layer{depth+1}: 双重URL解码")
                    changed = True
            except Exception:
                pass

        # 2. URL 编码
        if re.search(r'%[0-9a-fA-F]{2}', current):
            try:
                decoded = urllib.parse.unquote(current)
                if decoded != current:
                    current = decoded
                    encodings_found.add("URL编码")
                    bypass_info["decode_chain"].append(
                        f"Layer{depth+1}: URL解码")
                    changed = True
            except Exception:
                pass

        # 3. Hex 编码 (\\xNN)
        if re.search(r'\\x[0-9a-fA-F]{2}', current):
            decoded = _hex_decode(current)
            if decoded != current:
                current = decoded
                encodings_found.add("Hex编码")
                bypass_info["decode_chain"].append(
                    f"Layer{depth+1}: Hex解码 (\\xNN)")
                changed = True

        # 4. Unicode 编码 (\\uNNNN)
        if re.search(r'\\u[0-9a-fA-F]{4}', current):
            decoded = _unicode_decode(current)
            if decoded != current:
                current = decoded
                encodings_found.add("Unicode编码")
                bypass_info["decode_chain"].append(
                    f"Layer{depth+1}: Unicode解码 (\\uNNNN)")
                changed = True

        # 5. Base64 编码
        b64_decoded = _base64_decode(current)
        if b64_decoded:
            current = current + "\n[Base64解码]\n" + b64_decoded
            encodings_found.add("Base64编码")
            bypass_info["decode_chain"].append(
                f"Layer{depth+1}: Base64解码")
            changed = True

        # 6. HTML 实体编码
        if re.search(r'&#\d+;|&#x[0-9a-fA-F]+;', current):
            decoded = _html_entity_decode(current)
            if decoded != current:
                current = decoded
                encodings_found.add("HTML实体编码")
                bypass_info["decode_chain"].append(
                    f"Layer{depth+1}: HTML实体解码")
                changed = True

        if not changed:
            break

    bypass_info["has_encoding"] = len(encodings_found) > 0
    bypass_info["encoding_types"] = list(encodings_found)
    bypass_info["decoded_content"] = current

    # 在解码后的内容中检测攻击特征
    if bypass_info["has_encoding"]:
        for attack_type, config in ATTACK_FEATURES.items():
            for pattern in config.get("patterns", []):
                if pattern.lower() in current.lower():
                    bypass_info["is_attack"] = True
                    break
            if bypass_info["is_attack"]:
                break

    return bypass_info



def _match_indicators(content: str, indicators: List[Dict]) -> List[str]:
    """匹配指标列表，返回匹配到的描述列表。
    空载荷或 NaN 时跳过通配符模式，避免无内容的 ".*" 误匹配。"""
    matched = []
    # 排除空载荷和 pandas NaN 字符串
    is_empty = (not content or content.strip() in ('', 'nan', 'NaN', 'None', 'null'))
    for ind in indicators:
        pattern = ind.get('pattern', '')
        desc = ind.get('description', pattern)
        if not pattern:
            continue
        # 空载荷时不匹配通配符
        if is_empty and pattern in ('.*', '.+', '^.*$', '^.+$'):
            continue
        if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
            matched.append(desc)
    return matched


def analyze_threatbook_alert(event_name: str, event_type: str,
                              q_body: str, r_body: str) -> Dict:
    """
    专门分析微步厂商告警的误报判定 (v2 — 事件名称驱动)

    判定路径（按优先级）：
    1. 高置信度FP名单 → 直接判FP（无需看载荷）
    2. 漏洞利用名单 → 载荷深度分析 → TP
    3. 弱口令名单 → TP
    4. 中置信度规则 → 载荷正反指标匹配
    5. 业务流量白名单 → FP
    6. 编码绕过分析 → 按解码结果判定
    7. 攻击特征匹配 → TP
    8. 以上均不匹配 → 需人工审核
    """
    result = {
        "confidence": "",
        "is_false_positive": None,
        "requires_manual_review": False,
        "false_positive_reason": "",
        "bypass_detection": {},
        "evidence": []
    }

    # 编码绕过检测（保留用于证据收集）
    bypass_info = detect_encoding_bypass(q_body)
    result["bypass_detection"] = bypass_info

    # -- 路径 1: 高置信度误报名单 --
    if event_name in HIGH_CONFIDENCE_FP_NAMES:
        rule = HIGH_CONFIDENCE_FP_NAMES[event_name]
        result["is_false_positive"] = True
        result["requires_manual_review"] = False
        result["confidence"] = "高"
        result["false_positive_reason"] = rule.get('reason', '匹配高置信度误报模式')
        result["evidence"].append(f"事件名称 '{event_name}' 在高置信度误报名单中")
        result["evidence"].append(f"分类: {rule.get('category', '未知')}")
        return result

    # -- 路径 2: 漏洞利用/真实攻击名单 --
    if event_name in EXPLOIT_NAMES:
        rule = EXPLOIT_NAMES[event_name]
        # 用载荷指标确认
        payload_indicators = rule.get('payload_indicators', [])
        found_indicators = []
        if payload_indicators:
            for ind in payload_indicators:
                if ind.lower() in q_body.lower():
                    found_indicators.append(ind)

        if found_indicators or not payload_indicators:
            result["is_false_positive"] = False
            result["requires_manual_review"] = False
            result["confidence"] = "高" if found_indicators else "中"
            cve_str = f" ({rule.get('cve', 'N/A')})" if rule.get('cve') else ""
            result["false_positive_reason"] = (
                f"{rule.get('analysis', '已知漏洞利用')}{cve_str}"
            )
            result["evidence"].append(
                f"事件名称 '{event_name}' 在漏洞利用名单中"
            )
            if found_indicators:
                result["evidence"].append(
                    f"载荷含关键特征: {', '.join(found_indicators)}"
                )
            if rule.get('cvss'):
                result["evidence"].append(f"CVSS: {rule['cvss']}")
            return result
        else:
            # 在漏洞名单但载荷无特征 → 可能是变种，仍需标记
            result["is_false_positive"] = False
            result["requires_manual_review"] = False
            result["confidence"] = "中"
            result["false_positive_reason"] = (
                f"事件名称匹配已知漏洞 '{event_name}'，但载荷未含标准特征，可能是探测或变种"
            )
            return result

    # -- 路径 3: 弱口令名单 --
    if event_name in WEAK_PASSWORD_NAMES:
        rule = WEAK_PASSWORD_NAMES[event_name]
        result["is_false_positive"] = False
        result["requires_manual_review"] = False
        result["confidence"] = "中"
        result["false_positive_reason"] = rule.get('analysis', '弱口令爆破攻击')
        result["evidence"].append(f"弱口令告警: {rule.get('protocol', 'N/A')} 协议")
        return result

    # -- 路径 4: 中置信度规则（需载荷正反指标匹配） --
    for rule in MEDIUM_CONFIDENCE_RULES:
        event_pattern = rule.get('event_pattern', '')
        if event_pattern and event_pattern in event_name:
            fp_indicators = rule.get('fp_indicators', [])
            attack_indicators = rule.get('attack_indicators', [])

            fp_matches = _match_indicators(q_body, fp_indicators)
            attack_matches = _match_indicators(q_body, attack_indicators)

            if fp_matches and not attack_matches:
                result["is_false_positive"] = True
                result["requires_manual_review"] = False
                result["confidence"] = "中"
                result["false_positive_reason"] = (
                    f"匹配业务流量模式: {'; '.join(fp_matches)}"
                )
                result["evidence"].extend(fp_matches)
                return result

            if attack_matches and not fp_matches:
                result["is_false_positive"] = False
                result["requires_manual_review"] = False
                result["confidence"] = "中"
                result["false_positive_reason"] = (
                    f"检测到攻击特征: {'; '.join(attack_matches)}"
                )
                result["evidence"].extend(attack_matches)
                return result

            if fp_matches and attack_matches:
                result["requires_manual_review"] = True
                result["is_false_positive"] = None
                result["confidence"] = "低"
                result["false_positive_reason"] = (
                    f"同时存在业务特征和攻击特征。业务: {'; '.join(fp_matches)}；"
                    f"攻击: {'; '.join(attack_matches)}"
                )
                return result

            # 匹配到规则但无具体指标命中 → 用默认判定
            default = rule.get('default_judgment', 'manual_review')
            if default == 'false_positive':
                result["is_false_positive"] = True
                result["requires_manual_review"] = False
                result["confidence"] = "中"
                result["false_positive_reason"] = (
                    f"事件类型 '{event_name}' 默认为互联网背景噪声"
                )
                return result
            elif default == 'true_positive':
                result["is_false_positive"] = False
                result["requires_manual_review"] = False
                result["confidence"] = "中"
                result["false_positive_reason"] = (
                    f"事件类型 '{event_name}' 默认真阳性"
                )
                return result
            else:
                # manual_review — 继续往下走通用路径
                pass

    # -- 路径 5: 业务流量白名单 --
    business_result = _analyze_business_traffic(q_body, event_name)
    if business_result["is_business"]:
        # 检查是否同时存在攻击特征
        attack_found = _check_attack_features(q_body)
        if attack_found:
            result["requires_manual_review"] = True
            result["is_false_positive"] = None
            result["confidence"] = "低"
            result["false_positive_reason"] = (
                f"匹配业务模式 [{business_result['business_type']}]，"
                f"但同时存在攻击特征: {', '.join(attack_found)}"
            )
            return result
        else:
            result["is_false_positive"] = True
            result["requires_manual_review"] = False
            result["confidence"] = "高"
            result["false_positive_reason"] = business_result["reason"]
            result["evidence"].extend(business_result["evidence"])
            return result

    # -- 路径 6: 编码绕过分析 --
    if bypass_info["has_encoding"]:
        original_has_attack = bool(_check_attack_features(q_body))
        decoded_is_attack = bypass_info.get("is_attack", False)

        if original_has_attack and not decoded_is_attack:
            result["requires_manual_review"] = True
            result["is_false_positive"] = None
            result["confidence"] = "低"
            result["false_positive_reason"] = (
                f"流量含{', '.join(bypass_info['encoding_types'])}编码，"
                "原始内容有攻击特征但解码后特征消散"
            )
            return result
        elif not original_has_attack and decoded_is_attack:
            result["is_false_positive"] = False
            result["requires_manual_review"] = False
            result["confidence"] = "高"
            result["false_positive_reason"] = (
                f"解码后检出攻击特征，编码绕过确认"
            )
            return result
        elif not original_has_attack and not decoded_is_attack:
            result["is_false_positive"] = True
            result["requires_manual_review"] = False
            result["confidence"] = "中"
            result["false_positive_reason"] = (
                "流量含编码但原始和解码后均无攻击特征"
            )
            return result

    # -- 路径 7: 攻击特征匹配 --
    attack_patterns_found = _check_attack_features(q_body)

    if attack_patterns_found:
        result["is_false_positive"] = False
        result["requires_manual_review"] = False
        result["confidence"] = "中"
        result["false_positive_reason"] = (
            f"检测到明确的攻击特征: {', '.join(attack_patterns_found[:5])}"
        )
        result["evidence"].extend(attack_patterns_found)
        return result

    # -- 路径 8: 无载荷数据时的基础判定 --
    if not q_body or len(q_body.strip()) < 10:
        # 基于事件名称做最后的启发式判定
        if "扫描" in event_name:
            result["is_false_positive"] = True
            result["requires_manual_review"] = False
            result["confidence"] = "中"
            result["false_positive_reason"] = "扫描类告警无载荷，判定为背景噪声"
            return result
        if any(kw in event_name for kw in ["弱口令", "暴力", "爆破"]):
            result["is_false_positive"] = False
            result["requires_manual_review"] = False
            result["confidence"] = "低"
            result["false_positive_reason"] = "认证类告警，默认视为真实攻击尝试"
            return result

    # -- 最终兜底: 需人工审核 --
    result["requires_manual_review"] = True
    result["is_false_positive"] = None
    result["confidence"] = "低"
    result["false_positive_reason"] = (
        f"事件 '{event_name}' 未匹配已知判定规则，需人工审核"
    )
    return result


def _check_attack_features(content: str) -> List[str]:
    """检查内容是否包含攻击特征，返回匹配到的模式列表"""
    found = []
    if not content:
        return found
    content_lower = content.lower()
    for attack_type, config in ATTACK_FEATURES.items():
        for pattern in config.get("patterns", []):
            if pattern.lower() in content_lower:
                found.append(f"[{attack_type}]{pattern}")
                if len(found) >= 10:  # 最多收集10个
                    return found
    return found


def _analyze_business_traffic(q_body: str, msg: str) -> Dict:
    """分析是否为业务流量（从旧 analyze_business_traffic 重构）"""
    result = {
        "is_business": False,
        "business_type": None,
        "reason": "",
        "evidence": []
    }

    # 提取 URI
    uri = ""
    if q_body:
        lines = q_body.split('\n')
        if lines:
            first_line = lines[0].strip()
            if first_line.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ',
                                       'HEAD ', 'OPTIONS ')):
                uri = first_line.split()[1] if len(first_line.split()) > 1 else ""

    for business_name, config in BUSINESS_TRAFFIC_PATTERNS.items():
        patterns = config.get("patterns", [])
        matched = False
        for pattern in patterns:
            if pattern in q_body or pattern in uri:
                matched = True
                result["evidence"].append(
                    f"匹配业务模式 [{config.get('name', business_name)}]: "
                    f"包含 '{pattern}'"
                )
                break

        # 同时也检查 fp_msg 关键词（保持向后兼容）
        fp_msgs = config.get("false_positive_msg", [])
        msg_match = not fp_msgs  # 如果没有定义 fp_msg，默认通过
        for fp_msg in fp_msgs:
            if fp_msg in msg:
                msg_match = True
                break

        if matched and msg_match:
            result["is_business"] = True
            result["business_type"] = business_name
            result["reason"] = config.get("reason", "匹配业务流量模式")
            return result

    return result


# 厂商前缀映射表（文件名识别备用）
VENDOR_PREFIXES = {
    '绿盟事件研判': '绿盟',
    '微步事件研判': '微步'
}


def identify_vendor_from_filename(filename: str) -> str:
    """
    从文件名识别厂商（备用方式）

    Args:
        filename: 文件名

    Returns:
        厂商名称
    """
    for prefix, vendor in VENDOR_PREFIXES.items():
        if prefix in filename:
            return vendor
    return '未知厂商'


def normalize_ip(ip_str: str) -> str:
    """
    标准化IP地址，去除括号、内部IP标注等

    Args:
        ip_str: 原始IP字符串

    Returns:
        标准化后的IP地址
    """
    # 移除括号
    ip_str = ip_str.strip().strip("'")
    ip_str = ip_str.strip().strip('"')

    # 移除内部IP标注，如 (内部网络06)
    ip_str = re.sub(r'\(.*?\)', '', ip_str).strip()

    # 移除IPv6地址中的前导零
    # 例如 2402:f000:0009:8801:3257:8603:74df:2498 -> 2402:f000:9:8801:3257:8603:74df:2498
    if ':' in ip_str and not ip_str.startswith('['):
        parts = ip_str.split(':')
        normalized = []
        for part in parts:
            # 移除前导零
            if part and part != '0000':
                norm_part = part.lstrip('0')
                if not norm_part:
                    norm_part = '0'
                normalized.append(norm_part)
            else:
                normalized.append(part)
        ip_str = ':'.join(normalized)

    return ip_str


def read_csv_with_encoding(file_path: str, vendor: str) -> pd.DataFrame:
    """
    读取CSV文件，处理编码问题

    Args:
        file_path: CSV文件路径
        vendor: 厂商名称（绿盟/微步）

    Returns:
        DataFrame
    """
    try:
        df = pd.read_csv(file_path, encoding='gb18030', low_memory=False)
        return df
    except Exception as e:
        print(f"读取{vendor}文件失败: {e}")
        return pd.DataFrame()


def get_four_tuple(row: pd.Series) -> Tuple[str, str, str, str]:
    """
    获取四元组：源IP、源端口、目的IP、目的端口

    Args:
        row: 数据行

    Returns:
        (源IP, 源端口, 目的IP, 目的端口)
    """
    src_ip = normalize_ip(str(row.get('源IP', '')))
    src_port = str(row.get('源端口', '')).strip().strip("'")
    dst_ip = normalize_ip(str(row.get('目的IP', '')))
    dst_port = str(row.get('目的端口', '')).strip().strip("'")

    return (src_ip, src_port, dst_ip, dst_port)


def get_raw_four_tuple(row: pd.Series) -> Tuple[str, str, str, str]:
    """
    获取原始四元组：源IP、源端口、目的IP、目的端口（未标准化）

    Args:
        row: 数据行

    Returns:
        (源IP, 源端口, 目的IP, 目的端口)
    """
    src_ip = str(row.get('源IP', ''))
    src_port = str(row.get('源端口', '')).strip().strip("'")
    dst_ip = str(row.get('目的IP', ''))
    dst_port = str(row.get('目的端口', '')).strip().strip("'")

    return (src_ip, src_port, dst_ip, dst_port)


def extract_vendor_from_device_source(device_source: str) -> str:
    """
    从设备来源字段提取厂商名称

    提取规则：
    - 绿盟202 → 绿盟（删除数字）
    - 微步TIAS216(172.28.11.216) → 微步（删除设备型号及IP地址）

    Args:
        device_source: 设备来源字段原始值

    Returns:
        厂商名称
    """
    if not device_source or pd.isna(device_source):
        return '未知厂商'
    device_source = str(device_source).strip()
    # 提取厂商名称：删除数字、设备型号（英文字母+数字组合）及括号内IP地址
    vendor = re.sub(r'\(.*?\)', '', device_source)  # 删除括号及内容
    vendor = re.sub(r'[A-Za-z]+\d+', '', vendor)    # 删除设备型号如TIAS216
    vendor = re.sub(r'\d+', '', vendor)              # 删除数字如202
    vendor = vendor.strip()
    return vendor if vendor else '未知厂商'


def identify_vendor_from_csv(file_path: str) -> str:
    """
    从CSV文件的设备来源字段识别厂商

    Args:
        file_path: CSV文件路径

    Returns:
        厂商名称
    """
    try:
        df = pd.read_csv(file_path, encoding='gb18030', low_memory=False, nrows=1)
        if '设备来源' in df.columns:
            device_source = df['设备来源'].iloc[0]
            vendor = extract_vendor_from_device_source(device_source)
            if vendor != '未知厂商':
                return vendor
    except Exception as e:
        print(f"从设备来源识别厂商失败: {e}")
    return '未知厂商'


def compare_alerts(file1_path: str, file2_path: str) -> Dict:
    """
    对比两个厂商的安全告警日志

    厂商识别基于CSV文件中的"设备来源"字段

    Args:
        file1_path: 文件1路径
        file2_path: 文件2路径

    Returns:
        对比分析结果字典
    """
    # 从设备来源字段识别厂商，失败时回退到文件名识别
    vendor1 = identify_vendor_from_csv(file1_path)
    if vendor1 == '未知厂商':
        vendor1 = identify_vendor_from_filename(os.path.basename(file1_path))
    vendor2 = identify_vendor_from_csv(file2_path)
    if vendor2 == '未知厂商':
        vendor2 = identify_vendor_from_filename(os.path.basename(file2_path))

    # 读取文件
    print(f"读取{vendor1}文件: {file1_path}")
    df1 = read_csv_with_encoding(file1_path, vendor1)

    print(f"读取{vendor2}文件: {file2_path}")
    df2 = read_csv_with_encoding(file2_path, vendor2)

    if df1.empty:
        print(f"警告：{vendor1}文件为空或读取失败")
    if df2.empty:
        print(f"警告：{vendor2}文件为空或读取失败")

    # 构建四元组索引
    vendor1_index = defaultdict(list)
    vendor2_index = defaultdict(list)

    for idx, row in df1.iterrows():
        four_tuple = get_four_tuple(row)
        raw_four_tuple = get_raw_four_tuple(row)
        vendor1_index[four_tuple].append({
            'index': idx,
            'event_name': str(row.get('事件名称', '')),
            'event_type': str(row.get('事件类型', '')),
            'generate_time': str(row.get('生成时间', '')),
            'payload': str(row.get('载荷', '')),
            'request_body': str(row.get('请求体', '')),
            'response_body': str(row.get('响应体', '')),
            'threat_level': str(row.get('威胁等级', '')),
            'rule_id': str(row.get('规则ID', '')),
            'raw_four_tuple': raw_four_tuple,
            'device_source': str(row.get('设备来源', ''))
        })

    for idx, row in df2.iterrows():
        four_tuple = get_four_tuple(row)
        raw_four_tuple = get_raw_four_tuple(row)
        vendor2_index[four_tuple].append({
            'index': idx,
            'event_name': str(row.get('事件名称', '')),
            'event_type': str(row.get('事件类型', '')),
            'generate_time': str(row.get('生成时间', '')),
            'request_body': str(row.get('请求体', '')),
            'response_body': str(row.get('响应体', '')),
            'threat_level': str(row.get('威胁等级', '')),
            'rule_id': str(row.get('规则ID', '')),
            'raw_four_tuple': raw_four_tuple,
            'device_source': str(row.get('设备来源', ''))
        })

    # 获取所有四元组
    all_tuples = set(vendor1_index.keys()) | set(vendor2_index.keys())
    vendor1_only_tuples = set(vendor1_index.keys()) - set(vendor2_index.keys())
    vendor2_only_tuples = set(vendor2_index.keys()) - set(vendor1_index.keys())
    common_tuples = set(vendor1_index.keys()) & set(vendor2_index.keys())

    # 根据识别的厂商名称映射到绿盟/微步，确保结果键名与厂商名称对应
    if vendor1 == '绿盟' and vendor2 == '微步':
        lvmeng_index = vendor1_index
        weibu_index = vendor2_index
        df_lvmeng = df1
        df_weibu = df2
        lvmeng_only_tuples = vendor1_only_tuples
        weibu_only_tuples = vendor2_only_tuples
    elif vendor1 == '微步' and vendor2 == '绿盟':
        lvmeng_index = vendor2_index
        weibu_index = vendor1_index
        df_lvmeng = df2
        df_weibu = df1
        lvmeng_only_tuples = vendor2_only_tuples
        weibu_only_tuples = vendor1_only_tuples
    else:
        # 无法确定或未知厂商，保持原样
        lvmeng_index = vendor1_index
        weibu_index = vendor2_index
        df_lvmeng = df1
        df_weibu = df2
        lvmeng_only_tuples = vendor1_only_tuples
        weibu_only_tuples = vendor2_only_tuples

    # 分析结果
    result = {
        'vendor1': vendor1,
        'vendor2': vendor2,
        'summary': {
            'lvmeng_total_alerts': len(df_lvmeng),
            'weibu_total_alerts': len(df_weibu),
            'lvmeng_unique_four_tuples': len(lvmeng_only_tuples),
            'weibu_unique_four_tuples': len(weibu_only_tuples),
            'common_four_tuples': len(common_tuples),
            'lvmeng_only_alert_count': 0,
            'weibu_only_alert_count': 0,
            'cross_alert_count': 0
        },
        'lvmeng_only_alerts': [],
        'weibu_only_alerts': [],
        'cross_alerts': [],
        'detailed_comparison': []
    }

    # 微步误报分析统计
    weibu_fp_stats = {
        'total': 0,
        'false_positive': 0,
        'true_positive': 0,
        'manual_review': 0
    }

    # 统计绿盟独有告警
    for four_tuple in lvmeng_only_tuples:
        alerts = lvmeng_index[four_tuple]
        result['summary']['lvmeng_only_alert_count'] += len(alerts)

        for alert in alerts:
            result['lvmeng_only_alerts'].append({
                'four_tuple': four_tuple,
                'event_name': alert['event_name'],
                'event_type': alert['event_type'],
                'generate_time': alert['generate_time'],
                'threat_level': alert['threat_level'],
                'rule_id': alert['rule_id'],
                'raw_four_tuple': alert['raw_four_tuple']
            })

    # 统计微步独有告警
    for four_tuple in weibu_only_tuples:
        alerts = weibu_index[four_tuple]

        for alert in alerts:
            alert_data = {
                'four_tuple': four_tuple,
                'event_name': alert['event_name'],
                'event_type': alert['event_type'],
                'generate_time': alert['generate_time'],
                'threat_level': alert['threat_level'],
                'rule_id': alert['rule_id'],
                'raw_four_tuple': alert['raw_four_tuple'],
                'device_source': alert.get('device_source', '')
            }

            # 验证设备来源字段是否包含"微步"才进行误报判定
            # 严格遵守约束条件：数据分析仅仅是分析设备来源值包含微步字段的
            device_source = alert.get('device_source', '')
            if '微步' in device_source:
                result['summary']['weibu_only_alert_count'] += 1
                weibu_fp_stats['total'] += 1

                # 对微步告警进行误报判定
                fp_analysis = analyze_threatbook_alert(
                    alert['event_name'],
                    alert['event_type'],
                    alert['request_body'],
                    alert['response_body']
                )

                # 统计误报判定结果
                if fp_analysis['is_false_positive'] is True:
                    weibu_fp_stats['false_positive'] += 1
                elif fp_analysis['is_false_positive'] is False:
                    weibu_fp_stats['true_positive'] += 1
                elif fp_analysis['requires_manual_review']:
                    weibu_fp_stats['manual_review'] += 1

                # 将误报分析结果添加到告警数据中
                alert_data['false_positive_analysis'] = fp_analysis
            else:
                # 设备来源不包含"微步"，不进行误报分析
                alert_data['false_positive_analysis'] = {
                    'confidence': '',
                    'is_false_positive': None,
                    'requires_manual_review': False,
                    'false_positive_reason': f'设备来源"{device_source}"不包含"微步"，未进行误报判定',
                    'bypass_detection': {},
                    'evidence': []
                }

            result['weibu_only_alerts'].append(alert_data)

    # 分析交叉告警
    for four_tuple in common_tuples:
        lvmeng_alerts = lvmeng_index[four_tuple]
        weibu_alerts = weibu_index[four_tuple]

        result['summary']['cross_alert_count'] += max(len(lvmeng_alerts), len(weibu_alerts))

        # 对交叉告警中的微步告警进行误报判定
        weibu_alerts_with_fp = []
        for alert in weibu_alerts:
            alert_with_fp = alert.copy()
            # 验证设备来源字段是否包含"微步"才进行误报判定
            device_source = alert.get('device_source', '')
            if '微步' in device_source:
                # 对微步告警进行误报判定
                fp_analysis = analyze_threatbook_alert(
                    alert['event_name'],
                    alert['event_type'],
                    alert['request_body'],
                    alert['response_body']
                )

                alert_with_fp['false_positive_analysis'] = fp_analysis
            else:
                # 设备来源不包含"微步"，不进行误报分析
                alert_with_fp['false_positive_analysis'] = {
                    'confidence': '',
                    'is_false_positive': None,
                    'requires_manual_review': False,
                    'false_positive_reason': f'设备来源"{device_source}"不包含"微步"，未进行误报判定',
                    'bypass_detection': {},
                    'evidence': []
                }
            weibu_alerts_with_fp.append(alert_with_fp)

        # 对同一四元组的告警进行一致性分析
        comparison = {
            'four_tuple': four_tuple,
            'lvmeng_alerts': lvmeng_alerts,
            'weibu_alerts': weibu_alerts_with_fp,  # 使用包含误报分析的微步告警列表
            'consistency': {
                'event_name_match': False,
                'event_type_match': False,
                'attack_result_match': False
            }
        }

        # 检查一致性（取第一个告警进行比较）
        if lvmeng_alerts and weibu_alerts_with_fp:
            comparison['consistency']['event_name_match'] = lvmeng_alerts[0]['event_name'] == weibu_alerts_with_fp[0]['event_name']
            comparison['consistency']['event_type_match'] = lvmeng_alerts[0]['event_type'] == weibu_alerts_with_fp[0]['event_type']
            # 攻击结果判定可以根据威胁等级来判断
            comparison['consistency']['attack_result_match'] = lvmeng_alerts[0]['threat_level'] == weibu_alerts_with_fp[0]['threat_level']

        result['detailed_comparison'].append(comparison)
        result['cross_alerts'].append({
            'four_tuple': four_tuple,
            'lvmeng_event_names': list(set(a['event_name'] for a in lvmeng_alerts)),
            'weibu_event_names': list(set(a['event_name'] for a in weibu_alerts_with_fp))
        })

    # 添加微步误报统计结果到返回值
    result['weibu_fp_stats'] = weibu_fp_stats

    # 同步生成给 generate_report.py 用的派生字段（含误报率）
    if weibu_fp_stats['total'] > 0:
        result['weibu_false_positive_analysis'] = {
            'total_alerts': weibu_fp_stats['total'],
            'false_positive_count': weibu_fp_stats['false_positive'],
            'true_positive_count': weibu_fp_stats['true_positive'],
            'manual_review_count': weibu_fp_stats['manual_review'],
            'false_positive_rate': round(weibu_fp_stats['false_positive'] / weibu_fp_stats['total'] * 100, 2)
        }

    return result


def assess_cvss_score(event_name: str, event_type: str) -> Dict:
    """
    根据事件名称和类型评估CVSS评分

    这是一个简化的评估方法，实际应用中可能需要查询CVE数据库

    Args:
        event_name: 事件名称
        event_type: 事件类型

    Returns:
        CVSS评分和风险等级
    """
    # 高风险关键词
    high_risk_keywords = ['rce', '注入', '命令执行', '代码执行', '反序列化', 'SQL注入', 'XSS', '文件上传',
                          'sql注入', '命令执行', '代码执行', 'sql injection', 'remote code execution']

    # 中风险关键词
    medium_risk_keywords = ['扫描', '探测', '信息泄露', '未授权', '暴力破解', '暴力',
                            '信息泄露', '未授权访问', '弱口令', '弱口令', '未授权']

    # 低风险关键词
    low_risk_keywords = ['拒绝服务', 'slowhttptest', '慢速攻击', 'dos',
                         '拒绝服务', '慢速', 'dos']

    event_name_lower = event_name.lower()
    event_type_lower = event_type.lower()

    for keyword in high_risk_keywords:
        if keyword in event_name_lower or keyword in event_type_lower:
            return {'cvss': 8.5, 'risk_level': '高', 'recommendation': '强烈建议'}

    for keyword in medium_risk_keywords:
        if keyword in event_name_lower or keyword in event_type_lower:
            return {'cvss': 6.5, 'risk_level': '中', 'recommendation': '建议'}

    for keyword in low_risk_keywords:
        if keyword in event_name_lower or keyword in event_type_lower:
            return {'cvss': 3.5, 'risk_level': '低', 'recommendation': '可以忽略'}

    # 默认中等风险
    return {'cvss': 5.5, 'risk_level': '中', 'recommendation': '建议'}


def analyze_weibu_advantage(result: Dict) -> Dict:
    """
    分析微步的优势（当微步告警数量多于绿盟时）

    Args:
        result: 对比分析结果

    Returns:
        微步优势分析结果
    """
    advantage = {
        'weibu_coverage': [],
        'nsfocus_gaps': [],
        'recommendations': []
    }

    # 分析微步独有的告警类型
    event_type_stats = defaultdict(list)

    for alert in result['weibu_only_alerts']:
        event_type = alert.get('event_type', '未知')
        event_name = alert.get('event_name', '未知')

        cvss_info = assess_cvss_score(event_name, event_type)

        event_type_stats[event_type].append({
            'event_name': event_name,
            'four_tuple': alert['four_tuple'],
            'cvss': cvss_info['cvss'],
            'risk_level': cvss_info['risk_level'],
            'recommendation': cvss_info['recommendation']
        })

    # 按事件类型分组统计
    for event_type, alerts in event_type_stats.items():
        advantage['weibu_coverage'].append({
            'event_type': event_type,
            'count': len(alerts),
            'high_risk_count': len([a for a in alerts if a['risk_level'] == '高']),
            'medium_risk_count': len([a for a in alerts if a['risk_level'] == '中']),
            'low_risk_count': len([a for a in alerts if a['risk_level'] == '低'])
        })

        # 为每个高风险和中风险事件生成建议
        for alert in alerts:
            if alert['recommendation'] in ['强烈建议', '建议']:
                advantage['nsfocus_gaps'].append({
                    'event_name': alert['event_name'],
                    'event_type': event_type,
                    'cvss': alert['cvss'],
                    'risk_level': alert['risk_level'],
                    'recommendation': alert['recommendation'],
                    'reason': f'{event_type}类型攻击未被检测到，可能存在检测规则缺失',
                    'technical_suggestion': f'建议针对{event_name}添加检测规则，关注相关攻击特征'
                })

    return advantage


def main():
    if len(sys.argv) < 3:
        print("使用方法: python compare_alerts.py <文件1路径> <文件2路径>")
        sys.exit(1)

    file1_path = sys.argv[1]
    file2_path = sys.argv[2]

    print(f"开始对比分析...")
    print(f"文件1: {file1_path}")
    print(f"文件2: {file2_path}")

    # 执行对比分析
    result = compare_alerts(file1_path, file2_path)

    vendor1 = result.get('vendor1', '厂商1')
    vendor2 = result.get('vendor2', '厂商2')

    # 如果厂商2告警更多，分析厂商2优势
    if result['summary']['weibu_unique_four_tuples'] > result['summary']['lvmeng_unique_four_tuples']:
        print(f"{vendor2}告警数量更多，分析{vendor2}优势...")
        advantage = analyze_weibu_advantage(result)
        result['weibu_advantage'] = advantage

    # 保存结果
    output_file = "compare_result.json"
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    print(f"\n分析完成！")
    print(f"绿盟总告警数: {result['summary']['lvmeng_total_alerts']}")
    print(f"微步总告警数: {result['summary']['weibu_total_alerts']}")
    print(f"绿盟独有告警数: {result['summary']['lvmeng_only_alert_count']}")
    print(f"微步独有告警数: {result['summary']['weibu_only_alert_count']}")
    print(f"交叉告警数: {result['summary']['cross_alert_count']}")
    print(f"\n结果已保存到: {output_file}")

    return result


if __name__ == "__main__":
    main()