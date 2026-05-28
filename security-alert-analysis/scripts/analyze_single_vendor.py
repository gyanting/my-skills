#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
单厂商告警分析脚本
用于分析单个厂商的告警日志（当时间不关联时使用）
"""

import json
import sys
import re
import urllib.parse
from collections import defaultdict
from typing import Dict, List, Any
import pandas as pd


def read_csv_with_encoding(file_path: str, vendor: str) -> pd.DataFrame:
    """
    读取CSV文件，处理编码问题

    Args:
        file_path: CSV文件路径
        vendor: 厂商名称

    Returns:
        DataFrame
    """
    try:
        df = pd.read_csv(file_path, encoding='gb18030', low_memory=False)
        return df
    except Exception as e:
        print(f"读取{vendor}文件失败: {e}")
        return pd.DataFrame()


# 业务流量白名单模式
BUSINESS_TRAFFIC_PATTERNS = {
    "elasticsearch_monitoring": {
        "name": "Elasticsearch 监控",
        "patterns": ["/_nodes/", "/_cluster/", "/health", "cluster_name"],
        "false_positive_msg": ["Elasticsearch", "未授权访问", "监控", "状态查询"],
        "reason": "Elasticsearch 监控/管理接口正常访问"
    },
    "redis_config": {
        "name": "Redis 配置操作",
        "patterns": ["HSET", "nsfocus:", "websafe:", ":configs:", "CONFIG"],
        "false_positive_msg": ["Redis", "配置", "可疑"],
        "reason": "Redis 正常配置操作"
    },
    "http_proxy": {
        "name": "HTTP 代理",
        "patterns": ["CONNECT ", "Tunnel"],
        "false_positive_msg": ["CONNECT", "隧道", "代理"],
        "reason": "HTTP CONNECT 隧道正常使用"
    },
    "docker_registry": {
        "name": "Docker 镜像仓库",
        "patterns": ["/v2/", "/manifests/", "docker/"],
        "false_positive_msg": ["RTSP", "LIVE555", "镜像"],
        "reason": "Docker Registry 镜像仓库正常访问"
    },
    "health_check": {
        "name": "健康检查端点",
        "patterns": ["/health", "/metrics", "/status", "/ping"],
        "false_positive_msg": ["目录遍历", "SQL注入", "XSS", "信息泄露"],
        "reason": "监控健康检查端点正常访问"
    },
    "api_gateway": {
        "name": "API 网关",
        "patterns": ["/api/", "/v1/", "/v2/", "swagger", "openapi"],
        "false_positive_msg": ["路径遍历", "信息泄露"],
        "reason": "API 网关正常调用"
    }
}


# 攻击特征库
ATTACK_FEATURES = {
    "sql_injection": {
        "patterns": [
            "UNION SELECT",
            " OR 1=1",
            "' OR '",
            "DROP TABLE",
            "INSERT INTO",
            "UPDATE SET",
            "DELETE FROM",
            "--",
            "information_schema",
            "SLEEP(",
            "BENCHMARK(",
        ],
    },
    "xss": {
        "patterns": [
            "<script",
            "javascript:",
            "onerror=",
            "onload=",
            "onclick=",
        ],
    },
    "rce": {
        "patterns": [
            ";cat ",
            ";ls ",
            ";id",
            ";whoami",
            "wget",
            "curl",
            "eval(",
            "exec(",
            "system(",
        ],
    },
    "path_traversal": {
        "patterns": [
            "../",
            "%2e%2e",
            "/etc/passwd",
            "/windows/win.ini",
            "C:\\Windows",
            "..\\",
        ],
    }
}


def detect_encoding_bypass(q_body: str) -> Dict[str, Any]:
    """检测编码绕过攻击"""
    bypass_info = {
        "has_encoding": False,
        "encoding_types": [],
        "decoded_content": q_body,
        "is_attack": False
    }

    if not q_body:
        return bypass_info

    # URL 编码检测
    if re.search(r'%[0-9a-fA-F]{2}', q_body):
        bypass_info["has_encoding"] = True
        bypass_info["encoding_types"].append("URL编码")

        # 尝试 URL 解码
        try:
            decoded = urllib.parse.unquote(q_body)
            if decoded != q_body:
                bypass_info["decoded_content"] = decoded
                # 检查解码后是否还有编码
                if re.search(r'%[0-9a-fA-F]{2}', decoded):
                    bypass_info["encoding_types"].append("双重URL编码")
                    bypass_info["decoded_content"] = urllib.parse.unquote(decoded)
        except Exception:
            pass

    # 十六进制编码检测
    if re.search(r'\\x[0-9a-fA-F]{2}', q_body):
        bypass_info["has_encoding"] = True
        bypass_info["encoding_types"].append("十六进制编码")

    # Unicode 编码检测
    if re.search(r'\\u[0-9a-fA-F]{4}', q_body):
        bypass_info["has_encoding"] = True
        bypass_info["encoding_types"].append("Unicode编码")

    # 检查解码后是否为攻击
    decoded = bypass_info["decoded_content"]
    for attack_type, patterns in ATTACK_FEATURES.items():
        for pattern in patterns:
            if pattern in decoded.lower():
                bypass_info["is_attack"] = True
                break
        if bypass_info["is_attack"]:
            break

    return bypass_info


def analyze_business_traffic(q_body: str, uri: str, msg: str) -> Dict[str, Any]:
    """分析是否为业务流量"""
    result = {
        "is_business": False,
        "business_type": None,
        "reason": "",
        "evidence": []
    }

    for business_name, config in BUSINESS_TRAFFIC_PATTERNS.items():
        matched = False
        for pattern in config["patterns"]:
            if pattern in q_body or pattern in uri:
                matched = True
                result["evidence"].append(f"匹配业务模式 [{config['name']}]: 包含 '{pattern}'")
                break

        msg_matched = False
        for fp_msg in config.get("false_positive_msg", []):
            if fp_msg in msg:
                msg_matched = True
                break

        if matched and msg_matched:
            result["is_business"] = True
            result["business_type"] = business_name
            result["reason"] = config["reason"]
            return result

    return result


def calculate_confidence(evidence: List[str], attack_patterns_found: List[str], response_success: bool) -> str:
    """计算置信度"""
    confidence_score = 0

    # 证据数量
    confidence_score += min(len(evidence) * 15, 50)

    # 攻击特征明确性
    if attack_patterns_found:
        confidence_score += 20

    # 响应体证据
    if response_success:
        confidence_score += 20

    # 置信度分级
    if confidence_score >= 70:
        return "高"
    elif confidence_score >= 40:
        return "中"
    else:
        return "低"


def analyze_threatbook_alert(row: pd.Series) -> Dict[str, Any]:
    """
    专门分析微步厂商告警的误报判定

    Args:
        row: 告警记录

    Returns:
        误报判定结果
    """
    result = {
        "confidence": "",
        "is_false_positive": None,
        "requires_manual_review": False,
        "false_positive_reason": "",
        "bypass_detection": {},
        "evidence": []
    }

    # 提取字段
    msg = str(row.get('事件名称', ''))
    event_type = str(row.get('事件类型', ''))
    q_body = str(row.get('请求体', ''))
    r_body = str(row.get('响应体', ''))
    threat_level = str(row.get('威胁等级', ''))
    ai_analysis = str(row.get('AI分析要点', ''))

    # 编码绕过检测
    bypass_info = detect_encoding_bypass(q_body)
    result["bypass_detection"] = bypass_info

    # 提取URI（从请求体中简单提取）
    uri = ""
    if q_body:
        # 尝试提取第一行作为URI
        lines = q_body.split('\n')
        if lines:
            first_line = lines[0].strip()
            if first_line.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ')):
                uri = first_line.split()[1] if len(first_line.split()) > 1 else ""

    # 1. 业务流量识别
    business_result = analyze_business_traffic(q_body, uri, msg)
    if business_result["is_business"]:
        # 检查是否有攻击特征
        attack_patterns_found = []
        for attack_type, patterns in ATTACK_FEATURES.items():
            for pattern in patterns:
                if pattern in q_body.lower():
                    attack_patterns_found.append(pattern)
                    break

        if attack_patterns_found:
            result["requires_manual_review"] = True
            result["is_false_positive"] = None
            result["false_positive_reason"] = f"匹配业务模式 [{business_result['business_type']}，但同时存在攻击特征: {', '.join(attack_patterns_found)}，需人工审核"
            result["evidence"].extend(business_result["evidence"])
            result["evidence"].append(f"检测到攻击特征: {', '.join(attack_patterns_found)}")
            result["confidence"] = "低"
            return result
        else:
            result["is_false_positive"] = True
            result["false_positive_reason"] = business_result["reason"]
            result["evidence"].extend(business_result["evidence"])
            result["confidence"] = "高"
            return result

    # 2. 编码绕过分析
    if bypass_info["has_encoding"]:
        # 检查原始q_body是否包含攻击特征
        original_has_attack = False
        for attack_type, patterns in ATTACK_FEATURES.items():
            for pattern in patterns:
                if pattern in q_body.lower():
                    original_has_attack = True
                    break
            if original_has_attack:
                break

        if original_has_attack and not bypass_info["is_attack"]:
            # 原始内容有攻击特征，但解码后没有
            result["evidence"].append(f"检测到{', '.join(bypass_info['encoding_types'])}编码")
            result["evidence"].append(f"原始请求体包含攻击特征")
            result["evidence"].append(f"解码后未检测到明确攻击特征: {bypass_info['decoded_content'][:100] if bypass_info['decoded_content'] else '空'}")
            result["requires_manual_review"] = True
            result["is_false_positive"] = None
            result["false_positive_reason"] = "流量经过编码处理，原始内容含攻击特征但解码后特征消散，需人工审核"
            result["confidence"] = "低"
            return result
        elif not original_has_attack and not bypass_info["is_attack"]:
            # 原始和解码后都没有攻击特征
            result["evidence"].append(f"检测到{', '.join(bypass_info['encoding_types'])}编码")
            result["evidence"].append("原始请求体和解码后均未检测到明确攻击特征")
            result["is_false_positive"] = True
            result["false_positive_reason"] = "流量经过编码处理，原始内容和解码后均未发现有效攻击特征"
            result["confidence"] = "中"
            return result

    # 3. 攻击特征检测
    attack_patterns_found = []
    for attack_type, patterns in ATTACK_FEATURES.items():
        for pattern in patterns:
            if pattern in q_body.lower():
                attack_patterns_found.append(pattern)
                break

    # 4. 响应体分析
    response_success = False
    if r_body:
        if "error" in r_body.lower() or "exception" in r_body.lower():
            result["evidence"].append("响应包含错误信息，可能表明攻击被拦截")
        # 检查是否有敏感信息泄露
        if "root:x:" in r_body or "bin/bash" in r_body:
            response_success = True
            result["evidence"].append("响应包含系统信息泄露特征")

    # 5. 置信度计算
    result["confidence"] = calculate_confidence(result["evidence"], attack_patterns_found, response_success)

    # 6. 最终判定
    if result["is_false_positive"] is None:
        if attack_patterns_found:
            result["is_false_positive"] = False
            result["false_positive_reason"] = "检测到明确的攻击特征"
            if not result["evidence"]:
                result["evidence"].append(f"检测到攻击特征: {', '.join(attack_patterns_found)}")
        else:
            # 无足够证据，标记为需人工审核
            result["requires_manual_review"] = True
            result["is_false_positive"] = None
            result["false_positive_reason"] = "基于现有数据无法确定，需人工审核"

    return result


def analyze_single_vendor(file_path: str, vendor: str) -> Dict:
    """
    分析单个厂商的告警日志

    Args:
        file_path: CSV文件路径
        vendor: 厂商名称

    Returns:
        分析结果字典
    """
    # 读取文件
    print(f"读取{vendor}文件: {file_path}")
    df = read_csv_with_encoding(file_path, vendor)

    if df.empty:
        return {
            'vendor': vendor,
            'total_alerts': 0,
            'event_types': {},
            'high_risk_count': 0,
            'medium_risk_count': 0,
            'low_risk_count': 0,
            'top_alerts': []
        }

    # 统计事件类型
    event_types = defaultdict(int)
    event_type_details = defaultdict(list)

    # 统计风险等级
    high_risk_count = 0
    medium_risk_count = 0
    low_risk_count = 0

    # 记录前10个告警
    top_alerts = []

    # 微步误报分析结果（仅当vendor为微步时）
    threatbook_fp_analysis = None
    threatbook_alert_count = 0
    threatbook_fp_count = 0
    threatbook_manual_review_count = 0
    threatbook_tp_count = 0

    for idx, row in df.iterrows():
        event_name = str(row.get('事件名称', ''))
        event_type = str(row.get('事件类型', ''))
        threat_level = str(row.get('威胁等级', ''))

        # 统计事件类型
        event_types[event_type] += 1

        # 记录详情
        detail = {
            'event_name': event_name,
            'threat_level': threat_level,
            'source_ip': str(row.get('源IP', '')),
            'destination_ip': str(row.get('目的IP', '')),
            'source_port': str(row.get('源端口', '')),
            'destination_port': str(row.get('目的端口', '')),
        }
        event_type_details[event_type].append(detail)

        # 根据威胁等级统计
        if '高' in threat_level or '严重' in threat_level:
            high_risk_count += 1
        elif '中' in threat_level:
            medium_risk_count += 1
        elif '低' in threat_level:
            low_risk_count += 1

        # 记录前10个告警
        if len(top_alerts) < 10:
            top_alerts.append(detail)

        # 微步厂商误报分析
        if vendor == '微步':
            # 严格验证设备来源字段是否包含"微步"
            device_source = str(row.get('设备来源', ''))
            if '微步' in device_source:
                threatbook_alert_count += 1
                fp_result = analyze_threatbook_alert(row)
                detail['false_positive_analysis'] = fp_result

                if fp_result['is_false_positive'] is True:
                    threatbook_fp_count += 1
                elif fp_result['is_false_positive'] is False:
                    threatbook_tp_count += 1
                elif fp_result['requires_manual_review']:
                    threatbook_manual_review_count += 1
            else:
                # 设备来源不包含"微步"，不进行误报分析
                detail['false_positive_analysis'] = {
                    'confidence': '',
                    'is_false_positive': None,
                    'requires_manual_review': False,
                    'false_positive_reason': f'设备来源"{device_source}"不包含"微步"，未进行误报判定',
                    'bypass_detection': {},
                    'evidence': []
                }

    result = {
        'vendor': vendor,
        'total_alerts': len(df),
        'event_types': dict(event_types),
        'event_type_details': {k: v[:5] for k, v in event_type_details.items()},  # 每个类型最多5个示例
        'high_risk_count': high_risk_count,
        'medium_risk_count': medium_risk_count,
        'low_risk_count': low_risk_count,
        'top_alerts': top_alerts
    }

    # 添加微步误报分析结果
    if vendor == '微步' and threatbook_alert_count > 0:
        result['threatbook_false_positive_analysis'] = {
            'total_alerts': threatbook_alert_count,
            'false_positive_count': threatbook_fp_count,
            'true_positive_count': threatbook_tp_count,
            'manual_review_count': threatbook_manual_review_count,
            'false_positive_rate': round(threatbook_fp_count / threatbook_alert_count * 100, 2) if threatbook_alert_count > 0 else 0
        }

    return result


def main():
    if len(sys.argv) < 3:
        print("使用方法: python analyze_single_vendor.py <文件路径> <厂商名称>")
        print("示例: python analyze_single_vendor.py F:/claude/qinghua/log/绿盟事件研判0001_20260519_092200_to_20260519_092356.csv 绿盟")
        sys.exit(1)

    file_path = sys.argv[1]
    vendor = sys.argv[2]

    result = analyze_single_vendor(file_path, vendor)

    print(f"\n{vendor}告警分析结果：")
    print(f"总告警数：{result['total_alerts']}")
    print(f"高风险告警：{result['high_risk_count']}")
    print(f"中风险告警：{result['medium_risk_count']}")
    print(f"低风险告警：{result['low_risk_count']}")
    print(f"\n事件类型统计：")
    for event_type, count in sorted(result['event_types'].items(), key=lambda x: x[1], reverse=True):
        print(f"  {event_type}：{count}")

    # 保存结果
    output_file = f"{vendor}_analysis_result.json"
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    print(f"\n结果已保存到：{output_file}")

    return result


if __name__ == "__main__":
    main()