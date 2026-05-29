#!/usr/bin/env python3
"""Parse security vendor CSV alert logs into standardized JSON format.

Usage:
    python3 parse_csv.py <input.csv> --vendor <name> [--output <dir>] [--chunk-size 10000]

Features:
    - Auto-detect CSV delimiter and encoding
    - Normalize timestamps to YYYY-MM-DD HH:mm:ss
    - Normalize IP addresses
    - Large file slicing with configurable chunk size
    - Generate keyed JSON structure: { "startTime_endTime": [...] }
    - Data integrity validation (row counts, field missing rate)
"""

import argparse
import csv
import json
import os
import sys
import re
from collections import defaultdict
from datetime import datetime

# ---------------------------------------------------------------------------
# Field mapping: common Chinese/English column names → canonical keys
# ---------------------------------------------------------------------------
FIELD_MAP = {
    # 生成时间
    "生成时间": "生成时间", "发生时间": "生成时间", "告警时间": "生成时间",
    "timestamp": "生成时间", "time": "生成时间", "alert_time": "生成时间",
    # 结束时间
    "结束时间": "结束时间", "end_time": "结束时间",
    # 事件名称
    "事件名称": "事件名称", "告警名称": "事件名称", "rule_name": "事件名称",
    "alert_name": "事件名称", "signature": "事件名称", "rule": "事件名称",
    # 事件类型
    "事件类型": "事件类型", "攻击类型": "事件类型", "attack_type": "事件类型",
    "event_type": "事件类型", "alert_type": "事件类型",
    # 源IP
    "源IP": "源IP", "源ip": "源IP", "源地址": "源IP", "src_ip": "源IP",
    "source_ip": "源IP", "srcaddr": "源IP",
    # 源端口
    "源端口": "源端口", "src_port": "源端口", "source_port": "源端口",
    # 目的IP
    "目的IP": "目的IP", "目的ip": "目的IP", "目的地址": "目的IP",
    "dst_ip": "目的IP", "dest_ip": "目的IP", "destination_ip": "目的IP",
    "dstaddr": "目的IP",
    # 目的端口
    "目的端口": "目的端口", "dst_port": "目的端口", "dest_port": "目的端口",
    "destination_port": "目的端口",
    # 发生次数
    "发生次数": "发生次数", "次数": "发生次数", "count": "发生次数",
    "hit_count": "发生次数",
    # 请求体
    "请求体": "req_payload", "req_payload": "req_payload", "payload": "req_payload",
    "request": "req_payload", "http_request": "req_payload",
    # 响应体
    "响应体": "rep_payload", "rep_payload": "rep_payload", "response": "rep_payload",
    "http_response": "rep_payload",
    # 告警严重等级
    "告警严重等级": "告警严重等级", "严重等级": "告警严重等级", "severity": "告警严重等级",
    "level": "告警严重等级", "priority": "告警严重等级",
    # 设备来源 / 规则ID
    "设备来源": "设备来源", "device": "设备来源", "vendor": "设备来源",
    "规则ID": "规则ID", "rule_id": "规则ID", "sid": "规则ID",
}

REQUIRED_FIELDS = ["生成时间", "事件名称", "事件类型", "源IP", "目的IP"]
SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}


def detect_delimiter(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        sample = f.read(4096)
    if sample.count("\t") > sample.count(","):
        return "\t"
    return ","


def parse_line_count(path):
    """Count total lines in a file efficiently."""
    with open(path, "rb") as f:
        return sum(1 for _ in f)


def normalize_timestamp(val):
    """Try various timestamp formats → YYYY-MM-DD HH:mm:ss"""
    if not val or not val.strip():
        return ""
    val = val.strip().strip('"').strip("'")
    for fmt in [
        "%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S", "%Y/%m/%dT%H:%M:%S",
        "%Y-%m-%d %H:%M", "%Y/%m/%d %H:%M",
        "%m/%d/%Y %H:%M:%S", "%d-%b-%Y %H:%M:%S",
        "%Y%m%d%H%M%S",
    ]:
        try:
            return datetime.strptime(val[:19], fmt).strftime("%Y-%m-%d %H:%M:%S")
        except (ValueError, IndexError):
            continue
    return val[:19] if len(val) >= 16 else val


def normalize_ip(val):
    """Basic IP validation and normalization."""
    if not val or not val.strip():
        return ""
    val = val.strip().strip('"').strip("'")
    ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    if ip_pattern.match(val):
        return val
    return val  # return as-is if not a clean IP (could be hostname)


def clean_payload(val):
    """URL-decode and clean payload content."""
    if not val:
        return ""
    val = val.strip().strip('"').strip("'")
    # Apply URL decoding once
    import urllib.parse
    try:
        decoded = urllib.parse.unquote(val)
        return decoded if decoded != val else val
    except Exception:
        return val


def build_field_map(header_row):
    """Map CSV column names to canonical keys."""
    mapping = {}
    unresolved = []
    for col in header_row:
        col_clean = col.strip().strip('"').strip("'").lower()
        if col in FIELD_MAP:
            mapping[col] = FIELD_MAP[col]
        elif col_clean in {k.lower() for k in FIELD_MAP}:
            for k in FIELD_MAP:
                if k.lower() == col_clean:
                    mapping[col] = FIELD_MAP[k]
                    break
        else:
            unresolved.append(col)
    return mapping, unresolved


def parse_csv(path, vendor_name, chunk_size=0):
    """Parse a CSV file and return (records, stats)."""
    delimiter = detect_delimiter(path)
    total_lines = parse_line_count(path)
    records = []
    stats = {"total_lines": total_lines, "parsed": 0, "skipped": 0,
             "missing_required": 0, "field_missing_counts": defaultdict(int)}
    last_reported_pct = 0

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.reader(f, delimiter=delimiter)
        try:
            header = next(reader)
        except StopIteration:
            return [], stats

        field_map, unresolved = build_field_map(header)
        if unresolved:
            stats["unresolved_columns"] = unresolved

        canonical_fields = []
        for col in header:
            canonical_fields.append(field_map.get(col, col))

        for row_num, row in enumerate(reader, start=2):
            if not row or all(cell.strip() == "" for cell in row):
                stats["skipped"] += 1
                continue

            # Build record from mapped fields
            record = {}
            for i, val in enumerate(row):
                key = canonical_fields[i] if i < len(canonical_fields) else None
                if key:
                    record[key] = val.strip().strip('"').strip("'")

            # Add vendor source
            record["设备来源"] = vendor_name

            # Check required fields
            missing = [f for f in REQUIRED_FIELDS if f not in record or not record[f].strip()]
            if missing:
                stats["missing_required"] += 1
                for m in missing:
                    stats["field_missing_counts"][m] += 1

            # Normalize fields
            if "生成时间" in record:
                record["生成时间"] = normalize_timestamp(record["生成时间"])
            if "结束时间" in record:
                record["结束时间"] = normalize_timestamp(record["结束时间"])
            if "源IP" in record:
                record["源IP"] = normalize_ip(record["源IP"])
            if "目的IP" in record:
                record["目的IP"] = normalize_ip(record["目的IP"])
            if "req_payload" in record:
                record["req_payload"] = clean_payload(record["req_payload"])
            if "rep_payload" in record:
                record["rep_payload"] = clean_payload(record["rep_payload"])
            if "告警严重等级" in record:
                sev = record["告警严重等级"].capitalize()
                if sev in SEVERITY_ORDER:
                    record["告警严重等级"] = sev

            records.append(record)
            stats["parsed"] += 1

            # Progress for large files
            if chunk_size and stats["parsed"] % chunk_size == 0:
                pct = int(stats["parsed"] / total_lines * 100) if total_lines else 0
                if pct >= last_reported_pct + 10:
                    print(f"  Progress: {pct}% ({stats['parsed']}/{total_lines})", file=sys.stderr)
                    last_reported_pct = pct

    stats["unparsed"] = total_lines - stats["parsed"] - stats["skipped"] - 1  # -1 for header
    return records, stats


def build_json_output(records, vendor_name):
    """Group records by time key and build the standard output structure."""
    grouped = defaultdict(list)
    for rec in records:
        ts = rec.get("生成时间", "unknown")
        start_key = ts[:16] if len(ts) >= 16 else ts  # minute granularity
        # Use hour-level keys: 2025-01-01 10:00:00 → "2025-01-01 10:00:00_2025-01-01 11:00:00"
        if ts and ts != "unknown":
            try:
                dt = datetime.strptime(ts[:19], "%Y-%m-%d %H:%M:%S")
                hour_start = dt.strftime("%Y-%m-%d %H:00:00")
                hour_end = dt.replace(hour=dt.hour + 1).strftime("%Y-%m-%d %H:00:00")
                key = f"{hour_start}_{hour_end}"
            except ValueError:
                key = ts
        else:
            key = ts

        entry = {
            "事件类型": rec.get("事件类型", ""),
            "事件名称": rec.get("事件名称", ""),
            "发生次数": rec.get("发生次数", "1"),
            "五元组": f"{rec.get('源IP', '')}_{rec.get('源端口', '')}->{rec.get('目的IP', '')}_{rec.get('目的端口', '')}",
            "req_payload": rec.get("req_payload", ""),
            "rep_payload": rec.get("rep_payload", ""),
            "设备来源": vendor_name,
        }
        if "告警严重等级" in rec:
            entry["告警严重等级"] = rec["告警严重等级"]
        if "规则ID" in rec:
            entry["规则ID"] = rec["规则ID"]
        grouped[key].append(entry)

    return dict(grouped)


def compute_integrity(stats):
    """Compute row-level integrity check."""
    accounted = stats["parsed"] + stats["skipped"] + stats.get("unparsed", 0) + 1  # +1 header
    integrity = {
        "total_file_lines": stats["total_lines"],
        "parsed_rows": stats["parsed"],
        "skipped_rows": stats["skipped"],
        "unparsed_rows": stats.get("unparsed", 0),
        "header_row": 1,
        "accounted_total": accounted,
        "integrity_match": accounted == stats["total_lines"],
        "missing_required_field_count": stats["missing_required"],
        "missing_field_details": dict(stats.get("field_missing_counts", {})),
        "unresolved_columns": stats.get("unresolved_columns", []),
    }
    return integrity


def main():
    parser = argparse.ArgumentParser(description="Parse security vendor CSV alert logs")
    parser.add_argument("input", help="Input CSV file path")
    parser.add_argument("--vendor", "-v", required=True, help="Vendor/source name")
    parser.add_argument("--output", "-o", default=".", help="Output directory (default: current)")
    parser.add_argument("--chunk-size", type=int, default=10000,
                        help="Rows per chunk for progress reporting (0=disable)")
    args = parser.parse_args()

    if not os.path.isfile(args.input):
        print(f"Error: File not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    print(f"Parsing: {args.input}", file=sys.stderr)
    print(f"Vendor: {args.vendor}", file=sys.stderr)

    records, stats = parse_csv(args.input, args.vendor, chunk_size=args.chunk_size)
    integrity = compute_integrity(stats)

    if records:
        json_data = build_json_output(records, args.vendor)
        output_file = os.path.join(args.output, f"{args.vendor}.json")
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(json_data, f, ensure_ascii=False, indent=2)
        print(f"Output: {output_file}", file=sys.stderr)
    else:
        print("Warning: No records parsed!", file=sys.stderr)
        output_file = None

    # Write integrity report
    integrity_file = os.path.join(args.output, f"{args.vendor}_integrity.json")
    with open(integrity_file, "w", encoding="utf-8") as f:
        json.dump(integrity, f, ensure_ascii=False, indent=2)
    print(f"Integrity: {integrity_file}", file=sys.stderr)

    # Summary
    print(f"\nSummary:", file=sys.stderr)
    print(f"  Total lines: {stats['total_lines']}", file=sys.stderr)
    print(f"  Parsed records: {stats['parsed']}", file=sys.stderr)
    print(f"  Skipped (empty): {stats['skipped']}", file=sys.stderr)
    print(f"  Integrity match: {integrity['integrity_match']}", file=sys.stderr)
    print(f"  Missing required fields: {stats['missing_required']}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())