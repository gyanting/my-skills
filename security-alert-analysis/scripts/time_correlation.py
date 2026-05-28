#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
时间关联分析脚本
用于判断绿盟和微步日志文件的时间是否关联
"""

import re
import json
import sys
from datetime import datetime, timedelta
from typing import Dict, Tuple


def parse_time_from_filename(filename: str) -> Tuple[datetime, datetime]:
    """
    从文件名中解析时间范围

    文件名格式示例：
    - 绿盟事件研判_0001_20260519_092200_to_20260519_092356.csv
    - 微步事件研判0001_20260519_092213_to_20260519_092518.csv

    Args:
        filename: 文件名

    Returns:
        (开始时间, 结束时间)
    """
    # 尝试匹配时间格式
    pattern = r'(\d{8})_(\d{6})_to_(\d{8})_(\d{6})'
    match = re.search(pattern, filename)

    if match:
        start_date_str, start_time_str, end_date_str, end_time_str = match.groups()

        start_dt = datetime.strptime(f"{start_date_str}{start_time_str}", "%Y%m%d%H%M%S")
        end_dt = datetime.strptime(f"{end_date_str}{end_time_str}", "%Y%m%d%H%M%S")

        return start_dt, end_dt

    raise ValueError(f"无法从文件名解析时间: {filename}")


def check_time_correlation(start1: datetime, end1: datetime,
                          start2: datetime, end2: datetime) -> Dict:
    """
    检查两个时间范围是否关联

    Args:
        start1: 文件1的开始时间
        end1: 文件1的结束时间
        start2: 文件2的开始时间
        end2: 文件2的结束时间

    Returns:
        包含关联分析结果的字典
    """
    # 检查是否有交集或相接
    gap_before = start2 - end1  # 文件2开始时间 - 文件1结束时间
    gap_after = start1 - end2   # 文件1开始时间 - 文件2结束时间

    # 检查是否完全包含
    if start1 <= start2 and end1 >= end2:
        relation_type = "完全包含"
        is_related = True
        analysis = f"文件1（{start1.strftime('%H%M%S')}-{end1.strftime('%H%M%S')}）完全包含文件2（{start2.strftime('%H%M%S')}-{end2.strftime('%H%M%S')}）的时间范围"

    elif start2 <= start1 and end2 >= end1:
        relation_type = "完全包含"
        is_related = True
        analysis = f"文件2（{start2.strftime('%H%M%S')}-{end2.strftime('%H%M%S')}）完全包含文件1（{start1.strftime('%H%M%S')}-{end1.strftime('%H%M%S')}）的时间范围"

    # 检查部分重叠
    elif start1 < end2 and start2 < end1:
        relation_type = "部分重叠"
        is_related = True
        overlap_start = max(start1, start2)
        overlap_end = min(end1, end2)
        analysis = f"两个文件在{overlap_start.strftime('%H%M%S')}-{overlap_end.strftime('%H%M%S')}时间段有交集"

    # 检查首尾相接（间隔<=1秒）
    elif abs(gap_before.total_seconds()) <= 1 or abs(gap_after.total_seconds()) <= 1:
        relation_type = "首尾相接"
        is_related = True
        gap = min(abs(gap_before.total_seconds()), abs(gap_after.total_seconds()))
        analysis = f"两个文件时间范围相接，间隔{gap}秒"

    # 检查时间断层
    elif gap_before.total_seconds() > 1 or gap_after.total_seconds() > 1:
        relation_type = "时间断层"
        is_related = False
        gap = max(gap_before.total_seconds(), gap_after.total_seconds())
        analysis = f"两个文件时间范围断层，间隔约{gap:.0f}秒，不满足关联条件"

    # 完全分离
    else:
        relation_type = "完全分离"
        is_related = False
        analysis = "两个文件时间范围完全分离，无重叠且不连续"

    return {
        "is_related": is_related,
        "relation_type": relation_type,
        "analysis": analysis,
        "file1_time_range": {
            "start": start1.strftime("%Y-%m-%d %H:%M:%S"),
            "end": end1.strftime("%Y-%m-%d %H:%M:%S")
        },
        "file2_time_range": {
            "start": start2.strftime("%Y-%m-%d %H:%M:%S"),
            "end": end2.strftime("%Y-%m-%d %H:%M:%S")
        }
    }


def main():
    if len(sys.argv) < 3:
        print("使用方法: python time_correlation.py <绿盟文件路径> <微步文件路径>")
        print("示例: python time_correlation.py F:/claude/qinghua/log/绿盟事件研判0001_20260519_092200_to_20260519_092356.csv F:/claude/qinghua/log/微步事件研判0001_20260519_092213_to_20260519_092518.csv")
        sys.exit(1)

    file1 = sys.argv[1]
    file2 = sys.argv[2]

    print(f"分析文件1: {file1}")
    print(f"分析文件2: {file2}")

    try:
        # 解析时间
        start1, end1 = parse_time_from_filename(file1)
        start2, end2 = parse_time_from_filename(file2)

        print(f"文件1时间范围: {start1.strftime('%Y-%m-%d %H:%M:%S')} 至 {end1.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"文件2时间范围: {start2.strftime('%Y-%m-%d %H:%M:%S')} 至 {end2.strftime('%Y-%m-%d %H:%M:%S')}")

        # 检查关联性
        result = check_time_correlation(start1, end1, start2, end2)

        print(f"\n关联类型: {result['relation_type']}")
        print(f"是否关联: {result['is_related']}")
        print(f"分析: {result['analysis']}")

        # 输出JSON结果
        output_file = "time_correlation_result.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(result, f, ensure_ascii=False, indent=2)

        print(f"\n结果已保存到: {output_file}")

        return result

    except Exception as e:
        print(f"错误: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()