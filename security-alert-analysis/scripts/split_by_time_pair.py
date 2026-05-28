#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
按时间窗口将一对（绿盟+微步）大 CSV 切成若干分片对。

设计要点：
- 两厂商共享同一个时间桶 → 分片自动配对对齐
- 桶内任一方超过 max_rows 时优先时间二分，极端同秒上万行才按行数硬切
- 时间不重叠则 short-circuit 写 should_split=false，调用方走 analyze_single_vendor.py
- 时间无法解析的行进 __unparsed__ 桶，设备来源字段含损坏字符的行进 __corrupt__ 桶

使用：
    python split_by_time_pair.py <绿盟.csv> <微步.csv> \
        --window-sec 300 --max-rows 10000 --outdir chunks/

产出：
    chunks/manifest_pair.json
    chunks/cNNNN/绿盟_..._to_....csv
    chunks/cNNNN/微步_..._to_....csv
    chunks/__unparsed__/{lvmeng,weibu}.csv   （如有）
    chunks/__corrupt__/{lvmeng,weibu}.csv    （如有）
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd


TIME_COL = '生成时间'
DEVICE_SRC_COL = '设备来源'
EVENT_NAME_COL = '事件名称'
TIME_FMT = '%Y-%m-%d %H:%M:%S'
REPL_CHAR = '�'


def read_csv(path):
    """用 gb18030 读取 CSV，遇到非法字节用 replace 兜底。dtype=str 保留 '12546 这种前导引号。"""
    try:
        return pd.read_csv(
            path, encoding='gb18030', dtype=str,
            keep_default_na=False, encoding_errors='replace'
        )
    except TypeError:
        with open(path, 'rb') as f:
            data = f.read()
        text = data.decode('gb18030', errors='replace')
        from io import StringIO
        return pd.read_csv(StringIO(text), dtype=str, keep_default_na=False)


def parse_time_safe(s):
    try:
        return datetime.strptime(s, TIME_FMT)
    except Exception:
        return None


def classify_rows(df):
    """
    将 df 分为三组：
    - good_df: 时间可解析、设备来源未损坏，附加 __dt__ 列（datetime）
    - unparsed_df: 时间字段无法解析
    - corrupt_df: 设备来源含 �（说明 gb18030 decode 时这一行就坏了）
    """
    if df.empty:
        empty = df.iloc[0:0].copy()
        return empty, empty, empty

    if DEVICE_SRC_COL in df.columns:
        corrupt_mask = df[DEVICE_SRC_COL].astype(str).str.contains(REPL_CHAR, regex=False, na=False)
    else:
        corrupt_mask = pd.Series([False] * len(df), index=df.index)
    corrupt_df = df[corrupt_mask].copy()
    remaining = df[~corrupt_mask].copy()

    if TIME_COL not in remaining.columns:
        empty = remaining.iloc[0:0].copy()
        return empty, remaining, corrupt_df

    dt = remaining[TIME_COL].apply(parse_time_safe)
    unparsed_mask = dt.isna()
    unparsed_df = remaining[unparsed_mask].copy()
    good_df = remaining[~unparsed_mask].copy()
    good_df['__dt__'] = dt[~unparsed_mask]
    return good_df, unparsed_df, corrupt_df


def hard_split_by_rows(l_sub, w_sub, start, end, max_rows):
    """同秒上万条等极端情况按行数硬切；标 hard_split=True。"""
    n = max(len(l_sub), len(w_sub))
    if n <= max_rows:
        return [(l_sub, w_sub, start, end, True)]
    n_chunks = (n + max_rows - 1) // max_rows
    l_sorted = l_sub.sort_values('__dt__') if not l_sub.empty else l_sub
    w_sorted = w_sub.sort_values('__dt__') if not w_sub.empty else w_sub

    def _slice(df, idx, total):
        if df.empty or total == 0:
            return df.iloc[0:0]
        step = (len(df) + total - 1) // total
        return df.iloc[idx * step:(idx + 1) * step]

    chunks = []
    for i in range(n_chunks):
        chunks.append((
            _slice(l_sorted, i, n_chunks),
            _slice(w_sorted, i, n_chunks),
            start, end, True
        ))
    return chunks


def subdivide_if_needed(l_sub, w_sub, start, end, max_rows):
    """
    递归分片：
    1. 两边 ≤ max_rows → 单一 chunk
    2. 窗口 ≤ 1 秒 → 行数硬切
    3. 否则取桶内行时间中位数为切点，二分递归
    """
    if len(l_sub) <= max_rows and len(w_sub) <= max_rows:
        return [(l_sub, w_sub, start, end, False)]

    if (end - start).total_seconds() <= 1:
        return hard_split_by_rows(l_sub, w_sub, start, end, max_rows)

    all_dts = []
    if not l_sub.empty:
        all_dts.extend(l_sub['__dt__'].tolist())
    if not w_sub.empty:
        all_dts.extend(w_sub['__dt__'].tolist())
    if not all_dts:
        return [(l_sub, w_sub, start, end, False)]

    all_dts.sort()
    mid_dt = all_dts[len(all_dts) // 2]
    if mid_dt <= start or mid_dt >= end:
        mid_dt = start + (end - start) / 2

    l_left = l_sub[l_sub['__dt__'] < mid_dt] if not l_sub.empty else l_sub
    l_right = l_sub[l_sub['__dt__'] >= mid_dt] if not l_sub.empty else l_sub
    w_left = w_sub[w_sub['__dt__'] < mid_dt] if not w_sub.empty else w_sub
    w_right = w_sub[w_sub['__dt__'] >= mid_dt] if not w_sub.empty else w_sub

    if (len(l_left) == len(l_sub) and len(w_left) == len(w_sub)) or \
       (len(l_right) == len(l_sub) and len(w_right) == len(w_sub)):
        return hard_split_by_rows(l_sub, w_sub, start, end, max_rows)

    out = []
    out.extend(subdivide_if_needed(l_left, w_left, start, mid_dt, max_rows))
    out.extend(subdivide_if_needed(l_right, w_right, mid_dt, end, max_rows))
    return out


def time_bucket_split(l_good, w_good, window_sec, max_rows):
    """按 window_sec 共享时间桶切分；空桶（两边都空）跳过。"""
    t_min_cands, t_max_cands = [], []
    if not l_good.empty:
        t_min_cands.append(l_good['__dt__'].min())
        t_max_cands.append(l_good['__dt__'].max())
    if not w_good.empty:
        t_min_cands.append(w_good['__dt__'].min())
        t_max_cands.append(w_good['__dt__'].max())
    if not t_min_cands:
        return []

    t_start = min(t_min_cands)
    t_end = max(t_max_cands) + timedelta(seconds=1)

    epoch = datetime(1970, 1, 1)
    start_offset = int((t_start - epoch).total_seconds()) // window_sec * window_sec
    aligned_start = epoch + timedelta(seconds=start_offset)

    chunks = []
    cur = aligned_start
    while cur < t_end:
        nxt = cur + timedelta(seconds=window_sec)
        l_sub = l_good[(l_good['__dt__'] >= cur) & (l_good['__dt__'] < nxt)] if not l_good.empty else l_good
        w_sub = w_good[(w_good['__dt__'] >= cur) & (w_good['__dt__'] < nxt)] if not w_good.empty else w_good
        if l_sub.empty and w_sub.empty:
            cur = nxt
            continue
        chunks.extend(subdivide_if_needed(l_sub, w_sub, cur, nxt, max_rows))
        cur = nxt
    return chunks


def derive_chunk_filename(orig_filename, start_dt, end_dt):
    """
    原文件名形如：绿盟事件研判_0001_20260519_092200_to_20260519_092356.csv
    输出形如：    绿盟事件研判_0001_20260519_092200_to_20260519_092700.csv
    保留时间段前的前缀，时间替换为当前 chunk 的起止。
    """
    base = os.path.basename(orig_filename)
    m = re.match(r'^(.+?)(\d{8}_\d{6}_to_\d{8}_\d{6})\.csv$', base)
    prefix = m.group(1) if m else (os.path.splitext(base)[0] + '_')
    s = start_dt.strftime('%Y%m%d_%H%M%S')
    e = end_dt.strftime('%Y%m%d_%H%M%S')
    return f"{prefix}{s}_to_{e}.csv"


def write_df(df, path, template_cols=None):
    """写 CSV：剔除辅助列；空 DataFrame 时仅写表头（让下游 compare_alerts.py 正常处理空文件）。"""
    if df.empty and template_cols is not None:
        pd.DataFrame(columns=template_cols).to_csv(path, index=False, encoding='gb18030')
        return
    df_out = df.drop(columns=['__dt__'], errors='ignore')
    df_out.to_csv(path, index=False, encoding='gb18030')


COOKBOOK_KEYWORDS = {
    'sql_injection': ['sql', 'sqli', 'union select', 'or 1=1', '注入'],
    'xss': ['xss', '跨站脚本', '<script>', 'script'],
    'csrf': ['csrf', '跨站请求'],
    'ssrf': ['ssrf', '服务器端请求'],
    'command_injection': ['命令注入', 'rce', '远程命令', 'shell'],
    'web_crawler': ['爬虫', 'bot', '扫描', 'crawler', 'spider'],
}


def likely_cookbook(events):
    """根据事件名抽样预判该 chunk 主要攻击主题，让子代理优先加载对应 cookbook。"""
    if not events:
        return None
    counts = {k: 0 for k in COOKBOOK_KEYWORDS}
    for ev in events[:300]:
        ev_l = str(ev).lower()
        for k, kws in COOKBOOK_KEYWORDS.items():
            if any(kw in ev_l for kw in kws):
                counts[k] += 1
                break
    best = max(counts.items(), key=lambda x: x[1])
    return best[0] if best[1] > 0 else None


def main():
    parser = argparse.ArgumentParser(description='按时间窗口切分一对绿盟+微步大 CSV')
    parser.add_argument('lvmeng_csv', help='绿盟 CSV 路径')
    parser.add_argument('weibu_csv', help='微步 CSV 路径')
    parser.add_argument('--window-sec', type=int, default=300, help='时间窗口大小（秒），默认 300=5min')
    parser.add_argument('--max-rows', type=int, default=10000, help='单 chunk 单厂商行数硬上限，默认 10000')
    parser.add_argument('--outdir', default='chunks', help='输出目录')
    args = parser.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    print(f'[split] 读取绿盟: {args.lvmeng_csv}')
    df_lvmeng = read_csv(args.lvmeng_csv)
    print(f'[split] 读取微步: {args.weibu_csv}')
    df_weibu = read_csv(args.weibu_csv)
    print(f'[split] 行数: 绿盟 {len(df_lvmeng)} / 微步 {len(df_weibu)}')

    l_good, l_unparsed, l_corrupt = classify_rows(df_lvmeng)
    w_good, w_unparsed, w_corrupt = classify_rows(df_weibu)
    print(f'[split] 可分片: 绿盟 {len(l_good)} / 微步 {len(w_good)}；'
          f'unparsed: 绿盟 {len(l_unparsed)} / 微步 {len(w_unparsed)}；'
          f'corrupt: 绿盟 {len(l_corrupt)} / 微步 {len(w_corrupt)}')

    if len(l_unparsed) or len(w_unparsed):
        up_dir = outdir / '__unparsed__'
        up_dir.mkdir(exist_ok=True)
        if len(l_unparsed):
            write_df(l_unparsed, up_dir / 'lvmeng.csv')
        if len(w_unparsed):
            write_df(w_unparsed, up_dir / 'weibu.csv')

    if len(l_corrupt) or len(w_corrupt):
        cp_dir = outdir / '__corrupt__'
        cp_dir.mkdir(exist_ok=True)
        if len(l_corrupt):
            write_df(l_corrupt, cp_dir / 'lvmeng.csv')
        if len(w_corrupt):
            write_df(w_corrupt, cp_dir / 'weibu.csv')

    lvmeng_cols = list(df_lvmeng.columns)
    weibu_cols = list(df_weibu.columns)

    base_manifest = {
        'source': {'lvmeng': str(args.lvmeng_csv), 'weibu': str(args.weibu_csv)},
        'window_sec': args.window_sec,
        'max_rows': args.max_rows,
        'unparsed_rows': {'lvmeng': int(len(l_unparsed)), 'weibu': int(len(w_unparsed))},
        'corrupt_rows': {'lvmeng': int(len(l_corrupt)), 'weibu': int(len(w_corrupt))},
    }

    if l_good.empty and w_good.empty:
        manifest = {**base_manifest, 'should_split': False,
                    'reason': 'no_parseable_rows', 'chunks': []}
        _write_manifest(outdir, manifest)
        print('[split] 两文件均无可解析时间行，已 short-circuit')
        return

    if not l_good.empty and not w_good.empty:
        l_min, l_max = l_good['__dt__'].min(), l_good['__dt__'].max()
        w_min, w_max = w_good['__dt__'].min(), w_good['__dt__'].max()
        overlap_start = max(l_min, w_min)
        overlap_end = min(l_max, w_max)
        if overlap_start > overlap_end:
            manifest = {
                **base_manifest, 'should_split': False, 'reason': 'no_overlap',
                'time_domain': {
                    'lvmeng': {'start': l_min.strftime(TIME_FMT), 'end': l_max.strftime(TIME_FMT)},
                    'weibu': {'start': w_min.strftime(TIME_FMT), 'end': w_max.strftime(TIME_FMT)},
                },
                'chunks': []
            }
            _write_manifest(outdir, manifest)
            print('[split] 两文件时间不重叠，已 short-circuit，请走 analyze_single_vendor.py')
            return

    raw_chunks = time_bucket_split(l_good, w_good, args.window_sec, args.max_rows)

    chunk_records = []
    for i, (l_part, w_part, start_dt, end_dt, hard_split) in enumerate(raw_chunks, start=1):
        cid = f'c{i:04d}'
        cdir = outdir / cid
        cdir.mkdir(exist_ok=True)
        l_name = derive_chunk_filename(args.lvmeng_csv, start_dt, end_dt)
        w_name = derive_chunk_filename(args.weibu_csv, start_dt, end_dt)
        l_path = cdir / l_name
        w_path = cdir / w_name
        write_df(l_part, l_path, template_cols=lvmeng_cols)
        write_df(w_part, w_path, template_cols=weibu_cols)

        events = []
        if EVENT_NAME_COL in l_part.columns and not l_part.empty:
            events += l_part[EVENT_NAME_COL].astype(str).tolist()
        if EVENT_NAME_COL in w_part.columns and not w_part.empty:
            events += w_part[EVENT_NAME_COL].astype(str).tolist()

        chunk_records.append({
            'chunk_id': cid,
            'window': [start_dt.strftime(TIME_FMT), end_dt.strftime(TIME_FMT)],
            'window_sec': int((end_dt - start_dt).total_seconds()),
            'lvmeng_chunk': str(l_path),
            'weibu_chunk': str(w_path),
            'lvmeng_rows': int(len(l_part)),
            'weibu_rows': int(len(w_part)),
            'hard_split': bool(hard_split),
            'likely_cookbook': likely_cookbook(events),
            'neighbor_left': None,
            'neighbor_right': None,
        })

    for i in range(len(chunk_records)):
        if i > 0:
            chunk_records[i]['neighbor_left'] = chunk_records[i - 1]['chunk_id']
        if i < len(chunk_records) - 1:
            chunk_records[i]['neighbor_right'] = chunk_records[i + 1]['chunk_id']

    all_dt = []
    if not l_good.empty:
        all_dt.extend([l_good['__dt__'].min(), l_good['__dt__'].max()])
    if not w_good.empty:
        all_dt.extend([w_good['__dt__'].min(), w_good['__dt__'].max()])

    manifest = {
        **base_manifest,
        'should_split': True,
        'time_domain': {
            'start': min(all_dt).strftime(TIME_FMT),
            'end': max(all_dt).strftime(TIME_FMT),
        },
        'chunks': chunk_records,
    }
    _write_manifest(outdir, manifest)

    hard_n = sum(1 for c in chunk_records if c['hard_split'])
    print(f'[split] 完成：{len(chunk_records)} chunks，hard_split={hard_n}')
    print(f'[split] manifest: {outdir / "manifest_pair.json"}')


def _write_manifest(outdir, manifest):
    (outdir / 'manifest_pair.json').write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding='utf-8')


if __name__ == '__main__':
    main()
