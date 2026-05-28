#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
聚合多个分片 compare_result.json，重算全局统计、跨片去重、识别 boundary_seam。

输出的 final_compare_result.json 字段同构于 compare_alerts.py 的 compare_result.json，
generate_report.py 可零改动直接消费；额外追加：
    - aggregation_meta: 分片数、hard_split 数、冲突合并数、unparsed 行数、failed chunks
    - boundary_seam_candidates: 裂痕候选（主代理 LLM 二次研判用）
    - boundary_seam_reassessment: 占位（主代理回填）

使用：
    python aggregate_chunk_results.py --manifest <manifest_pair.json> \
        --chunks-dir <chunks/> -o <final_compare_result.json>
"""

import argparse
import json
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path


TIME_FMT = '%Y-%m-%d %H:%M:%S'

# 置信度排序：用于去重时保留更可信的判定
CONF_RANK = {'高': 3, '中': 2, '低': 1, '': 0, None: 0}


def conf_rank(conf):
    return CONF_RANK.get(conf, 0)


def parse_time_safe(s):
    try:
        return datetime.strptime(s, TIME_FMT)
    except Exception:
        return None


def alert_key(alert):
    """跨片去重主键：四元组 + 事件名 + 秒级生成时间。"""
    ft = tuple(alert.get('four_tuple', ()))
    if isinstance(alert.get('four_tuple'), list):
        ft = tuple(alert['four_tuple'])
    return (ft, alert.get('event_name', ''), alert.get('generate_time', ''))


def resolve_fp_conflict(records):
    """
    对同 key 在多片的判定做裁决，优先级从高到低：
    1. 任一片标 requires_manual_review=True → manual_review
    2. 任一片判 is_false_positive=False 且 confidence='高' → TP
    3. 全部 FP 且置信度 ∈ {高, 中} → FP（沿用置信度最高那条 fp_analysis）
    4. 其他冲突 → manual_review，理由拼接

    records: [(chunk_id, alert_dict)]
    返回：合并后的 alert（保留代表性字段 + 重写 false_positive_analysis）和冲突标记 bool
    """
    if len(records) == 1:
        return records[0][1], False

    fp_analyses = [(cid, r.get('false_positive_analysis') or {}) for cid, r in records]
    is_fp_values = [fa.get('is_false_positive') for _, fa in fp_analyses]
    mr_values = [fa.get('requires_manual_review') for _, fa in fp_analyses]

    base = max(records, key=lambda x: conf_rank((x[1].get('false_positive_analysis') or {}).get('confidence')))
    merged = dict(base[1])

    if any(mr is True for mr in mr_values):
        merged['false_positive_analysis'] = dict(merged.get('false_positive_analysis') or {})
        merged['false_positive_analysis']['requires_manual_review'] = True
        merged['false_positive_analysis']['is_false_positive'] = None
        merged['false_positive_analysis']['false_positive_reason'] = '跨分片合并：至少一片标 manual_review，整体升级'
        return merged, len(set(is_fp_values)) > 1

    if any(fa.get('is_false_positive') is False and fa.get('confidence') == '高'
           for _, fa in fp_analyses):
        winner = next((cid, fa) for cid, fa in fp_analyses
                      if fa.get('is_false_positive') is False and fa.get('confidence') == '高')
        merged['false_positive_analysis'] = dict(winner[1])
        return merged, len(set(is_fp_values)) > 1

    fp_with_good_conf = [fa for _, fa in fp_analyses
                         if fa.get('is_false_positive') is True
                         and fa.get('confidence') in ('高', '中')]
    if len(fp_with_good_conf) == len(fp_analyses) and fp_with_good_conf:
        best = max(fp_with_good_conf, key=lambda fa: conf_rank(fa.get('confidence')))
        merged['false_positive_analysis'] = dict(best)
        return merged, False

    conflict_summary = '；'.join(
        f"片{cid}判FP={fa.get('is_false_positive')}/置信度={fa.get('confidence')}"
        for cid, fa in fp_analyses
    )
    merged['false_positive_analysis'] = {
        'confidence': '低',
        'is_false_positive': None,
        'requires_manual_review': True,
        'false_positive_reason': f'跨分片结论冲突：{conflict_summary}',
        'bypass_detection': {},
        'evidence': [],
    }
    return merged, True


def load_chunk_results(manifest, chunks_dir):
    """读各分片 compare_result.json；失败片记录在 failed_chunks。"""
    results = []
    failed = []
    for c in manifest.get('chunks', []):
        cdir = chunks_dir / c['chunk_id']
        result_path = cdir / 'compare_result.json'
        if not result_path.exists():
            failed.append({'chunk_id': c['chunk_id'], 'reason': 'compare_result.json 缺失'})
            continue
        try:
            with open(result_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception as e:
            failed.append({'chunk_id': c['chunk_id'], 'reason': f'解析失败: {e}'})
            continue
        results.append((c, data))
    return results, failed


def aggregate(results, manifest, failed_chunks):
    """合并所有 chunk 的 compare_result.json，重算统计。"""
    vendor1 = vendor2 = None
    lvmeng_total = weibu_total = 0
    lvmeng_only_buckets = defaultdict(list)
    weibu_only_buckets = defaultdict(list)
    cross_buckets = defaultdict(lambda: {'lvmeng_event_names': set(), 'weibu_event_names': set(),
                                          'chunk_ids': set()})
    detailed_buckets = defaultdict(lambda: {'lvmeng_alerts': [], 'weibu_alerts': [],
                                             'chunk_ids': set()})

    for chunk_info, data in results:
        cid = chunk_info['chunk_id']
        if vendor1 is None:
            vendor1 = data.get('vendor1', '绿盟')
            vendor2 = data.get('vendor2', '微步')
        s = data.get('summary', {})
        lvmeng_total += s.get('lvmeng_total_alerts', 0)
        weibu_total += s.get('weibu_total_alerts', 0)

        for alert in data.get('lvmeng_only_alerts', []):
            lvmeng_only_buckets[alert_key(alert)].append((cid, alert))
        for alert in data.get('weibu_only_alerts', []):
            weibu_only_buckets[alert_key(alert)].append((cid, alert))
        for cross in data.get('cross_alerts', []):
            ft = tuple(cross.get('four_tuple', ()))
            entry = cross_buckets[ft]
            entry['lvmeng_event_names'].update(cross.get('lvmeng_event_names', []))
            entry['weibu_event_names'].update(cross.get('weibu_event_names', []))
            entry['chunk_ids'].add(cid)
        for det in data.get('detailed_comparison', []):
            ft = tuple(det.get('four_tuple', ()))
            entry = detailed_buckets[ft]
            entry['lvmeng_alerts'].extend(det.get('lvmeng_alerts', []))
            entry['weibu_alerts'].extend(det.get('weibu_alerts', []))
            entry['chunk_ids'].add(cid)

    audit_records = []
    lvmeng_only_dedup = []
    for key, records in lvmeng_only_buckets.items():
        first = dict(records[0][1])
        if len(records) > 1:
            first['_seen_in_chunks'] = sorted({cid for cid, _ in records})
        lvmeng_only_dedup.append(first)

    weibu_only_dedup = []
    conflict_count = 0
    for key, records in weibu_only_buckets.items():
        merged, had_conflict = resolve_fp_conflict(records)
        if len(records) > 1:
            merged = dict(merged)
            merged['_seen_in_chunks'] = sorted({cid for cid, _ in records})
        if had_conflict:
            conflict_count += 1
            audit_records.append({
                'key': {'four_tuple': list(key[0]), 'event_name': key[1], 'generate_time': key[2]},
                'chunk_decisions': [
                    {'chunk_id': cid,
                     'is_false_positive': (a.get('false_positive_analysis') or {}).get('is_false_positive'),
                     'confidence': (a.get('false_positive_analysis') or {}).get('confidence'),
                     'requires_manual_review': (a.get('false_positive_analysis') or {}).get('requires_manual_review')}
                    for cid, a in records
                ],
                'final_decision': {
                    'is_false_positive': (merged.get('false_positive_analysis') or {}).get('is_false_positive'),
                    'confidence': (merged.get('false_positive_analysis') or {}).get('confidence'),
                    'requires_manual_review': (merged.get('false_positive_analysis') or {}).get('requires_manual_review'),
                }
            })
        weibu_only_dedup.append(merged)

    # 重算 four_tuple 全局集合
    lvmeng_only_tuples = {tuple(a.get('four_tuple', ())) for a in lvmeng_only_dedup}
    weibu_only_tuples = {tuple(a.get('four_tuple', ())) for a in weibu_only_dedup}
    common_tuples = set(cross_buckets.keys()) | set(detailed_buckets.keys())
    # 真实的 only：要去掉那些其实在另一边有 cross 的（罕见，但分片间可能造成）
    lvmeng_only_tuples -= common_tuples
    weibu_only_tuples -= common_tuples

    # 重算微步误报统计（去重后）
    weibu_fp_stats = {'total': 0, 'false_positive': 0, 'true_positive': 0, 'manual_review': 0}
    for alert in weibu_only_dedup:
        device_source = alert.get('device_source', '')
        if '微步' not in device_source:
            continue
        fa = alert.get('false_positive_analysis') or {}
        weibu_fp_stats['total'] += 1
        if fa.get('is_false_positive') is True:
            weibu_fp_stats['false_positive'] += 1
        elif fa.get('is_false_positive') is False:
            weibu_fp_stats['true_positive'] += 1
        elif fa.get('requires_manual_review'):
            weibu_fp_stats['manual_review'] += 1

    cross_alerts = []
    cross_alert_count = 0
    for ft, entry in cross_buckets.items():
        cross_alerts.append({
            'four_tuple': list(ft),
            'lvmeng_event_names': sorted(entry['lvmeng_event_names']),
            'weibu_event_names': sorted(entry['weibu_event_names']),
            'seen_in_chunks': sorted(entry['chunk_ids']),
        })
        cross_alert_count += max(len(entry['lvmeng_event_names']), len(entry['weibu_event_names']), 1)

    detailed = []
    for ft, entry in detailed_buckets.items():
        det = {
            'four_tuple': list(ft),
            'lvmeng_alerts': entry['lvmeng_alerts'],
            'weibu_alerts': entry['weibu_alerts'],
            'consistency': {
                'event_name_match': False,
                'event_type_match': False,
                'attack_result_match': False,
            },
            'seen_in_chunks': sorted(entry['chunk_ids']),
        }
        if entry['lvmeng_alerts'] and entry['weibu_alerts']:
            l0 = entry['lvmeng_alerts'][0]
            w0 = entry['weibu_alerts'][0]
            det['consistency']['event_name_match'] = l0.get('event_name') == w0.get('event_name')
            det['consistency']['event_type_match'] = l0.get('event_type') == w0.get('event_type')
            det['consistency']['attack_result_match'] = l0.get('threat_level') == w0.get('threat_level')
        detailed.append(det)

    result = {
        'vendor1': vendor1 or '绿盟',
        'vendor2': vendor2 or '微步',
        'summary': {
            'lvmeng_total_alerts': lvmeng_total,
            'weibu_total_alerts': weibu_total,
            'lvmeng_unique_four_tuples': len(lvmeng_only_tuples),
            'weibu_unique_four_tuples': len(weibu_only_tuples),
            'common_four_tuples': len(common_tuples),
            'lvmeng_only_alert_count': len(lvmeng_only_dedup),
            'weibu_only_alert_count': sum(
                1 for a in weibu_only_dedup if '微步' in a.get('device_source', '')
            ),
            'cross_alert_count': cross_alert_count,
        },
        'lvmeng_only_alerts': lvmeng_only_dedup,
        'weibu_only_alerts': weibu_only_dedup,
        'cross_alerts': cross_alerts,
        'detailed_comparison': detailed,
        'weibu_fp_stats': weibu_fp_stats,
    }
    if weibu_fp_stats['total'] > 0:
        result['weibu_false_positive_analysis'] = {
            'total_alerts': weibu_fp_stats['total'],
            'false_positive_count': weibu_fp_stats['false_positive'],
            'true_positive_count': weibu_fp_stats['true_positive'],
            'manual_review_count': weibu_fp_stats['manual_review'],
            'false_positive_rate': round(
                weibu_fp_stats['false_positive'] / weibu_fp_stats['total'] * 100, 2
            ),
        }

    aggregation_meta = {
        'chunk_count': len(manifest.get('chunks', [])),
        'success_chunk_count': len(results),
        'failed_chunks': failed_chunks,
        'hard_split_chunks': [c['chunk_id'] for c in manifest.get('chunks', []) if c.get('hard_split')],
        'cross_chunk_conflicts': conflict_count,
        'unparsed_rows': manifest.get('unparsed_rows', {}),
        'corrupt_rows': manifest.get('corrupt_rows', {}),
        'cross_alerts_dedup_to_chunks_map_size': len(cross_alerts),
    }
    result['aggregation_meta'] = aggregation_meta

    seam_candidates, campaign_groups = identify_boundary_seams(weibu_only_dedup, manifest)
    result['boundary_seam_candidates'] = seam_candidates
    result['boundary_seam_reassessment'] = []
    result['campaign_groups'] = campaign_groups

    return result, audit_records


def identify_boundary_seams(weibu_alerts, manifest):
    """
    识别裂痕候选：
    - 当前判 FP 且 confidence ∈ {中, 低}
    - 生成时间距分片任一端 ≤ window_sec * 0.1（缓冲带，默认 30 秒）
    - 相邻分片有同源 IP 告警，间隔 ≤ 60 秒

    返回 (candidates, campaign_groups)
    campaign_groups: 同源 IP 横跨 ≥ 3 个 chunk 的告警序列（主代理可重判）
    """
    chunks = manifest.get('chunks', [])
    window_sec = manifest.get('window_sec', 300)
    buffer_sec = max(int(window_sec * 0.1), 10)

    chunk_index = {c['chunk_id']: c for c in chunks}
    chunk_windows = {}
    for c in chunks:
        try:
            ws = datetime.strptime(c['window'][0], TIME_FMT)
            we = datetime.strptime(c['window'][1], TIME_FMT)
            chunk_windows[c['chunk_id']] = (ws, we)
        except Exception:
            continue

    by_source_ip = defaultdict(list)
    for a in weibu_alerts:
        ft = a.get('four_tuple') or []
        if not ft:
            continue
        src_ip = ft[0] if len(ft) > 0 else None
        dt = parse_time_safe(a.get('generate_time', ''))
        if not src_ip or dt is None:
            continue
        chunks_seen = a.get('_seen_in_chunks') or []
        by_source_ip[src_ip].append({'alert': a, 'dt': dt, 'chunks_seen': chunks_seen})

    candidates = []
    for a in weibu_alerts:
        fa = a.get('false_positive_analysis') or {}
        if fa.get('is_false_positive') is not True:
            continue
        if fa.get('confidence') not in ('中', '低'):
            continue
        ft = a.get('four_tuple') or []
        if not ft:
            continue
        src_ip = ft[0] if len(ft) > 0 else None
        dt = parse_time_safe(a.get('generate_time', ''))
        if dt is None or src_ip is None:
            continue
        own_chunks = a.get('_seen_in_chunks') or []
        if not own_chunks:
            own_chunks = [_locate_chunk(dt, chunk_windows)]
            own_chunks = [c for c in own_chunks if c]

        near_boundary = False
        related_chunks = set()
        for cid in own_chunks:
            ws_we = chunk_windows.get(cid)
            if not ws_we:
                continue
            ws, we = ws_we
            if (dt - ws).total_seconds() <= buffer_sec:
                near_boundary = True
                left = chunk_index.get(cid, {}).get('neighbor_left')
                if left:
                    related_chunks.add(left)
            if (we - dt).total_seconds() <= buffer_sec:
                near_boundary = True
                right = chunk_index.get(cid, {}).get('neighbor_right')
                if right:
                    related_chunks.add(right)
        if not near_boundary:
            continue

        neighbor_snapshots = []
        for peer in by_source_ip.get(src_ip, []):
            if peer['alert'] is a:
                continue
            peer_chunks = set(peer['chunks_seen']) or {_locate_chunk(peer['dt'], chunk_windows)}
            if not (peer_chunks & related_chunks):
                continue
            if abs((peer['dt'] - dt).total_seconds()) > 60:
                continue
            neighbor_snapshots.append({
                'chunk_ids': sorted(c for c in peer_chunks if c),
                'event_name': peer['alert'].get('event_name'),
                'generate_time': peer['alert'].get('generate_time'),
                'is_false_positive': (peer['alert'].get('false_positive_analysis') or {}).get('is_false_positive'),
                'confidence': (peer['alert'].get('false_positive_analysis') or {}).get('confidence'),
            })

        if not neighbor_snapshots:
            continue

        candidates.append({
            'four_tuple': ft,
            'event_name': a.get('event_name'),
            'generate_time': a.get('generate_time'),
            'current_decision': {
                'is_false_positive': fa.get('is_false_positive'),
                'confidence': fa.get('confidence'),
                'reason': fa.get('false_positive_reason'),
            },
            'own_chunks': own_chunks,
            'neighbor_chunks': sorted(related_chunks),
            'neighbor_alerts': neighbor_snapshots,
            'source_ip': src_ip,
        })

    campaign_groups = []
    for src_ip, peers in by_source_ip.items():
        chunk_set = set()
        for p in peers:
            chunk_set.update(p['chunks_seen'] or [])
        if len(chunk_set) >= 3:
            campaign_groups.append({
                'source_ip': src_ip,
                'chunk_count': len(chunk_set),
                'chunk_ids': sorted(c for c in chunk_set if c),
                'alert_count': len(peers),
                'event_names_sample': sorted({p['alert'].get('event_name', '') for p in peers})[:10],
            })

    return candidates, campaign_groups


def _locate_chunk(dt, chunk_windows):
    """根据 datetime 找到所属 chunk_id（首个命中）。"""
    for cid, (ws, we) in chunk_windows.items():
        if ws <= dt < we:
            return cid
    return None


def main():
    parser = argparse.ArgumentParser(description='聚合分片 compare_result.json 为 final_compare_result.json')
    parser.add_argument('--manifest', required=True, help='manifest_pair.json 路径')
    parser.add_argument('--chunks-dir', required=True, help='分片目录（含 c0001/ 等子目录）')
    parser.add_argument('-o', '--output', required=True, help='输出 final_compare_result.json')
    parser.add_argument('--audit-output', default=None,
                        help='冲突审计输出路径（默认与 final 同目录的 aggregation_audit.json）')
    args = parser.parse_args()

    with open(args.manifest, 'r', encoding='utf-8') as f:
        manifest = json.load(f)

    if not manifest.get('should_split', False):
        print(f'[aggregate] manifest.should_split=False (reason={manifest.get("reason")})；'
              f'不应进入聚合，请走 analyze_single_vendor.py')
        sys.exit(2)

    chunks_dir = Path(args.chunks_dir)
    results, failed = load_chunk_results(manifest, chunks_dir)
    print(f'[aggregate] 成功读入 {len(results)} 个 chunk，失败 {len(failed)} 个')

    final, audit = aggregate(results, manifest, failed)

    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(final, f, ensure_ascii=False, indent=2)
    print(f'[aggregate] final 写入: {args.output}')

    audit_path = args.audit_output or str(Path(args.output).with_name('aggregation_audit.json'))
    with open(audit_path, 'w', encoding='utf-8') as f:
        json.dump(audit, f, ensure_ascii=False, indent=2)
    print(f'[aggregate] audit 写入: {audit_path}')

    seam_n = len(final.get('boundary_seam_candidates', []))
    camp_n = len(final.get('campaign_groups', []))
    print(f'[aggregate] boundary_seam_candidates: {seam_n}；campaign_groups: {camp_n}')


if __name__ == '__main__':
    main()
