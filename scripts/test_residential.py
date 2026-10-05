#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""家宽甄选增强单元自测 (基于 ip-api.com 真实在线情报, 非.mock 数据)

背景 (CHANGES.md #13): 旧逻辑里"家宽总量偏少"的主因之一是**召回不足** ——
白名单覆盖不到的真实民用运营商会被判成 unknown, 最终白白丢进非家宽区。

本自测用真实 IP + 真实 ip-api 响应用证:
  ① 严格家宽 / 移动家宽 / CDN / 机房 的原有判定 100% 不回归
  ② 原先判 unknown 的真家宽现在能进家宽区
  ③ 伪装家宽 (收购家宽段的云边网络, proxy=true) 依然被硬否决
"""
import os, sys, json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import main_v2 as mv

FAIL, SKIP = [], []
IP_API_URL = ("http://ip-api.com/batch?fields=status,countryCode,isp,org,as,"
              "asname,reverse,mobile,proxy,hosting,query")


def live_lookup(ips):
    """真查 ip-api; 网络不可用时返回 None (跳过而非伪造)"""
    import requests
    s = requests.Session()
    s.trust_env = True
    try:
        r = s.post(IP_API_URL, json=[{"query": i} for i in ips], timeout=25)
        if r.status_code != 200:
            return None
        return {rec.get("query"): rec for rec in r.json()}
    except Exception as e:
        print(f"  [skip] ip-api 不可达: {str(e)[:60]}")
        return None


def classify(ip, rec):
    return mv.classify_network_type(ip, rec.get("countryCode"), rec.get("as"),
                                    rec.get("asname"), rec or None)


# ══════════ 1) 离线用例: 保证原有判定零回归 ══════════
print("=" * 72)
print("阶段1: 原有判定零回归 (离线, 用老的一组样本)")
print("=" * 72)
LEGACY = [
    ("104.16.1.1", 13335, "cloudflare", "cdn"),
    ("172.67.10.1", 13335, "Cloudflare, Inc.", "cdn"),
    ("8.8.8.8", 15169, "Google LLC", "cdn"),
    ("23.94.10.1", 36352, "ColoCrossing", "datacenter"),
    ("211.72.35.1", 3462, "Chunghwa Telecom", "residential"),
    ("61.220.50.1", 3462, "CHT", "residential"),
    ("219.85.10.1", 17676, "Softbank BB", "residential"),
    ("81.19.66.1", 6679, "Skynet", "unknown"),
]
for ip, asn, org, expect in LEGACY:
    got, conf = mv.classify_network_type(ip, None, asn, org, None)
    ok = got == expect
    if not ok:
        FAIL.append(f"[LEGACY] {ip} ({org}) 期望 {expect} 实得 {got}")
    print(f"  {'✅' if ok else '❌'} {ip:16} ({org:22}) → {got} conf={conf}")

# ══════════ 2) 在线用例: 真实出口 IP 情报下的判定 ══════════
print()
print("=" * 72)
print("阶段2: 真实 ip-api 情报下的家宽甄选")
print("=" * 72)
# (ip, 期望类型, 说明)
CASES = [
    ("88.198.10.1",  "datacenter", "Hetzner 机房 — hosting=true 硬否决"),
    ("104.16.1.1",   "cdn",        "Cloudflare 任播段"),
    ("8.8.8.8",      "cdn",        "Google 公共 DNS — CDN 段硬判据优先于 proxy 字段"),
    ("24.90.100.1",  "residential", "Charter/Spectrum 美国家宽"),
    ("73.219.20.1",  "residential", "Comcast Cable 美国家宽"),
    ("62.155.10.1",  "residential", "Deutsche Telekom 德国家宽"),
    ("200.100.50.1", "residential", "Vivo/Telefonica 巴西家宽"),
    ("123.201.10.1", "residential", "YOU Broadband 印度有线宽带 (旧: unknown 漏判)"),
    ("211.72.35.1",  "residential", "Hinet 中华电信台湾家宽"),
    ("219.85.10.1",  None,         "So-net 台湾家宽 (旧: unknown 漏判)"),
]
info = live_lookup([c[0] for c in CASES])
if info is None:
    SKIP.append("ip-api 不可达, 阶段2 跳过")
    print("  [skip] 无网络, 跳过在线断言")
else:
    for ip, expect, desc in CASES:
        rec = info.get(ip) or {}
        if not rec or rec.get("status") != "success":
            print(f"  ⚠️ {ip:16} {desc} — ip-api 无数据, 跳过")
            continue
        got, conf = classify(ip, rec)
        prev_pretty = f"hosting={rec.get('hosting')} proxy={rec.get('proxy')} mobile={rec.get('mobile')}"
        if expect is None:
            mark = "✅" if got in ("residential", mv.RESIDENTIAL_SOFT) else "⚠️"
            print(f"  {mark} {ip:16} → {got:20} conf={conf:<3} {desc}")
            print(f"       ({prev_pretty}, AS={rec.get('as')})")
        else:
            ok = got == expect
            if not ok:
                FAIL.append(f"[LIVE] {ip} ({desc}) 期望 {expect} 实得 {got}")
            print(f"  {'✅' if ok else '❌'} {ip:16} → {got:20} conf={conf:<3} {desc}")
            print(f"       ({prev_pretty}, AS={rec.get('as')})")

# ══════════ 3) 伪装家宽防线: 必须仍然被否决 ══════════
print()
print("=" * 72)
print("阶段3: 伪装家宽防线 (不得因召回放宽而失守)")
print("=" * 72)
SPOOF = [
    # ip-api 已 giving hosting=false 但 proxy=true = 典型"机房收购家宽段"
    ({"query": "1.2.3.4", "hosting": False, "proxy": True, "mobile": False,
      "as": "AS62610 Zenlayer", "asname": "ZENLAYER-AS", "org": "Zenlayer"}, "datacenter"),
    # hosting 字段缺失 (None) → 不得走无罪推定; 落回 ASN 黑名单判 datacenter
    ({"query": "5.6.7.8", "mobile": False, "proxy": False,
      "as": "AS13335 Cloudflare", "asname": "CLOUDFLARENET"}, "datacenter"),
    # hosting 字段缺失且 ASN/org/reverse 全无线索 → 必须回到 unknown, 绝不能推定家宽
    ({"query": "77.88.99.100", "mobile": False, "proxy": False,
      "as": "AS64501 NOINFO", "asname": "Zzz"}, "unknown"),
    # rDNS 带 dsl 但同时 hosting=true →机房伪装
    ({"query": "9.9.9.10", "hosting": True, "mobile": False, "proxy": False,
      "reverse": "dsl-099-010.speakeasy.net", "asname": "UNKNOWN"}, "datacenter"),
    # 移动网络: 仍判 mobile
    ({"query": "11.12.13.14", "hosting": False, "proxy": False, "mobile": True,
      "asname": "VODAFONE-DE"}, "mobile"),
    # AS62610 Zenlayer rDNS 带 dsl.speakeasy.net 但 proxy=true → 硬否决 (旧版 #11 复发的防线)
    ({"query": "23.129.64.100", "hosting": False, "proxy": True, "mobile": False,
      "reverse": "dsl-129-064.speakeasy.net", "as": "AS62610 Zenlayer"}, "datacenter"),
    # ★ 2026-10-05 新增: 借 "telecom" 名 / "Private Customer" 名混入严格家宽区的
    #   转售商与小托管商 —— ASN 黑名单硬否决 (审计单实证)
    ({"query": "179.254.94.59", "countryCode": "US", "hosting": False, "proxy": False,
      "mobile": False, "as": "AS209604 2E TELEKOMUNIKASYON LTD STI",
      "asname": "2E TELEKOMUNIKASYON LTD STI", "org": "2E Telekomunikasyon LTD. STI",
      "isp": "2E TELEKOMUNIKASYON LTD STI"}, "datacenter"),  # 土耳其公司/US IP
    ({"query": "177.3.89.196", "countryCode": "JP", "hosting": False, "proxy": False,
      "mobile": False, "as": "AS137535 JT TELECOM INTERNATIONAL PTE.LTD.",
      "asname": "JT TELECOM INTERNATIONAL PTE.LTD.",
      "isp": "Hong Kong Communications International CO"}, "datacenter"),  # 新加坡注册/JP IP
    ({"query": "194.38.11.86", "countryCode": "RU", "hosting": False, "proxy": False,
      "mobile": False, "as": "AS199669 Okay-Telecom Ltd.",
      "asname": "Okay-Telecom Ltd.", "org": "Park-Web LLC",
      "isp": "Okay-Telecom Ltd."}, "datacenter"),  # ORG 是托管商 Park-Web
    ({"query": "140.150.227.51", "countryCode": "US", "hosting": False, "proxy": False,
      "mobile": False, "as": "AS29802 HIVELOCITY, Inc.",
      "asname": "HIVELOCITY, Inc.", "isp": "Private Customer"}, "datacenter"),  # VPS 冒充
    # ★ 2026-10-05 新增: 国家-ASN 错位否决 —— 公司后缀暴露注册国与 IP 地理国矛盾
    ({"query": "90.200.100.60", "countryCode": "US", "hosting": False, "proxy": False,
      "mobile": False, "as": "AS199997 FAKETEL", "asname": "FAKETEL",
      "org": "Faketel Telekomunikasyon Ltd. Sti."}, "datacenter"),  # 土耳其后缀/US IP
    ({"query": "90.200.100.61", "countryCode": "DE", "hosting": False, "proxy": False,
      "mobile": False, "as": "AS199996 FAKETEL2", "asname": "FAKETEL2",
      "org": "Faketel GmbH"}, "unknown"),  # 德国后缀/德国 IP 不错位, 但无线索 → unknown
]
# ★ 召回增强的自证: ip-api 明确 hosting=false + proxy=false, 但白名单/关键词都无线索
#   —— 这正是旧逻辑丢失真家宽的重灾区。
#   2026-09-29 精确率修正: "无罪推定"本身不是家宽证据 (ip-api 对未分类 ASN 的
#   hosting=false 只是"没标过", 不是"确认不是机房")。soft 档现在要求至少一个
#   弱阳性信号 (动态类 rDNS / 电信类 org), 零信号 → unknown (宁缺毋滥)。
RECALL = [
    # 零信号 (无 rDNS、无运营商词) → unknown, 不再无条件 soft
    # (旧期望 RESIDENTIAL_SOFT; 用户实测反馈 soft 档混入大量小机房, 精确率优先)
    ({"query": "90.200.100.50", "hosting": False, "proxy": False, "mobile": False,
      "as": "AS199999 TINYISPAB", "asname": "TINYISP-AS", "org": "Tiny ISP Ltd"}, "unknown"),
    # 同一组织 + 动态类 rDNS 弱阳性 → 疑似家宽 (soft 档仍有路可走, 只是要证据)
    # (dhcp 不在主关键词表, 走 6d 弱阳性路径)
    ({"query": "90.200.100.53", "hosting": False, "proxy": False, "mobile": False,
      "as": "AS199999 TINYISPAB", "asname": "TINYISP-AS", "org": "Tiny ISP Ltd",
      "reverse": "dhcp-100-53.tinyisp.example.net"}, mv.RESIDENTIAL_SOFT),
    # 组织名含 telecom → 疑似家宽 (soft)
    # ★ 2026-10-05 收紧: 光凭名字里的 telecom 不再给严格家宽
    #   (2E Telekomunikasyon / JT TELECOM / Okay-Telecom 实测借此混入严格区)。
    #   真民用运营商走 ASN 白名单/强关键词召回; 这里最多 soft, 高纯净优先。
    ({"query": "90.200.100.51", "hosting": False, "proxy": False, "mobile": False,
      "as": "AS199998 TINYISPTEL", "asname": "TINYISP-AS", "org": "Tiny Telecom Ltd"},
     mv.RESIDENTIAL_SOFT),
    # rDNS 强家宽指纹 → 严格家宽
    ({"query": "90.200.100.52", "hosting": False, "proxy": False, "mobile": False,
      "as": "AS199997 X", "asname": "X", "org": "X",
      "reverse": "pppoe-200-100-52.dynamic.example.net"}, "residential"),
]
for rec, expect in SPOOF:
    got, conf = mv.classify_network_type(rec["query"], None, None, None, rec)
    ok = got == expect
    if not ok:
        FAIL.append(f"[SPOOF] {rec['query']} 期望 {expect} 实得 {got}")
    print(f"  {'✅' if ok else '❌'} {rec['query']:16} → {got:12} conf={conf:<3} "
          f"(hosting={rec.get('hosting')} proxy={rec.get('proxy')} mobile={rec.get('mobile')})")

print()
print("  -- 召回增强自证 (旧逻辑这些会全部判 unknown 而丢失) --")
for rec, expect in RECALL:
    got, conf = mv.classify_network_type(rec["query"], None, None, None, rec)
    ok = got == expect
    if not ok:
        FAIL.append(f"[RECALL] {rec['query']} 期望 {expect} 实得 {got}")
    print(f"  {'✅' if ok else '❌'} {rec['query']:16} → {got:20} conf={conf:<3} {rec.get('org') or rec.get('reverse')}")

# ══════════ 4) 家宽候选聚合 & 命名 ══════════
print()
print("=" * 72)
print("阶段4: 家宽候选人选逻辑 / 命名导出")
print("=" * 72)
for t, expect in (("residential", True), ("mobile", True),
                  (mv.RESIDENTIAL_SOFT, True), ("datacenter", False),
                  ("cdn", False), ("unknown", False)):
    got = mv._is_res_like(t)
    ok = got == expect
    if not ok:
        FAIL.append(f"[CAND] {t} 期望 {expect} 实得 {got}")
    print(f"  {'✅' if ok else '❌'} _is_res_like({t:18}) → {got}")

names = {
    "residential":      " (家宽)",
    "mobile":           " (移动家宽)",
    mv.RESIDENTIAL_SOFT: " (疑似家宽)",
}
for t, expect_tag in names.items():
    n = mv.make_node_name({"country": "TW", "net_type": t, "confidence": 70}, 1, force_residential=True)
    ok = expect_tag in n
    if not ok:
        FAIL.append(f"[NAME] {t} 名称缺 [{expect_tag}] → {n}")
    print(f"  {'✅' if ok else '❌'} {t:18} → {n}")

# ══════════ 5) 订阅源可达性 ══════════
print()
print("=" * 72)
print("阶段5: 订阅源清单健康检查")
print("=" * 72)
print(f"  基础源 {len(mv.BASE_SOURCE_URLS)} + 新增源 {len(mv.EXTRA_SOURCE_URLS)} = {len(mv.SOURCE_URLS)}")
dupes = set(mv.BASE_SOURCE_URLS) & set(mv.EXTRA_SOURCE_URLS)
if dupes:
    FAIL.append(f"[SRC] 基础源与新增源重复: {len(dupes)} 条")
print(f"  {'✅' if not dupes else '❌'} 新旧源无重复")
if len(mv.BASE_SOURCE_URLS) != 14:
    FAIL.append(f"[SRC] 基础源数量被改动: {len(mv.BASE_SOURCE_URLS)} != 14")
print(f"  {'✅' if len(mv.BASE_SOURCE_URLS) == 14 else '❌'} 原 14 源完整保留")

print()
print("=" * 72)
if FAIL:
    print(f"共 {len(FAIL)} 项失败:")
    for f in FAIL:
        print(f"  - {f}")
    sys.exit(1)
print("全部测试通过 ✅" + (f" (跳过: {'; '.join(SKIP)})" if SKIP else ""))
