#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
免费节点自动测活订阅池 v2 — 全协议 · 高精度 · 低误杀
====================================================

架构（三阶段流水线）:
  1. 抓取订阅源 → 解析全部协议 URI 为统一节点对象
     (vless/vmess/trojan/ss/hysteria2/tuic/anytls + reality + 全部传输层)
  2. 真实测活（sing-box v1.14 内核，逐节点 SOCKS 入站 + 节点出站）:
     - 阶段A 端口预检: TCP/QUIC 直连握手, 快速丢弃死端口 (削减 90% 无效工作)
     - 阶段B 真实探测: 多 URL 探测 (gstatic 204 / cloudflare trace) 
       + 经代理取真实出口 IP (api.ip.sb/geoip → 一次拿 country+asn+isp)
       + Cloudflare 限时下载测速 → 断流节点识别 (吞吐量不足)
       + cloudflare trace tls=VERIFIED → MITM/劫持节点识别
  3. 分类与导出:
     - 国家: 出口 IP ip-api.com 批量(45req/min 免费) → MaxMind GeoLite2 兜底
     - 属性: hosting=true/CDN网段/IDC ASN → 机房 | mobile=true → 移动
            | 运营商白名单+rDNS → 家宽
     - 去重: 出口IP+端口 唯一化, 家宽区严格防同IP刷屏
"""

import os
import re
import io
import sys
import json
import time
import uuid
import base64
import shutil
import socket
import zipfile
import tarfile
import platform
import subprocess
import ipaddress
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    import yaml
    import maxminddb
except ImportError as e:
    print(f"[!] 缺少依赖: {e} — 请先 pip install -r requirements.txt")
    sys.exit(1)

# ══════════════════════════════════════════════════════════════════
# 配置
# ══════════════════════════════════════════════════════════════════

# ★ 原版 14 源 (保持不变, 顺序即优先级)
BASE_SOURCE_URLS = [
    "https://wild-cloud-9893.heleimail.workers.dev",
    "https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/by-country/v2ray-base64-TW.txt",
    "https://raw.githubusercontent.com/ShatakVPN/ConfigForge-V2Ray/main/configs/all.txt",
    "https://raw.githubusercontent.com/10ium/HiN-VPN/main/subscription/base64/mix",
    "https://raw.githubusercontent.com/10ium/telegram-configs-collector/main/protocols/hysteria",
    "https://raw.githubusercontent.com/10ium/telegram-configs-collector/main/security/tls",
    "https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/v2ray-base64.txt",
    "https://raw.githubusercontent.com/freefq/free/master/v2",
    "https://open.heleimail.workers.dev/",
    "https://www.ermao.net/sub/v2ray/ermao.net",
    "https://raw.githubusercontent.com/ishalumi/proxy-node-collector/main/output/nodes_base64.txt",
    "https://gist.githubusercontent.com/shuaidaoya/9e5cf2749c0ce79932dd9229d9b4162b/raw/base64.txt",
    "https://raw.githubusercontent.com/PuddinCat/BestClash/main/proxies.yaml",
    "https://raw.githubusercontent.com/twj0/subseek/refs/heads/master/data/sub_github.txt",
]

# ★ 新增源 (2026-09 实测全部 HTTP 200 且有节点产出; 单个源失效不影响整体,
#   fetch_raw_nodes 自行重试与跳过)
#   增设原则 (为家宽目标服务):
#    ① 大容量聚合源      — 提升总池 = 提升家宽命中基数 (家宽是稀缺资源, ~0.5% 命中率)
#    ② 分国家源          — 补齐原版缺失地区 (ID/MY/TR/IN/OM/RO/EE/FI... 家宽占比更高的国家)
#    ③ 分协议源          — 补分包 vn/vmess/trojan/ss (全协议池 vless 占比过高会稀释其它协议)
EXTRA_SOURCE_URLS = [
    # ── ① 大容量聚合 (实测: 5430 / 4029 节点, 与原 14 源重叠极低) ──
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
    # ── ② Au1rxx 全量分国家 (原版只用了 TW; 补齐其余 32 国) ──
    #    亚洲/东南亚/南亚 ── 家用宽带与移动家宽占比最高的地区
    "https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/by-country/v2ray-base64-ID.txt",
    "https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/by-country/v2ray-base64-MY.txt",
    "https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/by-country/v2ray-base64-TR.txt",
    "https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/by-country/v2ray-base64-IN.txt",
    "https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/by-country/v2ray-base64-KR.txt",
    "https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/by-country/v2ray-base64-JP.txt",
    "https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/by-country/v2ray-base64-HK.txt",
    "https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/by-country/v2ray-base64-SG.txt",
    "https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/by-country/v2ray-base64-IL.txt",
    "https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/by-country/v2ray-base64-AE.txt",
    "https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/by-country/v2ray-base64-OM.txt",
    #    欧洲 ── 补齐原版没有的东欧/北欧家宽大国
    "https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/by-country/v2ray-base64-RO.txt",
    "https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/by-country/v2ray-base64-EE.txt",
    "https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/by-country/v2ray-base64-FI.txt",
    "https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/by-country/v2ray-base64-BG.txt",
    "https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/by-country/v2ray-base64-LT.txt",
    "https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/by-country/v2ray-base64-LV.txt",
    "https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/by-country/v2ray-base64-PL.txt",
    "https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/by-country/v2ray-base64-RU.txt",
    "https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/by-country/v2ray-base64-SE.txt",
    "https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/by-country/v2ray-base64-IE.txt",
    "https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/by-country/v2ray-base64-AT.txt",
    "https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/by-country/v2ray-base64-CH.txt",
    "https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/by-country/v2ray-base64-ES.txt",
    "https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/by-country/v2ray-base64-IT.txt",
    "https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/by-country/v2ray-base64-FR.txt",
    "https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/by-country/v2ray-base64-DE.txt",
    "https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/by-country/v2ray-base64-GB.txt",
    "https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/by-country/v2ray-base64-NL.txt",
    "https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/by-country/v2ray-base64-CA.txt",
    "https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/by-country/v2ray-base64-US.txt",
    "https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/by-country/v2ray-base64-AU.txt",
    # ── ③ 分协议分包 ──
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Splitted-By-Protocol/vmess.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Splitted-By-Protocol/trojan.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Splitted-By-Protocol/ss.txt",
    "https://raw.githubusercontent.com/10ium/HiN-VPN/main/subscription/base64/vless",
    "https://raw.githubusercontent.com/10ium/HiN-VPN/main/subscription/base64/vmess",
    "https://raw.githubusercontent.com/ShatakVPN/ConfigForge-V2Ray/main/configs/vless.txt",
    "https://raw.githubusercontent.com/ShatakVPN/ConfigForge-V2Ray/main/configs/vmess.txt",
    "https://raw.githubusercontent.com/ShatakVPN/ConfigForge-V2Ray/main/configs/trojan.txt",
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list_raw.txt",
]

SOURCE_URLS = BASE_SOURCE_URLS + EXTRA_SOURCE_URLS

OUTPUT_DIR = "output"
COUNTRY_DIR = os.path.join(OUTPUT_DIR, "by-country")
RESIDENTIAL_COUNTRY_DIR = os.path.join(OUTPUT_DIR, "residential-by-country")

SINGBOX_VERSION = "v1.14.2"
WORKDIR = os.path.dirname(os.path.abspath(__file__))          # scripts/
BASEDIR = os.path.dirname(WORKDIR)                              # repo root
RUNTIME_DIR = os.path.join(BASEDIR, "runtime")                  # kernels & db
SINGBOX_BIN = os.path.join(RUNTIME_DIR, "sing-box")

# --- 测活阈值 (毫秒/秒) ---
# ★ 分层超时: 首击宽 (12s 容慢节点), 重试窄 (4s 快速放弃死节点)
#   依据 CI 实测: 25 分钟里 ~60% 时间烧在死节点 3×12s 满额重试上
PROBE_TIMEOUT          = 12      # 活性首击超时 (秒) — 容纳慢启动节点
PROBE_RETRY_TIMEOUT    = 4       # 活性重试超时 (秒) — 死节点快速放弃
PORT_KNOCK_TIMEOUT     = 3.5     # 端口预检超时
#   2.5 → 3.5s: 家宽节点跑在家庭上传链路上, 首包延迟天然高于机房,
#   2.5s 会把慢但活着的家宽节点误判成"不可达"硬淘汰掉。
IP_ECHO_TIMEOUT        = 6.0     # 出口 IP 检测超时
SPEED_TEST_BYTES       = 2_500_000   # 2.5MB 下载测速 (2.5MB 足以算准吞吐且 < 70KB/s 判定线不变)
SPEED_TEST_BUDGET      = 5.0         # 测速时间预算 (秒) — 2.5MB@70KB/s=36s 必断流, 5s 预算足够判型
SPEED_MIN_BYTES_PER_S  = 70_000      # 吞吐 < 70KB/s 判定断流/不可用 (标准不变)
IP_ECHO_URLS = [                    # 经代理获取出口 IP (多路冗余)
    "https://api.ip.sb/geoip",                         # JSON: country_code/asn/isp
    "https://ipinfo.io/json",                          # JSON: country/org
    "http://ip-api.com/json/?fields=status,query,countryCode,isp,org,as",  # HTTP free
]
LIVENESS_URLS = [                    # 活性探测 URL (全部要求代理链路完整)
    "https://www.gstatic.com/generate_204",       # 实测 204 OK
    "https://www.google.com/generate_204",
    "http://connectivitycheck.gstatic.com/generate_204",
]
SPEED_TEST_URLS = [               # 测速端点多路 (实测部分节点商屏蔽 speed.cloudflare.com)
    "https://speed.cloudflare.com/__down?bytes=" + str(SPEED_TEST_BYTES),
    "https://cachefly.cachefly.net/10mb.test",
]
TRACE_URL = "https://www.cloudflare.com/cdn-cgi/trace"      # warp=on 检测套壳节点
MAX_WORKERS_TEST    = 48            # 同时 sing-box 实测节点数 (Azure 2C7G 实测 24→48 稳定; sing-box 单实例 < 30MB)
MAX_WORKERS_FETCH   = 8
MAX_WORKERS_CLASSIFY = 32

# --- 规模化护栏 (扩充订阅源后防止 CI 超 50min 超时) ---
# 源从 14 → 58 后待测量上涨约 65%, 必须加两道闸:
#   ① 端口预检硬淘汰: 仅当 FRONT_PROXY 未设置(即 GitHub Actions 海外直连视角)时启用。
#      逻辑: CI 直连跑到不了 TCP 端口 = 端口真死, 无需再烧 sing-box 全流程 (省 60%+ 时间)。
#      本地大陆调试机 (设了 FRONT_PROXY) 保持原行为 —— 只排序不淘汰, 防 GFW 视角误杀。
#   ② MAX_TEST_NODES 硬上限: 万不得已时的兜底, 保证一次 CI 永远跑得完。
# 用法: PREFILTER_DROP_FAILED=0 MAX_TEST_NODES=12000
FRONT_PROXY_ACTIVE  = bool(os.environ.get("FRONT_PROXY", "").strip())
PREFILTER_DROP_FAILED = os.environ.get(
    "PREFILTER_DROP_FAILED", "1" if not FRONT_PROXY_ACTIVE else "0").strip() in ("1", "true")
PREFILTER_RETRY      = 2            # 硬淘汰前重试次数 (防单次抖动误杀)
MAX_TEST_NODES       = int(os.environ.get("MAX_TEST_NODES", "14000"))
#   9000 → 14000: CI #5 实测预检通过 11252 个却只测了 9000, 有 2252 个
#   压根没进测活就被上限截掉 —— 那些没测的节点里就可能有家宽。
#   时间可行性: #5 全程 23.9 分钟 / 预算 50 分钟, 尚有 ~26 分钟余量。

# --- 家宽策略 ---
# 家宽是稀缺资源: 只靠扩大订阅池提升基数不够, 还要提升识别召回率 (详见 classify_network_type)。
#   RES_SOFT_TIER: 开启"疑似家宽"次级判定 (ip-api 明确 hosting=false 且 proxy=false, 且无任何机房证据)。
#      命中节点入家宽专区但打 "(疑似家宽)" 标记 —— 既不稀释严格家宽的可信度, 又显著增加家宽数量与国家覆盖。
#      仍须通过原有四道闸门: ipapi.is 二次否决 / Scamalytics <75 / 欺诈分 <90 / 链式双跳复测。
#   MAX_RES_PER_IP: 同一出口 IP 在家宽专区最多保留几个不同端口的节点 (原为 1, 太浪费: 同一条家宽上常跑多端口)
RES_SOFT_TIER   = os.environ.get("RES_SOFT_TIER", "1").strip() in ("1", "true")
MAX_RES_PER_IP  = int(os.environ.get("MAX_RES_PER_IP", "3"))
RESIDENTIAL_SOFT = "residential_soft"   # 次级类型名

# 上游节点备注里的家宽/住宅宣称词 —— 仅用于提升测活优先级 (绝不作为判定依据, 免费池虚标率极高)
RESIDENTIAL_HINT_RE = re.compile(
    r"(家宽|住宅|民用|宽带|dyn|dynamic|dsl|pppoe|adsl|ftth|家庭|isp|residential|home)",
    re.I)

# ip-api.com 免费批量: 15 req/min, 每 req ≤100 IP (仅 HTTP)
IP_API_BATCH_URL = "http://ip-api.com/batch?fields=status,countryCode,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
IP_API_BATCH_SIZE = 100
IP_API_BATCH_RPS_INTERVAL = 4.2     # 60/15s ≈ 每 4.2s 一批

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"

# ══════════════════════════════════════════════════════════════════
# 出口 IP 情报 (本地离线兜底)
# ══════════════════════════════════════════════════════════════════

# Cloudflare 官方 Anycast 全网段 (命中即 CDN 任播, 绝非家宽)
CLOUDFLARE_IP_NETWORKS = [ipaddress.ip_network(n) for n in (
    "173.245.48.0/20","103.21.244.0/22","103.22.200.0/22","103.31.4.0/22",
    "141.101.64.0/18","108.162.192.0/18","190.93.240.0/20","188.114.96.0/20",
    "197.234.240.0/22","198.41.128.0/17","162.158.0.0/15","104.16.0.0/13",
    "104.24.0.0/14","172.64.0.0/13","131.0.72.0/22",
)]

# Google / Fastly / Akamai 等常见 CDN 与云入口段 (命中即标 CDN/机房)
CDN_IP_NETWORKS_EXTRA = [ipaddress.ip_network(n) for n in (
    # Google
    "8.8.4.0/24","8.8.8.0/24","8.34.208.0/20","8.35.192.0/20","34.64.0.0/10","35.184.0.0/13",
    "35.192.0.0/14","35.196.0.0/15","35.200.0.0/13","35.216.0.0/15","35.220.0.0/14",
    "64.15.112.0/20","64.233.160.0/19","66.102.0.0/20","66.249.64.0/19","72.14.192.0/18",
    "74.125.0.0/16","108.177.0.0/17","142.250.0.0/15","172.217.0.0/16","173.194.0.0/16",
    "209.85.128.0/17","216.58.192.0/19","216.239.32.0/19",
    # Fastly
    "23.235.32.0/20","43.249.72.0/22","103.244.50.0/24","103.245.222.0/23",
    "104.156.80.0/20","140.248.64.0/18","146.75.0.0/16","151.101.0.0/16",
    "157.52.64.0/18","167.82.0.0/17","199.232.0.0/16","204.129.196.0/22",
    # Akamai (核心段)
    "23.32.0.0/13","23.64.0.0/14","23.192.0.0/11","23.197.0.0/16",
    "95.100.0.0/15","104.64.0.0/10","184.24.0.0/13","184.84.0.0/14",
    # Cloudflare Spectrum / 托管入口
    "104.16.0.0/12",
)]

# 已知云/机房 ASN (离线兜底用; 在线 ip-api hosting=true 为主判据)
DATACENTER_ASNS = {
    13335,  # Cloudflare
    16509, 14618,  # AWS
    15169, 396982,  # Google
    8075, 8068,  # Microsoft
    24940,  # Hetzner
    16276,  # OVH
    14061,  # DigitalOcean
    31898, 63949,  # Oracle
    45102,  # Alibaba
    132203,  # Tencent
    20473,  # Choopa/Vultr 早期
    60068,  # Datacamp (CDN77)
    55081,  # Hostinger
    197540,  # Hostinger EU
    51167,  # Contabo
    8560,  # 1&1 / IONOS
    42708,  # IONOS
    201814, 49981,  # Hosthatch/Hostkey 类
    212238, 46652,  # Serverius/OVH 类
    141995, 200019, 136907, 39351, 9009,  # M247/Hosthatch 等
    174, 3356, 1299, 2914, 6939,  # 骨干 (Cogent/Lumen/Arelion/NTT/Hurricane)
    199524, 206096, 49505,  # Selectel/WorldStream
    62240, 49304, 34665, 209242, 219337, 44477,
    200651, 202685, 210644, 205628, 51852, 204544, 397373, 140224,  # 小型 IDC
    49462,  # Parsebian/HydraTransit 类
    # ★ 已移除 45899 (VNPT): 越南最大民用固网运营商, 同时被列在 RESIDENTIAL_ASNS 里,
    #   两条规则冲突导致 DATACENTER 永远先命中 → 越南家宽 100% 漏判。
    #   其云业务 IP 由 ip-api hosting=true 与 ipapi.is 交叉核验兜底, 不会误入家宽区。
    8342,  # Deltacomputers/Evrasia 类
    9009, 47692, 62041, 56630, 57502,  # Serverius/ProXmedia/Clouvider 类
    # ★ 2026-10-05 补 (家宽审计实证: 借 "telecom" 名/ "Private Customer" 名混入
    #   严格家宽区的转售商与小托管商; ip-api 对它们 hosting=false, 只能靠 ASN 硬否决)
    29802,   # HIVELOCITY, Inc. (美国 VPS, ISP 常标 "Private Customer")
    199669,  # Okay-Telecom Ltd. (ORG 常为 Park-Web LLC, 托管转售)
    209604,  # 2E Telekomunikasyon (土耳其公司, IP 地理常标 US —— 跨国转售指纹)
    137535,  # JT TELECOM INTERNATIONAL (新加坡注册, IP 地理常标 JP —— 跨国转售指纹)
}

# 民用宽带 ASN 白名单 (离线兜底; 关键国家主流运营商)
RESIDENTIAL_ASNS = {
    # 台湾
    3462,    # Chunghwa Telecom (中华电信)
    9924, 17709, 4780, 18049,  # 亚太电信/远传/台湾大哥大/凯擘
    9269, 3491,  # 台湾硕网/和宇宽频
    # 香港
    4760, 476, 4515, 9229, 9266, 10103,  # PCCW/HKT/CUHK/HGC/HKBN/HKTBB
    9059, 38861,  # Hong Kong Broadband
    # 日本
    4713, 2516, 17676, 4721, 2497, 9605, 17511, 9318, 2518, 20193,
    # Softbank/NTT Communications/KDDI/IIJ/Sony/Plala/@nifty/JCN
    4766, 3786, 17816, 9357,
    # 韩国
    4713, 9318, 17816, 9357, 4766,  # KT/LG/SK  
    # 美国
    701, 7018, 7922, 20115, 22773, 10796, 20057, 11427, 10507, 6128,
    33363, 21928, 10777, 33660, 33661, 33662, 36466, 53417, 55136,
    20057, 19024, 12271, 11404, 6983, 33554, 7155, 30162, 10790,
    # Comcast (7922/33487/22263...) / Charter (20115/10796/20057) / Cox / AT&T / Verizon
    702, 703, 704, 705, 706, 709, 710, 711, 712, 713, 714, 715,  # legacy Verizon
    2828, 20001, 3549,  # CenturyLink/Level3 (部分为家宽)
    6167, 6162, 7018,  # AT&T
    5056,  # Cox East
    10796,  # Charter
    11351,  # TWC
    6128,  # Atlantis
    # 英国
    2856, 5607, 20650, 13285, 12576, 12725, 19541, 33950, 5413,
    # BT/TalkTalk/Orange/Virgin/Plusnet/Sky/Eclipse
    # 德国
    3320, 3209, 6805, 8888, 9145, 13237, 15366, 20879, 16097, 15594,
    # DT/Vodafone/EWE/netcup/Telefónica
    # 法国
    3215, 12322, 15557, 5410, 21590, 22869, 8228, 8220, 12670,
    # Orange/Free/SFR/Bouygues/LDN/9.tel
    # 荷兰 / 比利时
    33915, 20857, 5418, 6777, 15535, 6830, 8683,
    # KPN/Ziggo/Tele2/Solcon/Proximus/Telenet
    # 加拿大
    577, 6539, 812, 7992, 22995, 23498, 30645, 11260, 5645, 13331,
    # Bell/Rogers/Corus/Cogeco/Videotron/Telus
    # 澳大利亚 / 新西兰
    1221, 4764, 4761, 4747, 4802, 4804, 38293, 9443, 23871, 4771,
    # Telstra/Optus/iinet/AAPT/Exetel/SparkNZ
    # 新加坡 / 马来西亚
    9506, 9224, 10091, 4657, 32308, 55553, 177545, 9534, 17971, 24210,
    # Singtel/StarHub/M1/MyRepublic/TM/Maxis/Time
    # 巴西 / 拉美
    28573, 26599, 28598, 22085, 27699, 11014, 16832, 16397, 26615,
    # Claro/Vivo/Algar/Brisanet
    # 土耳其 / 俄罗斯 / 哈萨克
    9121, 34984, 15924, 31103, 47853, 25513, 12714, 8359, 12389,
    # Türk Telekom/Vodafone TR/MTS/Rostelecom/Kazakhtelecom
    # 意大利 / 西班牙
    3269, 30722, 12874, 12392, 12474, 3352, 12479, 12430,
    # Telecom Italia/Fastweb/Vodafone IT/Telefónica ES
    # 印度 / 越南 / 泰国 / 菲律宾 / 印尼
    55836, 9829, 9498, 17813, 45899, 7552, 9675, 7568, 45773, 45543,
    7590, 17457, 7552, 131293, 9336, 23969, 17816, 24099, 38251,
    # 印尼 Telkomsel/Indosat/Smartfren; 越南 Viettel/FPT; 泰国 AIS/True
}

# ★ 民用运营商 ASN 增补 (2026-09 扩源后针对"更多国家家宽"补齐)
#   来源依据: ip-api.com batch 实测返回 (isp/org/asname 明确为民用固网/移动运营商),
#   例如 AS18207 = YOU Broadband India / AS7713 = Telkom Indonesia / AS5384 = Etisalat。
#   原则: 只加"主体业务是消费者宽带"的运营商; 兼营云业务的运营商 (AS8075/AS16509 等) 一律不加。
RESIDENTIAL_ASNS_EXTRA = {
    # 亚太
    18182,  # Sony Network Taiwan (So-net 台湾, 实测家用固网)
    9467,   # SK Broadband / Hanaro Telecom (韩国)
    7713,   # Telkom Indonesia (印尼第一大固网+移动)
    17974,  # Indosat Ooredoo (印尼)
    24203,  # XL Axiata (印尼)
    4788,   # TMnet / Telekom Malaysia
    9930,   # TIME dotCom (马来西亚)
    3758,   # StarHub (新加坡)
    9299,   # PLDT (菲律宾)
    4775,   # Globe Telecom (菲律宾)
    18403,  # FPT Telecom (越南)
    38726,  # CMC Telecom (越南)
    45758,  # True Internet / 3BB (泰国)
    18207,  # YOU Broadband India (实测: hosting=false, proxy=false)
    24560,  # Airtel Broadband (印度)
    38266,  # Vodafone Idea (印度)
    45820,  # Tata Teleservices (印度)
    17488,  # Hathway (印度有线宽带)
    45595,  # PTCL (巴基斯坦)
    1221,   # Telstra (澳洲固网, 主表已有但从 HINT 复核无误)
    # 中东
    5384,   # Etisalat (阿联酋)
    8966,   # du (阿联酋)
    25019,  # Saudi Telecom Company (沙特)
    39891,  # Mobily (沙特)
    8781,   # Ooredoo Qatar
    8551,   # Bezeq (以色列)
    12849,  # HOT-Net (以色列有线)
    44244,  # MTN Irancell / Irancell (伊朗, 移动家宽)
    58224,  # TIC (伊朗电信基础设施公司)
    12880,  # Information Technology Company (伊朗)
    # 欧洲
    31334,  # Kabel Deutschland / Vodafone DE
    6739,   # Ono / Vodafone España
    1267,   # Wind / Infostrada (意大利)
    1136,   # KPN (荷兰 legacy 段)
    9143,   # Ziggo (荷兰有线)
    5617,   # Orange Polska / TPNET
    12741,  # Netia (波兰)
    8374,   # Play / P4 (波兰移动宽带)
    8708,   # RCS & RDS / Digi Romania
    9050,   # Telekom Romania
    8866,   # Vivacom (保加利亚)
    31042,  # mts / Telekom Srbija (塞尔维亚)
    6799,   # OTEnet (希腊)
    3243,   # MEO / Portugal Telecom
    5466,   # eir (爱尔兰)
    3303,   # Swisscom (瑞士)
    8447,   # A1 Telekom Austria
    1257,   # Tele2 Sweden
    2116,   # Telenor Norge
    3292,   # Telenor Denmark
    16086,  # DNA (芬兰)
    9198,   # Kazakhtelecom (哈萨克斯坦)
    13188,  # Kyivstar (乌克兰)
    35362,  # Volia (乌克兰有线)
    8402,   # Corbina / Vimpelcom (俄罗斯家用宽带)
    3216,   # Vimpelcom / Beeline (俄罗斯)
    # 美洲
    7843,   # Cox Communications (美国)
    30036,  # Mediacom (美国)
    13367,  # Cable One (美国)
    19108,  # Optimum / Suddenlink (Altice 美国)
    852,    # Telus (加拿大)
    5089,   # Virgin Media (英国)
    18881,  # GVT / Vivo (巴西)
    7303,   # Telecom Argentina
    8151,   # Uninet / Telmex (墨西哥)
    13489,  # ETB (哥伦比亚)
    # 非洲
    37457,  # Telkom SA (南非)
    8452,   # TE Data (埃及)
    29465,  # MTN Nigeria
    37282,  # Airtel Nigeria
}
RESIDENTIAL_ASNS |= RESIDENTIAL_ASNS_EXTRA

# rDNS / ISP 名称关键词 (大小写不敏感; 离线兜底)
IDC_NAME_PATTERNS = [
    "hosting", "hoster", "datacenter", "data center", "cloud", "server",
    "vps", "dedicated", "colo", "colocation", "compute", "storage",
    "amazon", "aws", "google cloud", "microsoft", "azure", "oracle",
    "digitalocean", "linode", "vultr", "choopa", "hetzner", "ovh",
    "contabo", "m247", "leaseweb", "online s.a.s", "scaleway",
    "alibaba", "tencent", "huawei cloud", "ucloud", "jdcloud", "ksyun",
    "fastly", "cloudflare", "akamai", "cdn", "anycast", "edge network",
    "hostkey", "selectel", "aeza", "justhost", "idnica", "hostinger",
    "ionos", "1&1", "godaddy", "namecheap", "sucuri", "ispxk",
    "zenlayer", "zencom", "g-core", "gcore", "netcup", "hetzner",
]

RESIDENTIAL_NAME_PATTERNS = [
    # 通用家宽特征
    # ★ 2026-10-05 删掉 "cust" / "customer" / "subscriber": VPN/代理商常用
    #   "Private Customer" 做 ISP 名 (实测 HIVELOCITY VPS 因此以 70 分混入严格家宽)。
    #   真家宽 ISP 用 residential/home/broadband/dsl 等词, 不靠这三个泛词召回。
    "broadband", "pppoe", "pppoa", "dsl", "cable", "fiber", "ftth",
    "fibre", "dynamic", "dial", "dialup", "residential", "home",
    "consumer", "pool", "dynamic-ip",
    # 台湾
    "chunghwa", "hinet", "taiwanmobile", "twn", "aptg", "kbro",
    "tfn", "sparq", "seednet", "data communication business group",
    # 香港
    "hkbn", "hong kong broadband", "pccw", "hkt", "hgc", "smartone",
    "netvigator", "citic telecom", "i-cable", "hk cable",
    # 日本
    "softbank", "ocn", "plala", "so-net", "iiJmio home", "eonet",
    "kddi", "jcom", "au broadband", "biglobe", "nifty",
    # 韩国
    "korea telecom", "kt corp", "sk broadband", "lgu+", "lg uplus",
    # 美国
    "comcast", "charter communications", "spectrum", "cox communications",
    "at&t", "at and t", "bellsouth", "sbc internet", "qwest", "centurylink",
    "verizon fios", "verizon online", "frontier communications", "windstream",
    "altice", "optimum online", "rcn", "wave broadband", "consolidated",
    "hughes", "viasat", "starlink", "mediaserv",
    # 欧洲
    "deutsche telekom", "telekom deutschland", "vodafone d2", "kabel deutschland",
    "british telecom", "bt broadband", "virgin media", "sky uk", "talktalk",
    "orange sa", "free SAS".lower(), "sfr", "bouygues", "bbox", "numericable",
    "kpn", "ziggo", "t-mobile netherlands", "proximus", "telenet",
    "telefonica", "movistar", "vodafone espana", "jazztel", "orange es",
    "telecom italia", "fastweb home", "iliad italia", "windtre",
    "swisscom", "a1 telekom", "magyar telekom", "o2 czech",
    "telia sweden", "telenor", "tele2 sweden", "bredband2",
    "rostelecom home", "mgts", "ertelecom", "dom.ru", "mtu-moscow",
    # 亚太其他
    "singtel", "starhub", "m1 limited", "myrepublic", "viewqwest",
    "maxis", "unifi", "time dotcom", "tm net", "celcom",
    "ais", "true internet", "3bb", "dtac tri", "ntc net",
    "viettel", "vnpt", "fpt telecom", "cmc telecom", "vinaphone",
    "pldt", "globe telecom", "converge ict", "sky broadband ph",
    "telkomsel", "indosat", "xl axiata", "biznet networks", "first media",
    # 拉美 / 土耳其 / 其他
    "claro", "vivo", "tim brasil", "oi internet", "net servicos",
    "turk telekom", "superonline", "ttk", "kablonet", "vodafone net",
    " kazakhtelecom", "beeline kz", "izatelecom",
    "bigpond", "iinet", "optus", "tpg internet", "aussie broadband",
    "spark nz", "vodafone nz", "2degrees", "orcon", "slingshot",
]

# 公司名后缀 → 注册国 (用于"国家-ASN 错位"检测; 后缀须足够独特, 避免误伤)
# 原理: 跨国 VPN 转售商常用注册国公司主体运营他国 IP
# (实测: 美国 IP 挂着土耳其 "LTD. STI." / 日本 IP 挂着新加坡 "PTE.")
_FOREIGN_SUFFIX_CC = {
    "ltd. sti": "TR", "ltd sti": "TR",  # 土耳其
    "telekomunikasyon": "TR",           # 土耳其语拼写
    "pte.": "SG",                      # 新加坡 PTE. LTD.
    "s.r.o.": "CZ",                    # 捷克/斯洛伐克
    "sp. z o.o": "PL",                 # 波兰
    "gmbh": "DE",                      # 德国 (DE/AT/CH)
    "s.a.r.l": "FR", "sarl": "FR",     # 法国
    "ltda": "BR",                      # 巴西/葡萄牙
    "pty": "AU",                       # 澳洲 Pty Ltd
}

# 协议 → 全称 (命名用)
PROTOCOL_LABELS = {
    "vless": "VLESS", "vmess": "VMESS", "trojan": "Trojan",
    "ss": "Shadowsocks", "hysteria2": "Hysteria2", "tuic": "TUIC",
    "anytls": "AnyTLS",
}

COUNTRY_NAMES = {
    "HK": "中国香港 (Hong Kong)", "TW": "中国台湾 (Taiwan)", "JP": "日本 (Japan)",
    "SG": "新加坡 (Singapore)", "US": "美国 (United States)", "KR": "韩国 (South Korea)",
    "DE": "德国 (Germany)", "GB": "英国 (United Kingdom)", "CA": "加拿大 (Canada)",
    "FR": "法国 (France)", "NL": "荷兰 (Netherlands)", "RU": "俄罗斯 (Russia)",
    "IN": "印度 (India)", "AU": "澳大利亚 (Australia)", "IT": "意大利 (Italy)",
    "ES": "西班牙 (Spain)", "TR": "土耳其 (Turkey)", "AE": "阿联酋 (UAE)",
    "BR": "巴西 (Brazil)", "MY": "马来西亚 (Malaysia)", "TH": "泰国 (Thailand)",
    "VN": "越南 (Vietnam)", "PH": "菲律宾 (Philippines)", "ID": "印尼 (Indonesia)",
    "MX": "墨西哥 (Mexico)", "AR": "阿根廷 (Argentina)", "CL": "智利 (Chile)",
    "CO": "哥伦比亚 (Colombia)", "PE": "秘鲁 (Peru)", "ZA": "南非 (South Africa)",
    "EG": "埃及 (Egypt)", "KE": "肯尼亚 (Kenya)", "NG": "尼日利亚 (Nigeria)",
    "UA": "乌克兰 (Ukraine)", "PL": "波兰 (Poland)", "SE": "瑞典 (Sweden)",
    "NO": "挪威 (Norway)", "FI": "芬兰 (Finland)", "DK": "丹麦 (Denmark)",
    "CH": "瑞士 (Switzerland)", "AT": "奥地利 (Austria)", "BE": "比利时 (Belgium)",
    "IE": "爱尔兰 (Ireland)", "PT": "葡萄牙 (Portugal)", "GR": "希腊 (Greece)",
    "CZ": "捷克 (Czech)", "RO": "罗马尼亚 (Romania)", "HU": "匈牙利 (Hungary)",
    "IL": "以色列 (Israel)", "SA": "沙特 (Saudi Arabia)", "QA": "卡塔尔 (Qatar)",
    "KZ": "哈萨克斯坦 (Kazakhstan)", "UZ": "乌兹别克斯坦 (Uzbekistan)",
    "PK": "巴基斯坦 (Pakistan)", "BD": "孟加拉 (Bangladesh)", "LK": "斯里兰卡 (Sri Lanka)",
    "NP": "尼泊尔 (Nepal)", "MM": "缅甸 (Myanmar)", "KH": "柬埔寨 (Cambodia)",
    "LA": "老挝 (Laos)", "NZ": "新西兰 (New Zealand)", "EE": "爱沙尼亚 (Estonia)",
    "LV": "拉脱维亚 (Latvia)", "LT": "立陶宛 (Lithuania)", "BG": "保加利亚 (Bulgaria)",
    "RS": "塞尔维亚 (Serbia)", "HR": "克罗地亚 (Croatia)", "SK": "斯洛伐克 (Slovakia)",
    "SI": "斯洛文尼亚 (Slovenia)", "IS": "冰岛 (Iceland)", "LU": "卢森堡 (Luxembourg)",
    "MT": "马耳他 (Malta)", "CY": "塞浦路斯 (Cyprus)", "GE": "格鲁吉亚 (Georgia)",
    "AM": "亚美尼亚 (Armenia)", "AZ": "阿塞拜疆 (Azerbaijan)", "MD": "摩尔多瓦 (Moldova)",
    "BY": "白俄罗斯 (Belarus)", "SC": "塞舌尔 (Seychelles)", "OTHER": "其他地区 (Other)",
}


# ══════════════════════════════════════════════════════════════════
# 工具函数
# ══════════════════════════════════════════════════════════════════

def get_country_flag(country_code: str) -> str:
    if not country_code:
        return "🌐"
    cc = country_code.upper()
    if cc in ("OTHER", "ZZ", "XX", "T1", "A1", "A2"):
        return "🌐"
    if len(cc) == 2 and cc.isalpha() and cc.isascii():
        return chr(ord(cc[0]) + 127397) + chr(ord(cc[1]) + 127397)
    return "🌐"


def b64_decode(data: str) -> str:
    """容错 base64 解码 (支持 URL-safe / 缺失 padding)"""
    data = data.strip()
    try:
        pad = -len(data) % 4
        if data and data[-1] not in "=":
            data += "=" * pad
        raw = base64.urlsafe_b64decode(data)
        return raw.decode("utf-8", errors="ignore")
    except Exception:
        pass
    try:
        raw = base64.b64decode(data + "=" * (-len(data) % 4))
        return raw.decode("utf-8", errors="ignore")
    except Exception:
        return ""


# ══════════════════════════════════════════════════════════════════
# HTTP 会话 (两分离设计):
#
# 【设计定位: 测活视角 = GitHub Actions 美国微软云 (海外直连节点)】
#   节点从海外可达即入库; 大陆用户经前置代理(链式)访问 —— 与 CI 同视角。
#   因此: 本地开发机 (大陆网络) 只用于调试, 抓订阅源需借系统代理过墙;
#   生产环境 (Actions) 无代理直连, 天然正确。
#
#   - DIRECT_SESSION (trust_env=True): 抓订阅源/下载数据库/IP情报/Scamalytics。
#       本地: 经系统代理 (v2rayN) 过墙; Actions: 直连 — 两种环境都正确。
#   - PROBE_SESSION (trust_env=False): 经 sing-box SOCKS 探测节点。
#       强制隔离环境代理, 保证测的是"运行机→节点"真实链路。
#       (本地调试时受 GFW 影响的失败 ≠ 节点死亡, Actions 上会得到真实结果;
#        宁可本地多杀, 不可 CI 误杀 — 生产判定以 Actions 为准)
# ══════════════════════════════════════════════════════════════════

DIRECT_SESSION = requests.Session()
DIRECT_SESSION.trust_env = True    # 跟随系统/环境代理 (本地大陆网络抓 GitHub 需要; Actions 无代理直连不受影响)
DIRECT_SESSION.headers.update({"User-Agent": USER_AGENT, "Accept": "*/*"})

PROBE_SESSION = requests.Session()
PROBE_SESSION.trust_env = False    # 强制隔离: 节点探测链路绝不经本机代理, 防污染测试结果
PROBE_SESSION.headers.update({"User-Agent": USER_AGENT})


def http_get(url: str, timeout: int = 15, headers: dict = None) -> requests.Response:
    h = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    if headers:
        h.update(headers)
    return DIRECT_SESSION.get(url, timeout=timeout, headers=h)


def ensure_directories():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(COUNTRY_DIR, exist_ok=True)
    os.makedirs(RESIDENTIAL_COUNTRY_DIR, exist_ok=True)
    os.makedirs(RUNTIME_DIR, exist_ok=True)


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip())
        return True
    except ValueError:
        return False


def parse_host_port(hostinfo: str):
    """解析 '[v6]:port' 或 'v4:port' 或 'host:port'"""
    hostinfo = hostinfo.strip()
    if hostinfo.startswith("["):
        m = re.match(r"^\[([^\]]+)\](?::(\d+))?$", hostinfo)
        if m:
            return m.group(1), int(m.group(2)) if m.group(2) else 0
        return hostinfo, 0
    if hostinfo.count(":") == 1:
        host, _, port = hostinfo.rpartition(":")
        if host and port.isdigit():
            return host, int(port)
    if hostinfo.count(":") > 1 and is_ip_literal(hostinfo):
        return hostinfo, 0  # 裸 IPv6 无端口
    parts = hostinfo.rsplit(":", 1)
    if len(parts) == 2 and parts[1].isdigit():
        return parts[0], int(parts[1])
    return hostinfo, 0


# ══════════════════════════════════════════════════════════════════
# 环境准备 (sing-box / GeoLite)
# ══════════════════════════════════════════════════════════════════

def download_file(url: str, dest: str, timeout: int = 300, retries: int = 3):
    """下载文件到本地; 分块流式 + 原子替换 + 重试 + 镜像切换
    (GitHub 直连失败自动尝试 jsdelivr 镜像 — 本地大陆网络/CI 偶发限流都更稳)"""
    if os.path.exists(dest) and os.path.getsize(dest) > 1024:
        return
    # 镜像: github.com/OWNER/REPO/... → cdn.jsdelivr.net/gh/OWNER/REPO@...
    mirrors = [url]
    m = re.match(r"^https://(?:github\.com|raw\.githubusercontent\.com)/([^/]+)/([^/]+)/(?:raw|releases/download)/(.+)$", url)
    if m and "releases/download" not in url:
        owner, repo, path = m.groups()
        mirrors.append(f"https://cdn.jsdelivr.net/gh/{owner}/{repo.replace('.git','')}@{path}")
    print(f"[*] 下载: {url}")
    tmp = dest + ".part"
    last_err = None
    for mirror in mirrors:
        for attempt in range(retries):
            try:
                with DIRECT_SESSION.get(mirror, timeout=timeout, stream=True,
                                        headers={"Accept": "*/*"}) as r:
                    r.raise_for_status()
                    with open(tmp, "wb") as f:
                        for chunk in r.iter_content(chunk_size=1 << 20):
                            if chunk:
                                f.write(chunk)
                if os.path.getsize(tmp) < 1024:
                    raise RuntimeError(f"下载不完整: {os.path.getsize(tmp)} bytes")
                os.replace(tmp, dest)
                return
            except Exception as e:
                last_err = e
                if attempt < retries - 1:
                    wait = 3 * (attempt + 1)
                    print(f"[!] 下载失败 (第{attempt+1}次): {str(e)[:70]} — {wait}s 后重试")
                    time.sleep(wait)
        if len(mirrors) > 1 and mirror != mirrors[-1]:
            print(f"[!] 切换镜像: {mirrors[1]}")
    # 清理失败的半截文件
    try:
        if os.path.exists(tmp):
            os.remove(tmp)
    except OSError:
        pass
    raise RuntimeError(f"下载最终失败 ({mirrors[0]}): {last_err}")


def setup_environment():
    print("[*] 准备 sing-box 内核与 GeoLite2 离线数据库 ...")
    os.makedirs(RUNTIME_DIR, exist_ok=True)

    # --- sing-box ---
    exe = SINGBOX_BIN + (".exe" if os.name == "nt" else "")
    if not os.path.exists(exe) or os.path.getsize(exe) < 1024:
        system = "windows" if os.name == "nt" else "linux"
        ext = "zip" if system == "windows" else "tar.gz"
        url = (f"https://github.com/SagerNet/sing-box/releases/download/"
               f"{SINGBOX_VERSION}/sing-box-{SINGBOX_VERSION.lstrip('v')}-{system}-amd64.{ext}")
        archive = os.path.join(RUNTIME_DIR, f"sing-box.{ext}")
        download_file(url, archive)
        if system == "windows":
            with zipfile.ZipFile(archive) as z:
                for name in z.namelist():
                    if name.endswith("sing-box.exe"):
                        with z.open(name) as src, open(exe, "wb") as dst:
                            shutil.copyfileobj(src, dst)
        else:
            with tarfile.open(archive) as t:
                for m in t.getmembers():
                    if m.name.endswith("sing-box"):
                        f = t.extractfile(m)
                        with open(exe, "wb") as dst:
                            shutil.copyfileobj(f, dst)
        os.chmod(exe, 0o755)
        try:
            os.remove(archive)
        except OSError:
            pass
    # 校验内核可运行
    try:
        ver = subprocess.run([exe, "version"], capture_output=True, text=True, timeout=20)
        first = (ver.stdout or "").splitlines()[0] if ver.stdout else "?"
        print(f"[+] sing-box 内核就绪: {first.strip()}")
    except Exception as e:
        print(f"[!] sing-box 内核无法运行: {e}")
        raise

    # --- GeoLite2 数据库 ---
    country_db = os.path.join(RUNTIME_DIR, "Country.mmdb")
    asn_db = os.path.join(RUNTIME_DIR, "ASN.mmdb")
    download_file("https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb", country_db)
    download_file("https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb", asn_db)
    print(f"[+] GeoLite 数据库就绪: Country={os.path.getsize(country_db)//1024}KB, ASN={os.path.getsize(asn_db)//1024}KB")


# ═══════════════════════════════════════════N═══════════════════════
# 节点 URI 解析 (全协议 → sing-box outbound JSON)
# ═══════════════════════════════════════════N═══════════════════════

def _query_dict(query: str) -> dict:
    return {k: v[0] for k, v in urllib.parse.parse_qs(query, keep_blank_values=True).items()}


def _parse_tls_params(params: dict, host: str) -> dict:
    """从 URI query 提取 TLS/Reality 设置 → sing-box 格式"""
    security = params.get("security", "").lower()
    tls = {}
    if security == "reality":
        pbk = params.get("pbk", "")
        if not pbk:
            return None
        tls = {
            "enabled": True,
            "server_name": params.get("sni", params.get("peer", host)),
            "utls": {"enabled": True, "fingerprint": params.get("fp", "chrome")},
            "reality": {"enabled": True, "public_key": pbk, "short_id": params.get("sid", "")},
        }
    elif security in ("tls", "xtls"):
        tls = {
            "enabled": True,
            "server_name": params.get("sni", params.get("peer", host)),
            "insecure": params.get("allowInsecure", "0") in ("1", "true"),
            "alpn": params.get("alpn", "").split(",") if params.get("alpn") else None,
        }
        if params.get("fp"):
            tls["utls"] = {"enabled": True, "fingerprint": params["fp"]}
        if tls.get("alpn") is None:
            del tls["alpn"]
    return tls or None


def _parse_transport(params: dict) -> dict:
    """从 URI query 提取传输层 → sing-box transport 格式"""
    network = params.get("type", "tcp").lower()
    if network in ("tcp", "none", "raw"):
        return None
    if network == "ws":
        t = {"type": "ws"}
        if params.get("path"):
            t["path"] = urllib.parse.unquote(params["path"])
        if params.get("host"):
            t["headers"] = {"Host": params["host"]}
        # 0-RTT early data (v2ray ws 0-RTT: path 含 ?ed=2560 时由 max-early-data 指定)
        if params.get("ed"):
            t["max_early_data"] = 2560
            t["early_data_header_name"] = "Sec-WebSocket-Protocol"
        return t
    if network in ("grpc", "gun"):
        t = {"type": "grpc"}
        if params.get("serviceName"):
            t["service_name"] = urllib.parse.unquote(params["serviceName"])
        return t
    if network in ("h2", "http"):   # v2ray 生态两种写法都有: type=h2 / type=http (导出用 http, 兼容两者)
        t = {"type": "http"}
        host = params.get("host", "")
        if host:
            t["host"] = [h for h in host.split(",") if h]
        if params.get("path"):
            t["path"] = urllib.parse.unquote(params["path"])
        return t
    if network == "httpupgrade":
        t = {"type": "httpupgrade"}
        if params.get("path"):
            t["path"] = urllib.parse.unquote(params["path"])
        if params.get("host"):
            t["host"] = params["host"]
        return t
    return None


def parse_vless(uri: str):
    """vless://uuid@host:port?params#name"""
    m = re.match(r"^vless://([^@#]+)@(\[[^\]]+\]|[^:@/]+):(\d+)(?:[/?]([^#]*))?(?:#(.*))?$", uri)
    if not m:
        return None
    user, host, port, query, _name = m.groups()
    params = _query_dict(query or "")
    tls = _parse_tls_params(params, host)
    if params.get("security", "").lower() == "reality" and tls is None:
        return None  # reality 缺 pbk 无法测
    outbound = {
        "type": "vless",
        "tag": "node",
        "server": host,
        "server_port": int(port),
        "uuid": user,
    }
    flow = params.get("flow", "")
    if flow and ("vision" in flow or "xtls" in flow):
        outbound["flow"] = flow
    if tls:
        outbound["tls"] = tls
    transport = _parse_transport(params)
    if transport:
        outbound["transport"] = transport
    return outbound


def parse_vmess(uri: str):
    """vmess://base64({v,ps,add,port,id,aid,net,tls,sni,path,host,type})"""
    data = json.loads(b64_decode(uri[8:]))
    if not data:
        return None
    server = str(data.get("add", "")).strip()
    port = int(data.get("port", 0) or 0)
    if not server or port <= 0:
        return None
    outbound = {
        "type": "vmess",
        "tag": "node",
        "server": server,
        "server_port": port,
        "uuid": str(data.get("id", "")).strip(),
        "security": "auto",
    }
    aid = int(data.get("aid", 0) or 0)
    if aid > 0:
        outbound["alter_id"] = aid
    net = str(data.get("net", "tcp")).lower()
    if data.get("tls") in ("tls", "1", 1, True):
        outbound["tls"] = {
            "enabled": True,
            "server_name": str(data.get("sni") or data.get("host") or server).strip(),
            "insecure": str(data.get("verify_cert", "false")).lower() in ("true", "1"),
        }
    transport = None
    if net in ("ws",):
        transport = {"type": "ws"}
        if data.get("path"):
            transport["path"] = str(data["path"])
        if data.get("host"):
            transport["headers"] = {"Host": str(data["host"])}
    elif net in ("grpc", "gun"):
        transport = {"type": "grpc"}
        if data.get("path"):
            transport["service_name"] = str(data["path"])
    elif net == "h2":
        transport = {"type": "http"}
        if data.get("path"):
            transport["path"] = str(data["path"])
        if data.get("host"):
            transport["host"] = [str(data["host"])]
    elif net == "httpupgrade":
        transport = {"type": "httpupgrade"}
        if data.get("path"):
            transport["path"] = str(data["path"])
        if data.get("host"):
            transport["host"] = str(data["host"])
    if transport:
        outbound["transport"] = transport
    return outbound


def parse_trojan(uri: str):
    """trojan://password@host:port?params#name"""
    m = re.match(r"^trojan://([^@#]+)@(\[[^\]]+\]|[^:@/]+):(\d+)(?:[/?]([^#]*))?(?:#(.*))?$", uri)
    if not m:
        return None
    password, host, port, query, _ = m.groups()
    params = _query_dict(query or "")
    outbound = {
        "type": "trojan",
        "tag": "node",
        "server": host,
        "server_port": int(port),
        "password": urllib.parse.unquote(password),
        "tls": {
            "enabled": True,
            "server_name": params.get("sni", params.get("peer", host)),
            "insecure": params.get("allowInsecure", "0") in ("1", "true"),
        },
    }
    if params.get("alpn"):
        outbound["tls"]["alpn"] = params["alpn"].split(",")
    if params.get("fp"):
        outbound["tls"]["utls"] = {"enabled": True, "fingerprint": params["fp"]}
    transport = _parse_transport(params)
    if transport:
        outbound["transport"] = transport
    return outbound


def parse_ss(uri: str):
    """ss://base64(method:password)@host:port#name  或  ss://method:password@... (SIP002)"""
    body = uri[5:].split("#", 1)[0]
    name = urllib.parse.unquote(uri.split("#", 1)[1]) if "#" in uri else ""
    # SIP002: method:password@host:port
    if "@" in body:
        userinfo, _, hostinfo = body.rpartition("@")
        host, port = parse_host_port(hostinfo.split("/")[0].split("?")[0])
        method, password = "", ""
        if ":" in userinfo:
            method, _, password = userinfo.partition(":")
        else:
            dec = b64_decode(userinfo)
            if ":" in dec:
                method, _, password = dec.partition(":")
        method = urllib.parse.unquote(method)
        password = urllib.parse.unquote(password)
        if not (host and port > 0 and method and password):
            return None
        return _ss_outbound(host, port, method, password)
    # legacy: base64(method:password@host:port)
    dec = b64_decode(body)
    if "@" in dec:
        userinfo, _, hostinfo = dec.rpartition("@")
        host, port = parse_host_port(hostinfo.strip())
        method, _, password = userinfo.partition(":")
        if host and port > 0 and method:
            return _ss_outbound(host, port, urllib.parse.unquote(method), urllib.parse.unquote(password))
    return None


def _ss_outbound(host, port, method, password):
    return {
        "type": "shadowsocks",
        "tag": "node",
        "server": host,
        "server_port": int(port),
        "method": method.strip().lower(),
        "password": password,
    }


def parse_hysteria2(uri: str):
    """hy2:// / hysteria2:// auth@host:port?sni=..&obfs=salamander&obfs-password=..&insecure=1
    注: auth 可能含 : / 等特殊字符 (如 https:// 前缀的密码) — 以最后一个 @ 为锚点分割"""
    prefix = "hysteria2://" if uri.startswith("hysteria2://") else "hy2://"
    body = uri[len(prefix):].split("#", 1)[0]
    # 以最后一个 @ 分割 (密码内可能含 @); host 部分不含 @
    at = body.rfind("@")
    if at <= 0:
        return None
    auth, rest = body[:at], body[at+1:]
    m = re.match(r"^(\[[^\]]+\]|[^:/?#]+):(\d+)(?:[/?]([^#]*))?$", rest)
    if not m:
        return None
    host, port, query = m.groups()
    params = _query_dict(query or "")
    outbound = {
        "type": "hysteria2",
        "tag": "node",
        "server": host,
        "server_port": int(port),
        "password": urllib.parse.unquote(auth),
        "tls": {
            "enabled": True,
            "server_name": params.get("sni", params.get("peer", host)),
            "insecure": params.get("allowInsecure", "0") in ("1", "true") or params.get("insecure", "0") in ("1", "true"),
        },
    }
    if params.get("alpn"):
        outbound["tls"]["alpn"] = params["alpn"].split(",")
    if params.get("obfs", "") and params["obfs"] not in ("none", ""):
        outbound["obfs"] = {"type": params["obfs"], "password": params.get("obfs-password", "")}
    mport = params.get("mport") or params.get("ports")
    if mport:
        # 实测验证: server_ports 只接受 "start:end" 区间; 裸单端口 "443" 会 FATAL
        # 单端口保留在 server_port, 区间放 server_ports (两者可共存, 实测 check 通过)
        singles, ranges = [], []
        for part in str(mport).split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                a, _, b = part.partition("-")
                if a.strip().isdigit() and b.strip().isdigit():
                    if a.strip() == b.strip():
                        singles.append(a.strip())
                    else:
                        ranges.append(f"{a.strip()}:{b.strip()}")
            elif part.isdigit():
                singles.append(part)
        if ranges or singles:
            # 全部转为 "start:end" 区间格式 (实测: 裸单端口 FATAL)
            outbound["server_ports"] = ranges + [f"{s}:{s}" for s in singles]
            outbound.pop("server_port", None)  # 端口跳跃节点无固定单端口
    return outbound


def _parse_port_range(spec: str):
    """'2087-2097,443' → sing-box server_ports 格式 ['2087:2097', '443:443'] (实测: 裸单端口 FATAL, 必须区间)"""
    result = []
    for part in str(spec).split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, _, b = part.partition("-")
            if a.strip().isdigit() and b.strip().isdigit():
                result.append(f"{a.strip()}:{b.strip()}")
        elif part.isdigit():
            result.append(f"{part}:{part}")
    return result


def parse_tuic(uri: str):
    """tuic://uuid:password@host:port?congestion_control=bbr&alpn=h3&sni=..&udp_relay_mode=native#name"""
    m = re.match(r"^tuic://([^@#/?]+)@(\[[^\]]+\]|[^:@/?]+):(\d+)(?:[/?]([^#]*))?$", uri.split("#")[0])
    if not m:
        return None
    userinfo, host, port, query = m.groups()
    if ":" not in userinfo:
        return None
    uuid_, _, password = userinfo.partition(":")
    params = _query_dict(query or "")
    outbound = {
        "type": "tuic",
        "tag": "node",
        "server": host,
        "server_port": int(port),
        "uuid": urllib.parse.unquote(uuid_),
        "password": urllib.parse.unquote(password),
        "congestion_control": params.get("congestion_control", "bbr"),
        "udp_relay_mode": params.get("udp_relay_mode", "native"),
        "tls": {
            "enabled": True,
            "server_name": params.get("sni", host),
            "insecure": params.get("allow_insecure", "0") in ("1", "true"),
            "alpn": [a for a in params.get("alpn", "h3").split(",") if a],
        },
    }
    return outbound


def parse_anytls(uri: str):
    """anytls://password@host:port?sni=..&insecure=1#name"""
    m = re.match(r"^anytls://([^@#/?]+)@(\[[^\]]+\]|[^:@/?]+):(\d+)(?:[/?]([^#]*))?$", uri.split("#")[0])
    if not m:
        return None
    password, host, port, query = m.groups()
    params = _query_dict(query or "")
    outbound = {
        "type": "anytls",
        "tag": "node",
        "server": host,
        "server_port": int(port),
        "password": urllib.parse.unquote(password),
        "tls": {
            "enabled": True,
            "server_name": params.get("sni", host),
            "insecure": params.get("insecure", "0") in ("1", "true") or params.get("allowInsecure", "0") in ("1", "true"),
        },
    }
    if params.get("alpn"):
        outbound["tls"]["alpn"] = params["alpn"].split(",")
    return outbound


def parse_ssh(uri: str):
    """ssh://user:pass@host:port#name (少见于免费池, 顺手支持)"""
    m = re.match(r"^ssh://([^@#/?]+)@(\[[^\]]+\]|[^:@/?]+):(\d+)?", uri.split("#")[0])
    if not m:
        return None
    userinfo, host, port = m.groups()
    outbound = {
        "type": "ssh",
        "tag": "node",
        "server": host,
        "server_port": int(port or 22),
        "user": urllib.parse.unquote(userinfo.split(":")[0]),
    }
    if ":" in userinfo:
        outbound["user"] = urllib.parse.unquote(userinfo.split(":")[0])
        outbound["password"] = urllib.parse.unquote(userinfo.split(":", 1)[1])
    return outbound


PARSERS = {
    "vless://": parse_vless,
    "vmess://": parse_vmess,
    "trojan://": parse_trojan,
    "ss://": parse_ss,
    "hy2://": parse_hysteria2,
    "hysteria2://": parse_hysteria2,
    "tuic://": parse_tuic,
    "anytls://": parse_anytls,
    "ssh://": parse_ssh,
}

# 排除明显加密残缺/占位节点
BLACKLIST_NAME_HINTS = re.compile(r"(剩余流量|流量重置|expire|expired|官网|套餐|telegram\.me|t\.me/|获取订阅)", re.I)


def parse_node_uri(uri: str):
    """解析节点 URI → (outbound, server, port, protocol) ; 失败返回 None"""
    for prefix, parser in PARSERS.items():
        if uri.startswith(prefix):
            try:
                out = parser(uri)
            except Exception:
                return None
            if not out:
                return None
            proto = out["type"]
            port = out.get("server_port")
            if port is None:  # 端口跳跃节点: 无固定端口, 取区间首个起点用于预检
                ports = out.get("server_ports") or []
                first = ports[0].split(":")[0] if ports else "0"
                port = int(first)
            if port <= 0:
                return None
            return out, out["server"], int(port), proto
    return None


def extract_nodes_from_text(text: str) -> set:
    results = set()
    if not text:
        return results
    probe = text.strip()
    # 最多三层 base64 解包 (订阅常见整体 base64)
    for _ in range(3):
        if any(p in probe for p in ("vmess://", "vless://", "ss://", "trojan://",
                                     "hy2://", "hysteria2://", "tuic://", "anytls://")):
            break
        decoded = b64_decode(probe)
        if not decoded or decoded == probe:
            break
        probe = decoded
    # 直接文本也可能混杂 base64 行
    lines_blob = probe
    pattern = (r'((?:vmess|vless|trojan|ss|hy2|hysteria2|tuic|anytls|ssh)://'
               r'[^\s"\'<>\\]+)')
    for m in re.findall(pattern, lines_blob):
        clean = m.strip().rstrip(".,;'\"")
        if len(clean) > 12:
            results.add(clean)
    return results


def fetch_raw_nodes() -> list:
    nodes = set()
    print("[*] 抓取全部订阅源 ...")

    def _fetch(url):
        last_err = None
        # 重试 2 次 (网络抖动/GFW 间歇性重置; 退避 3s)
        for attempt in range(3):
            try:
                r = http_get(url, timeout=30)
                if r.status_code == 200:
                    got = extract_nodes_from_text(r.text)
                    return url, got, None
                last_err = f"HTTP {r.status_code}"
            except Exception as e:
                last_err = str(e)[:70]
            if attempt < 2:
                time.sleep(3)
        return url, set(), last_err

    with ThreadPoolExecutor(MAX_WORKERS_FETCH) as ex:
        futs = [ex.submit(_fetch, u) for u in SOURCE_URLS]
        for f in as_completed(futs):
            url, got, err = f.result()
            if err:
                print(f"[!] 拉取失败 {url} → {err}")
            else:
                print(f"[+] {url} → {len(got)} 节点")
            nodes.update(got)
    print(f"[*] 初始抓取总量: {len(nodes)}")
    return list(nodes)


# ═══════════════════════════════════════════N═══════════════════════
# 阶段 A: 端口预检 (削减死节点, 避免后面浪费 sing-box 全流程)
# ═══════════════════════════════════════════N═══════════════════════

# DoH 域名解析 (Cloudflare): 防 DNS 污染 (本地大陆网络); Actions 上顺带跳过其国内 DNS 限制
_DNS_CACHE = {}

def resolve_host(host: str) -> str:
    """DoH 解析 (带本地缓存); 失败退回系统 DNS"""
    if not host or is_ip_literal(host):
        return host or ""
    if host in _DNS_CACHE:
        return _DNS_CACHE[host]
    # 1) DoH (Cloudflare 1.1.1.1, 走 DIRECT_SESSION 可过墙)
    try:
        r = DIRECT_SESSION.get(
            f"https://cloudflare-dns.com/dns-query?name={urllib.parse.quote(host)}&type=A",
            headers={"Accept": "application/dns-json"}, timeout=5)
        if r.status_code == 200:
            answers = r.json().get("Answer") or []
            for a in answers:
                if a.get("type") == 1 and a.get("data"):
                    _DNS_CACHE[host] = a["data"]
                    return a["data"]
    except Exception:
        pass
    # 2) 系统 DNS 兜底
    try:
        return socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
    except Exception:
        return ""


def knock_port(server: str, port: int, protocol_type: str) -> bool:
    """TCP 直连预检 (DoH 解析防本地 DNS 污染); QUIC 类直接放行阶段B
    注: 预检失败是否淘汰取决于 PREFILTER_DROP_FAILED ——
        CI 海外直连视角下失败 = 端口真死, 可安全淘汰 (见 prefilter_candidates);
        本地大陆视角下 PREFILTER_DROP_FAILED=0, 失败不淘汰只降级排序。"""
    if protocol_type in ("hysteria2", "tuic"):
        # QUIC 无法轻量预检 UDP 端口连通性, 且本地 UDP 常被 QoS → 放行交阶段B
        return True
    for attempt in range(PREFILTER_RETRY if PREFILTER_DROP_FAILED else 1):
        try:
            ip = resolve_host(server)
            if not ip:
                continue
            with socket.create_connection((ip, port), timeout=PORT_KNOCK_TIMEOUT):
                return True
        except Exception:
            if attempt == 0:
                time.sleep(0.4)   # 单次抖动重试 (硬淘汰模式下才重试)
    return False


def prefilter_candidates(candidates: list) -> list:
    """端口预检: 通过者优先, 未通过者降级保留 (防止本地网络/GFW 视角误杀;
    真正生死由阶段B sing-box 全流程测活裁决 — Actions 海外视角)"""
    print(f"[*] 端口预检 (TCP {PORT_KNOCK_TIMEOUT}s): {len(candidates)} 候选 ...")
    passed, deferred = [], []

    def _knock(item):
        raw, outbound, server, port, proto = item
        return knock_port(server, port, proto)

    with ThreadPoolExecutor(max_workers=64) as ex:
        # ex.map 保序返回; 通过者优先, 未通过降级保留 (不淘汰, 防本地视角误杀)
        for item, ok in zip(candidates, ex.map(_knock, candidates)):
            (passed if ok else deferred).append(item)
    print(f"[+] 预检通过: {len(passed)} | 预检未过: {len(deferred)}"
          f"{' (已硬淘汰)' if PREFILTER_DROP_FAILED else ' (保留低优先级待全测)'}")
    if PREFILTER_DROP_FAILED:
        # 端口都握手不上, 没必要再烧 sing-box 全流程 (每个约 10-20s)
        dropped = len(deferred)
        if dropped:
            print(f"[*] 端口预检硬淘汰 {dropped} 个不可达节点 "
                  f"(节省约 {dropped * 15 // 60} 分钟 CI 时间)")
        return passed
    # 未启用硬淘汰时保持原行为: 预检未过的排后面, 交给 sing-box 真实裁决
    return passed + deferred


# ═══════════════════════════════════════════N═══════════════════════
# 阶段 B: sing-box 真实测活
# ═══════════════════════════════════════════N═══════════════════════

def _alloc_socks_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def build_test_config(outbound: dict, socks_port: int, chain_relay: dict = None) -> dict:
    node = dict(outbound)
    node["tag"] = "node"

    outbounds = [node, {"type": "direct", "tag": "direct"}, {"type": "block", "tag": "block"}]

    # ══ 链式前置 (家宽链式复测用) ═════════════════════════════════════
    # chain_relay: 已验证存活的 sing-box outbound dict — node 经它转发 (detour 双跳)
    # 模拟用户 v2rayN "链式/前置代理" 场景: 前置 → 家宽节点 → 目标
    if chain_relay:
        relay = dict(chain_relay)
        relay["tag"] = "chain-relay"
        # relay 自身剥 detour (避免与 node 的 detour 循环)
        relay.pop("detour", None)
        outbounds.append(relay)
        node["detour"] = "chain-relay"

    # ══ 前置代理 (链式) ═════════════════════════════════════════════
    # 模拟 GitHub Actions 海外视角:
    #   - 本地大陆开发机: 经前置代理(默认 v2rayN 127.0.0.1:10808)出海 → 等效 CI 视角
    #     (大陆直连目标节点会被 GFW 拦截, 造成本地假死 ≠ 节点死亡)
    #   - GitHub Actions: FRONT_PROXY 为空 → 直连 (Azure US 本就是海外视角)
    # 用法: 环境变量 FRONT_PROXY=socks5://127.0.0.1:10808
    front = os.environ.get("FRONT_PROXY", "").strip()
    if front and not chain_relay:
        # 解析 socks5://host:port → socks outbound
        m = re.match(r"^(socks5h?|http)://([^:]+):(\d+)$", front)
        if m:
            scheme, fhost, fport = m.groups()
            ftype = "socks" if scheme.startswith("socks5") else "http"
            front_out = {
                "type": ftype, "tag": "front-proxy",
                "server": fhost, "server_port": int(fport),
            }
            if ftype == "socks":
                front_out["version"] = "5"
            outbounds.append(front_out)
            # 节点出站流量经前置代理 (detour 链式)
            node["detour"] = "front-proxy"
            print_once("_FRONT_ENABLED", f"[*] 前置代理已启用: {front} (模拟 CI 海外视角)")

    config = {
        "log": {"level": "warn"},   # 实测: silent 不是合法级别 (trace/debug/info/warn/error/fatal/panic)
        "inbounds": [{
            "type": "socks",
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "listen_port": socks_port,
            "sniff": False,
        }],
        "outbounds": outbounds,
        "route": {"rules": [], "final": "node"},
    }
    return config


_PRINTED_ONCE = set()


def print_once(key: str, msg: str):
    if key not in _PRINTED_ONCE:
        _PRINTED_ONCE.add(key)
        print(msg)


def test_single_node(item, keep_alive_check=True):
    """返回 dict 或 None; 含: 活性/延迟/出口IP/国家/ASN/ISP/速度/MITM"""
    raw, outbound, server, port, proto = item
    socks_port = _alloc_socks_port()
    task_id = uuid.uuid4().hex[:10]
    cfg_path = os.path.join(RUNTIME_DIR, f"sb_{task_id}.json")

    # ★ 链式前置 (chain relay): 注入已验证存活节点作前置 (chain_retest 用, 模拟 v2rayN 链式)
    chain_out = None
    chain_json = os.environ.get("CHAIN_RELAY_OUT", "").strip()
    if chain_json:
        try:
            chain_out = json.loads(chain_json)
        except Exception:
            chain_out = None
    config = build_test_config(outbound, socks_port, chain_relay=chain_out)
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(config, f)

    exe = SINGBOX_BIN + (".exe" if os.name == "nt" else "")

    # --- 0) sing-box check 预校验: 快速淘汰 schema 错误 (实测可发现 2022 密钥长度/端口区间等错误) ---
    try:
        chk = subprocess.run([exe, "check", "-c", cfg_path],
                             capture_output=True, text=True, timeout=15,
                             creationflags=(subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0))
        if chk.returncode != 0:
            return None  # 配置级错误 → 该节点无法被 sing-box 使用, 必淘汰
    except Exception:
        pass  # check 本身失败不阻止后续 run 尝试

    proc = None
    result = None
    try:
        proc = subprocess.Popen(
            [exe, "run", "-c", cfg_path],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=(subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0),
        )
        # 等 SOCKS 端口就绪 (主动探测而非盲 sleep — 修复旧版误杀)
        deadline = time.time() + 6
        ready = False
        while time.time() < deadline:
            if proc.poll() is not None:
                break  # 进程崩溃 (配置错误/端口冲突)
            try:
                with socket.create_connection(("127.0.0.1", socks_port), timeout=0.4):
                    ready = True
                    break
            except Exception:
                time.sleep(0.15)
        if not ready:
            return None

        proxies = {"http": f"socks5h://127.0.0.1:{socks_port}",
                   "https": f"socks5h://127.0.0.1:{socks_port}"}

        # --- 1) 活性探测: 分层超时重试 (首击宽 12s 容慢节点保准确率; 重试窄 4s 快速放弃死节点) ---
        alive_hits, latency_ms = 0, 99999
        t0 = time.time()
        for i, url in enumerate(LIVENESS_URLS):
            timeout = PROBE_TIMEOUT if i == 0 else PROBE_RETRY_TIMEOUT
            try:
                r = PROBE_SESSION.get(url, proxies=proxies, timeout=timeout, allow_redirects=False)
                if r.status_code in (204, 200):
                    alive_hits += 1
                    latency_ms = min(latency_ms, (time.time() - t0) * 1000)
                    break  # 任一成功即可
            except Exception:
                continue
        if alive_hits == 0:
            return None

        # --- 2) 真实出口 IP (多路冗余) ---
        exit_ip, exit_country, exit_asn, exit_asn_org, exit_isp = None, None, None, None, None
        for url in IP_ECHO_URLS:
            try:
                r = PROBE_SESSION.get(url, proxies=proxies, timeout=IP_ECHO_TIMEOUT)
                if r.status_code != 200:
                    continue
                j = r.json()
                ip = (j.get("ip") or j.get("query") or j.get("your_ip") or "").strip()
                if not ip:
                    continue
                exit_ip = ip
                if url.startswith("https://api.ip.sb"):
                    exit_country = j.get("country_code")
                    exit_asn = j.get("asn")
                    exit_asn_org = (j.get("asn_organization") or j.get("organization") or "")
                    exit_isp = (j.get("isp") or j.get("organization") or "")
                elif url.startswith("https://ipinfo.io"):
                    exit_country = exit_country or (j.get("country") or "").upper()
                    org = j.get("org") or ""
                    if org and not exit_asn:
                        mm = re.match(r"^AS(\d+)\s+(.*)", org)
                        if mm:
                            exit_asn, exit_asn_org = int(mm.group(1)), mm.group(2)
                    exit_isp = exit_isp or org
                elif "ip-api.com" in url:
                    exit_country = exit_country or (j.get("countryCode") or "").upper()
                    exit_asn = exit_asn or j.get("as")
                    exit_asn_org = exit_asn_org or j.get("asname") or j.get("org") or ""
                    exit_isp = exit_isp or j.get("isp") or j.get("org") or ""
                break
            except Exception:
                continue

        # --- 3) MITM 劫持检测 (轻量: 复用活性首击的 gstatic 请求已验证证书链) ---
        # 3a) 独立复检一次带 verify=True 的请求: SSLError = TLS 拦截
        mitm_risk = False
        try:
            r = PROBE_SESSION.get("https://www.gstatic.com/generate_204", proxies=proxies,
                                  timeout=PROBE_RETRY_TIMEOUT, verify=True)
            if r.status_code in (204, 200):
                mitm_risk = False
            else:
                mitm_risk = r.status_code in (301, 302, 403, 407, 502, 503) or len(r.content) > 0
        except requests.exceptions.SSLError:
            # 证书链验证失败 = TLS 拦截 (MITM) 或劣质自签劫持
            mitm_risk = True
        except Exception:
            pass  # 网络层失败不算 MITM (活性探测已通过)

        # 3b) cloudflare trace: warp=on = 套壳 WARP 节点 (非真实出口, 降权标记) — 4s 窄超时
        is_warp = False
        try:
            r = PROBE_SESSION.get(TRACE_URL, proxies=proxies, timeout=PROBE_RETRY_TIMEOUT, verify=True)
            if r.status_code == 200:
                if re.search(r"^warp=on", r.text, re.M):
                    is_warp = True
        except Exception:
            pass

        # --- 4) 断流检测: 限时下载测速 (chunked 读 + 空闲计时; 多端点兜底防测速站被屏蔽) ---
        # 断流签名: 连接建立且首包正常, 但中途停止送数据 → 空闲超时强断
        speed_bps = 0
        for speed_url in SPEED_TEST_URLS:
            downloaded = 0
            t_speed = time.time()
            last_chunk_time = time.time()
            try:
                with PROBE_SESSION.get(speed_url, proxies=proxies,
                                       timeout=(5, SPEED_TEST_BUDGET), stream=True) as r:
                    if r.status_code == 200:
                        for chunk in r.iter_content(chunk_size=65536):
                            now = time.time()
                            if chunk:
                                downloaded += len(chunk)
                                last_chunk_time = now
                            # 总预算超限 → 正常截断 (拿已有数据算吞吐)
                            if now - t_speed > SPEED_TEST_BUDGET:
                                break
                            # 空闲 > 3s 无任何数据 → 断流签名, 立即中止
                            if now - last_chunk_time > 3.0:
                                break
                elapsed = max(time.time() - t_speed, 0.001)
                if downloaded > 0:
                    speed_bps = int(downloaded / elapsed)
                    break  # 首个成功端点的结果即有效
            except Exception:
                continue
        # 全部端点都失败 (下载0字节) → 视为断流 (活性已过但无法承载数据流)

        # 断流判定: 连 70KB/s 都达不到 → 断流/极慢, 真实不可用
        is_stalled = speed_bps < SPEED_MIN_BYTES_PER_S

        result = {
            "raw": raw,
            "server": server,
            "port": port,
            "proto": proto,
            # 凭据指纹: 供去重回填用完整 key (server, port, proto, fp) 精确匹配,
            # 避免同目标不同凭据的组互相覆盖结果 (死节点被标活 / 活节点被标死)
            "cred_fp": cred_fingerprint(outbound, proto),
            # 实测验证过的 outbound: 导出/链式复测优先用它, 而不是从 raw 重解析
            # (同一 raw 可能解析出多个 outbound, 如 ss 多用户, parsed[0] 未必是测过的那个)
            "outbound": dict(outbound),
            "alive": True,
            "latency_ms": int(latency_ms),
            "exit_ip": exit_ip,
            "exit_country_online": exit_country,
            "exit_asn_online": exit_asn,
            "exit_asn_org_online": (exit_asn_org or "")[:120],
            "exit_isp_online": (exit_isp or "")[:120],
            "mitm_risk": mitm_risk,
            "is_warp": is_warp,
            "speed_bps": speed_bps,
            "is_stalled": is_stalled,
        }
        return result
    except Exception:
        return None
    finally:
        if proc and proc.poll() is None:
            proc.kill()
            try:
                proc.wait(timeout=3)
            except Exception:
                pass
        try:
            if os.path.exists(cfg_path):
                os.remove(cfg_path)
        except OSError:
            pass


def run_liveness_test(candidates: list) -> list:
    print(f"[*] sing-box 全协议真实测活: {len(candidates)} 节点 (并发 {MAX_WORKERS_TEST}) ...")
    results = []
    done_count = [0]

    def _work(item):
        return test_single_node(item)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS_TEST) as ex:
        futs = {ex.submit(_work, it): it for it in candidates}
        for fut in as_completed(futs):
            done_count[0] += 1
            r = fut.result()
            if r:
                results.append(r)
            if done_count[0] % 40 == 0:
                print(f"[*] 测活进度: {done_count[0]}/{len(candidates)}, 通过 {len(results)}")

    alive = [r for r in results if r["alive"] and not r["is_stalled"]]
    mitm = sum(1 for r in results if r["mitm_risk"])
    stalled = sum(1 for r in results if r["is_stalled"])
    print(f"[+] 测活完成: 真活 {len(alive)} | 断流淘汰 {stalled} | MITM 风险 {mitm}")
    return results  # 保留全部信息, 分类阶段再决定去留


# ═══════════════════════════════════════════N═══════════════════════
# 阶段 B2: 家宽链式复测 (chain relay retest)
# ════════════════════════════════════════════════════════════════════

def chain_retest(test_results: list) -> list:
    """家宽链式复测: 模拟用户 v2rayN 链式 (前置 → 家宽节点 → 目标)

    实测背景: 用户反馈家宽节点在 v2rayN 链式代理下仅 ~50% 可用。
    根因: 单跳测活通过 ≠ 双跳可用 (部分节点不允许"已被代理的流量"再入,
    或 UDP/QUIC 节点无法过 socks 链)。解决: CI 里用最快存活节点当前置,
    对家宽候选做双跳复测 — 双跳通过的才进家宽专区。

    流程: 先跑一遍轻量分类拿到家宽候选 → 取最快存活节点做 relay →
    家宽候选逐个双跳复测 → 双跳也活的保留, 双跳死的降级普通区。
    返回: 更新 net_type 后的 test_results (原对象原地修改)。
    """
    # 1) 轻量分类拿家宽候选 (复用 classify_and_export 的候选判定, 但不导出)
    #    家宽候选 = ip-api/mmdb 六信号判 residential/mobile 的节点
    ip_api_info = {}
    all_exit_ips = list({r["exit_ip"] for r in test_results if r.get("exit_ip")})
    if all_exit_ips:
        try:
            ip_api_info = ip_api_batch_lookup(all_exit_ips)
        except Exception as e:
            print(f"[!] 链式复测: ip-api 批量失败 ({e}), 跳过链式复测")
            return test_results

    res_candidates = {}
    for r in test_results:
        if not (r.get("alive") and not r.get("is_stalled")):
            continue
        rec = ip_api_info.get(r.get("exit_ip"), {})
        t, c = classify_network_type(r["exit_ip"], r.get("exit_country_online"),
                                     r.get("exit_asn_online"),
                                     r.get("exit_asn_org_online"), rec or None)
        if t in ("residential", "mobile", RESIDENTIAL_SOFT) and c >= 50:
            # ★ 完整 4 段 key (含凭据指纹): 同目标不同凭据是不同账号,
            #   各自独立链式复测, 互不塌缩、互不代命
            res_candidates[(r["server"].lower(), r["port"], r["proto"],
                            r.get("cred_fp") or "")] = r

    if not res_candidates:
        print("[*] 链式复测: 无家宽候选, 跳过")
        return test_results
    print(f"[*] 链式复测: {len(res_candidates)} 个家宽候选")

    # 2) 选 relay: 全体存活节点里延迟最低、非家宽候选自己 (避免自己套自己)
    alive_sorted = sorted(
        [r for r in test_results if r.get("alive") and not r.get("is_stalled")],
        key=lambda x: x.get("latency_ms", 99999))
    relay_result = None
    for r in alive_sorted:
        if (r["server"].lower(), r["port"], r["proto"], r.get("cred_fp") or "") \
                not in res_candidates:
            relay_result = r
            break
    if not relay_result:
        print("[!] 链式复测: 无可用 relay 节点, 跳过")
        return test_results
    relay_out = relay_result.get("outbound")
    if not relay_out:
        # 重新解析 relay 的 raw 拿 outbound
        p = parse_node_uri(relay_result["raw"])
        if p:
            relay_out = p[0]
    if not relay_out:
        print("[!] 链式复测: relay outbound 构建失败, 跳过")
        return test_results
    # relay 必须剥离 detour (前置链复用时防循环)
    relay_out = dict(relay_out)
    relay_out.pop("detour", None)
    print(f"[*] 链式 relay: {relay_result['proto']} {relay_result['server']}:{relay_result['port']} "
          f"(延迟 {relay_result['latency_ms']}ms)")

    # 3) 家宽候选逐个双跳复测 (注入 CHAIN_RELAY_OUT, test_single_node 自动加 detour)
    #    ★ 原实现是串行 for 循环: 每次约 10-20s。家宽候选由 4 个涨到几十个后,
    #      串行会把 CI 直接拖超时 (50 个 × 15s = 12.5 分钟), 故改为并发。
    #      CHAIN_RELAY_OUT 是进程级只读环境变量, 线程安全。
    CHAIN_MAX_WORKERS = min(16, max(4, len(res_candidates)))
    CHAIN_MAX_CANDIDATES = int(os.environ.get("CHAIN_MAX_CANDIDATES", "160"))
    os.environ["CHAIN_RELAY_OUT"] = json.dumps(relay_out)
    chain_alive, chain_dead = [], []
    try:
        items = []
        for key, r in res_candidates.items():
            ob = r.get("outbound") or (parse_node_uri(r["raw"]) or [None])[0]
            if not ob:
                chain_dead.append(r)
                continue
            items.append((r, (r["raw"], ob, r["server"], r["port"], r["proto"])))
        if len(items) > CHAIN_MAX_CANDIDATES:
            print(f"[!] 链式复测候选 {len(items)} > 上限 {CHAIN_MAX_CANDIDATES}, 按延迟取前 N")
            items.sort(key=lambda x: x[0].get("latency_ms", 99999))
            items = items[:CHAIN_MAX_CANDIDATES]

        def _chain_check(pair):
            r, item = pair
            recheck = test_single_node(item)
            return r, bool(recheck and recheck.get("alive") and not recheck.get("is_stalled"))

        with ThreadPoolExecutor(max_workers=CHAIN_MAX_WORKERS) as ex:
            for r, ok in ex.map(_chain_check, items):
                (chain_alive if ok else chain_dead).append(r)
    finally:
        os.environ.pop("CHAIN_RELAY_OUT", None)

    # 4) 双跳失败的 → 降级普通区 (不从订阅删除, 用户直连场景仍可能可用)
    #    ★ 降级标记按完整 4 段 key 传播: 回填克隆体 raw 不同但 server/port/proto/
    #      凭据相同, 行为一致, 必须同步降级 —— 否则克隆体绕过链式复测直接进家宽区
    failed_keys = {(r["server"].lower(), r["port"], r["proto"], r.get("cred_fp") or "")
                   for r in chain_dead}
    for r in test_results:
        if (r["server"].lower(), r["port"], r["proto"], r.get("cred_fp") or "") in failed_keys:
            r["_chain_failed"] = True

    print(f"[+] 链式复测完成: 双跳可用 {len(chain_alive)} | 双跳失败降级 {len(chain_dead)}")
    return test_results


# ═══════════════════════════════════════════N═══════════════════════
# 阶段 C: 出口 IP 批量情报 (ip-api.com 免费 batch) + 离线兜底
# ═══════════════════════════════════════════N═══════════════════════

def ip_api_batch_lookup(ip_list: list) -> dict:
    """ip-api.com batch (免费 HTTP, ≤100/req, 15 req/min → 1500 IP/min)"""
    info = {}
    session = requests.Session()
    session.trust_env = True  # 直连即可; ip-api.com 免费层全球可达 (CI 无代理/本地走系统代理均可)
    total_batches = (len(ip_list) + IP_API_BATCH_SIZE - 1) // IP_API_BATCH_SIZE
    for bi, i in enumerate(range(0, len(ip_list), IP_API_BATCH_SIZE), 1):
        chunk = ip_list[i:i + IP_API_BATCH_SIZE]
        payload = [{"query": ip} for ip in chunk]
        for attempt in range(3):
            try:
                r = session.post(IP_API_BATCH_URL, json=payload, timeout=20)
                if r.status_code == 200:
                    for rec in r.json():
                        q = rec.get("query")
                        if q:
                            info[q] = rec
                    break
                elif r.status_code == 429:
                    time.sleep(4 + attempt * 3)
                else:
                    time.sleep(2)
            except Exception:
                time.sleep(2)
        if total_batches >= 3 and (bi % 5 == 0 or bi == total_batches):
            print(f"[*] ip-api 进度: 批 {bi}/{total_batches} ({len(info)} IP 已查)")
        time.sleep(IP_API_BATCH_RPS_INTERVAL)
    return info


def offline_ip_lookup(ip: str, country_reader, asn_reader) -> tuple:
    """GeoLite2 离线查询 → (country, asn, org)"""
    country, asn, org = None, None, None
    try:
        c = country_reader.get(ip)
        if c and c.get("country", {}).get("iso_code"):
            country = c["country"]["iso_code"]
    except Exception:
        pass
    try:
        a = asn_reader.get(ip)
        if a:
            asn = a.get("autonomous_system_number")
            org = a.get("autonomous_system_organization", "")
    except Exception:
        pass
    return country, asn, org


def get_rdns(ip: str) -> str:
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(2.0)
        host, _, _ = socket.gethostbyaddr(ip)
        return host.lower()
    except Exception:
        return ""
    finally:
        socket.setdefaulttimeout(old)


def classify_network_type(ip: str, country: str, asn, org: str, ip_api_rec: dict = None) -> tuple:
    """
    返回 (net_type, confidence):
      net_type ∈ {datacenter, residential, mobile, cdn, unknown}
    优先级: ip-api.com hosting/mobile 字段 > CDN 网段 > ASN 白/黑名单 > 名称关键词
    """
    ip_str = str(ip)
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return "unknown", 0

    # 1) CDN / Anycast 网段 (硬判据)
    for net in CLOUDFLARE_IP_NETWORKS:
        if ip_obj in net:
            return "cdn", 100
    for net in CDN_IP_NETWORKS_EXTRA:
        if ip_obj in net:
            return "cdn", 95

    asn_int = None
    if isinstance(asn, int):
        asn_int = asn
    elif isinstance(asn, str) and asn:
        m = re.match(r"AS(\d+)", asn)
        if m:
            asn_int = int(m.group(1))

    org_lower = (org or "").lower()
    hosting_flag = False
    mobile_flag = False
    proxy_flag = False
    rdns_online = ""          # ★ ip-api batch 已返回的 PTR (零额外请求, 原先被丢弃未用)
    hosting_explicit = False  # ip-api 明确返回 hosting=false (而非字段缺失)

    # 2) ip-api.com 在线字段 (最高可信)
    if ip_api_rec:
        hosting_flag = bool(ip_api_rec.get("hosting"))
        mobile_flag = bool(ip_api_rec.get("mobile"))
        proxy_flag = bool(ip_api_rec.get("proxy"))
        hosting_explicit = ("hosting" in ip_api_rec) and (ip_api_rec.get("hosting") is False)
        rdns_online = (ip_api_rec.get("reverse") or "").lower()
        rec_asn = ip_api_rec.get("as") or ""
        m = re.match(r"AS(\d+)", str(rec_asn))
        if m and asn_int is None:
            asn_int = int(m.group(1))
        # ★ asname / org / isp 是同一实体的三个侧面, 必须取并集再匹配关键词:
        #     asname = ASN 注册名, 常是不透明串 ("HINET", "ZENLAYER-AS", "TINYISP-AS")
        #     org    = 注册组织名, 可读 ("Chunghwa Telecom Co. Ltd.")
        #     isp    = 面向用户的品牌名 ("Spectrum", "Vivo", "You Broadband")
        #   原实现 `asname or org or org_lower` 一旦 asname 非空就彻底丢弃 org/isp,
        #   导致诸如 "Tiny Telecom Ltd / Tiny ISP Ltd" 这类只在 org 里带运营商词的
        #   小型民用运营商全部漏判 (下方单元测试已复现)。
        #   并集同时让两侧都更准: 更强的机房关键词否决 + 更强的家宽关键词召回。
        org_lower = " ".join(
            str(x) for x in (ip_api_rec.get("asname"), ip_api_rec.get("org"),
                             ip_api_rec.get("isp"), org) if x).lower()

    if hosting_flag:
        return "datacenter", 90
    # ★ proxy/VPN/Tor 出口标志 (ip-api) — 硬否决家宽/民用
    # 实测 AS62610 Zenlayer (收购 speakeasy DSL legacy 段): hosting=false 但 proxy=true
    # 此类"机房收购家宽段"是假家宽主要形态, rDNS 带 dsl/pppoe 也不能信
    if proxy_flag:
        return "datacenter", 88
    if mobile_flag:
        return "mobile", 85

    # 3) ASN 白/黑名单
    if asn_int:
        if asn_int in DATACENTER_ASNS:
            return "datacenter", 80
        if asn_int in RESIDENTIAL_ASNS:
            return "residential", 82

    # 4) ISP 名称关键词
    if org_lower:
        for kw in IDC_NAME_PATTERNS:
            if kw in org_lower:
                return "datacenter", 70
        for kw in RESIDENTIAL_NAME_PATTERNS:
            if kw in org_lower:
                return "residential", 70

    # 5) rDNS 兜底
    #    ★ 优先用 ip-api 已返回(且零成本)的 PTR, 没有才回落到本地 DNS。
    #      本地 gethostbyaddr 在 CI 上串行且常超时 (2s/IP), 原实现会白白吃掉大量时间。
    rdns = rdns_online or get_rdns(ip_str)
    if rdns:
        for kw in IDC_NAME_PATTERNS:
            if kw in rdns:
                return "datacenter", 60
        for kw in RESIDENTIAL_NAME_PATTERNS:
            if kw in rdns:
                return "residential", 60

    # ───────────────────────────────────────────────────────────────────
    # 6) ★ 家宽召回增强 (本次扩源配套; 解决"真实家宽落到 unknown 被丢进机房区")
    #
    #   根因: 上面 ③~⑤ 依赖 ASN 白名单与关键词。而全球有 ~7 万个 ASN, 其中数千个
    #   是消费者运营商 —— 白名单注定覆盖不全。实测铁证: 印度 AS18207 (YOU Broadband)、
    #   台湾 AS18182 (So-net) 都是 ip-api hosting=false 的真家宽, 却因不在白名单
    #   且关键词不命中而判为 unknown, 最终被算进"非家宽区"白白浪费。
    #
    #   做法: 用 ip-api 的"在线显式无罪推定"代替名单 ——
    #     hosting=false 且 proxy=false 是 ip-api 主动给出的否定结论, 比任何静态表都覆盖面广,
    #     而且它是国家无关的, 天然适配"更多国家的家宽"目标。
    #
    #   安全边界 (误判代价最高的地方必须有显式证据才放行):
    #     · 必须 hosting / proxy 字段真实存在且为 false (字段缺失不算)
    #     · 只要出现任何机房迹象 (云服务器名/rDNS 词) 立即否决
    #     · 分两档评级: 强特征 → residential; 仅"无罪推定" → residential_soft (打"疑似家宽"标记)
    #     · 后续仍要过 ipapi.is 二次否决 / Scamalytics <75 / fraud <90 / 链式双跳 四道闸门
    # ───────────────────────────────────────────────────────────────────
    if ip_api_rec and hosting_explicit and proxy_flag is False and not mobile_flag:
        evidence = (org_lower + " " + rdns).strip()
        # 6a) 机房迹象一票否决
        if any(kw in evidence for kw in IDC_NAME_PATTERNS):
            return "datacenter", 65
        # 6a2) 国家-ASN 错位一票否决 (2026-10-05 新增)
        #     公司名后缀暴露注册国, 与 IP 地理国矛盾 = 跨国转售指纹。
        #     严格家宽区不收跨国转售 (真家宽一定是本国运营商本国 IP)。
        _cc = country or (ip_api_rec.get("countryCode") if ip_api_rec else None)
        if _cc and len(str(_cc)) == 2:
            _cc = str(_cc).upper()
            for suffix, suffix_cc in _FOREIGN_SUFFIX_CC.items():
                if suffix in org_lower and _cc != suffix_cc:
                    return "datacenter", 66
        # 6b) 强家宽指纹 → 与名单词同级的严格家宽
        strong_home = ("pppoe", "adsl", "vdsl", "sdsl", ".dsl", "dsl-", "dsl.",
                       "cable.", "-cable", "dyn-", "dynamic", "pool-", "-pool",
                       "broadband", "ftth", "fttb", "fiber", "dial-up", "home.",
                       "residential", ".home", "customer", "subscriber")
        if any(k in rdns for k in strong_home):
            return "residential", 72
        # 6c) 组织名含电信/宽带词 → 疑似家宽 (soft), 不再直接给严格家宽
        #     2026-10-05 收紧 (用户要求高纯净): "XX Telecom/Telekom" 类名字被大量
        #     VPN 转售商、小型托管商使用 —— 实测 2E Telekomunikasyon / JT TELECOM /
        #     Okay-Telecom 均借此以 71 分混入严格家宽区, 这是误判主因。
        #     真正的民用运营商走 ASN 白名单(③)/强关键词(④/6b) 已能召回;
        #     光凭名字里的 telecom, 最多给 soft。
        consumer_hint = ("telecom", "telekom", "telefonica", "telco", "broadband")
        if any(k in org_lower for k in consumer_hint):
            return RESIDENTIAL_SOFT, 55
        # 6d) 次级判定 (2026-09-29 收紧): "无罪推定"本身不是家宽证据。
        #     ip-api 的 hosting=false 对中小机房 / 未分类 ASN 覆盖不全, 无条件放行
        #     会把大量 VPS 标成"疑似家宽" (实测曾占家宽池八成以上)。
        #     现在要求至少一个弱阳性信号才给 soft, 否则判 unknown ——
        #     家宽专区精确率优先于召回率。
        if RES_SOFT_TIER:
            weak_home = ("dyn", "dynamic", "pool", "dhcp", "cpe", "cable",
                         "fiber", "fibre", "dsl", "ftth", "fttb", "vdsl",
                         "broadband", "residential", "home", "subscriber",
                         "customer", "retail", "wimax", "lte", "5g")
            weak_isp = ("telecom", "telekom", "telefonica", "telco",
                        "broadband", "cabletv", "ftth")
            if any(k in rdns for k in weak_home) or \
               any(k in org_lower for k in weak_isp):
                return RESIDENTIAL_SOFT, 55

    return "unknown", 30


# ═══════════════════════════════════════════N═══════════════════════
# 节点 → 各客户端配置转换
# ═══════════════════════════════════════════N═══════════════════════

def outbound_to_clash(node: dict, name: str) -> dict:
    """sing-box outbound → Clash (Meta/mihomo) proxy dict
    端口跳跃 (Hysteria2 mport) 节点没有 server_port: 用首个区间起始端口,
    ports 字段保留完整跳跃区间 (见下方 hysteria2 分支)。"""
    t = node.get("type")
    server = node.get("server")
    port = node.get("server_port")
    if port is None and node.get("server_ports"):
        # Hysteria2 端口跳跃: server_ports 为 ["20000:30000", "40000:40000"] 列表
        # (或逗号字符串); Clash 取首个区间起始端口, ports 保留完整区间 (见下方分支)
        try:
            first = node["server_ports"]
            if isinstance(first, (list, tuple)):
                first = first[0] if first else ""
            port = int(str(first).split(",")[0].split(":")[0].split("-")[0])
        except (ValueError, IndexError):
            port = None
    if not server or not port:
        return None
    proxy = {"name": name, "server": server, "port": port, "udp": True}

    if t == "vless":
        proxy["type"] = "vless"
        proxy["uuid"] = node["uuid"]
        if node.get("flow"):
            proxy["flow"] = node["flow"]
        tls = node.get("tls") or {}
        if tls.get("reality"):
            proxy["tls"] = True
            proxy["reality-opts"] = {"public-key": tls["reality"]["public_key"]}
            if tls["reality"].get("short_id"):
                proxy["reality-opts"]["short-id"] = tls["reality"]["short_id"]
            proxy["servername"] = tls.get("server_name") or server
            if tls.get("utls"):
                proxy["client-fingerprint"] = tls["utls"].get("fingerprint", "chrome")
        elif tls.get("enabled"):
            proxy["tls"] = True
            proxy["servername"] = tls.get("server_name") or server
            proxy["skip-cert-verify"] = bool(tls.get("insecure"))
            if tls.get("utls"):
                proxy["client-fingerprint"] = tls["utls"].get("fingerprint", "chrome")
        transport = node.get("transport") or {}
        if transport.get("type"):
            proxy["network"] = transport["type"]
            if transport["type"] == "ws":
                proxy["ws-opts"] = {"path": transport.get("path", "/")}
                if transport.get("headers"):
                    proxy["ws-opts"]["headers"] = transport["headers"]
            elif transport["type"] == "grpc":
                proxy["grpc-opts"] = {"grpc-service-name": transport.get("service_name", "")}
            elif transport["type"] == "http":
                proxy["network"] = "h2"
                proxy["h2-opts"] = {"host": transport.get("host", []),
                                    "path": transport.get("path", "/")}
            elif transport["type"] == "httpupgrade":
                proxy["network"] = "httpupgrade"
                proxy["httpupgrade-opts"] = {"path": transport.get("path", "/"),
                                              "headers": {"Host": transport.get("host", "")}}
    elif t == "vmess":
        proxy["type"] = "vmess"
        proxy["uuid"] = node["uuid"]
        proxy["alterId"] = node.get("alter_id", 0)
        proxy["cipher"] = "auto"
        tls = node.get("tls") or {}
        if tls.get("enabled"):
            proxy["tls"] = True
            proxy["servername"] = tls.get("server_name") or server
            proxy["skip-cert-verify"] = bool(tls.get("insecure"))
        transport = node.get("transport") or {}
        if transport.get("type"):
            proxy["network"] = transport["type"]
            if transport["type"] == "ws":
                proxy["ws-opts"] = {"path": transport.get("path", "/")}
                if transport.get("headers"):
                    proxy["ws-opts"]["headers"] = transport["headers"]
            elif transport["type"] == "grpc":
                proxy["grpc-opts"] = {"grpc-service-name": transport.get("service_name", "")}
            elif transport["type"] == "http":
                proxy["network"] = "h2"
                proxy["h2-opts"] = {"host": transport.get("host", []),
                                    "path": transport.get("path", "/")}
    elif t == "trojan":
        proxy["type"] = "trojan"
        proxy["password"] = node["password"]
        tls = node.get("tls") or {}
        proxy["sni"] = tls.get("server_name") or server
        proxy["skip-cert-verify"] = bool(tls.get("insecure"))
        transport = node.get("transport") or {}
        if transport.get("type"):
            proxy["network"] = transport["type"]
            if transport["type"] == "ws":
                proxy["ws-opts"] = {"path": transport.get("path", "/")}
            elif transport["type"] == "grpc":
                proxy["grpc-opts"] = {"grpc-service-name": transport.get("service_name", "")}
    elif t == "shadowsocks":
        proxy["type"] = "ss"
        proxy["cipher"] = node["method"]
        proxy["password"] = node["password"]
    elif t == "hysteria2":
        proxy["type"] = "hysteria2"
        proxy["password"] = node["password"]
        tls = node.get("tls") or {}
        proxy["sni"] = tls.get("server_name") or server
        proxy["skip-cert-verify"] = bool(tls.get("insecure"))
        if node.get("obfs"):
            proxy["obfs"] = node["obfs"].get("type")
            proxy["obfs-password"] = node["obfs"].get("password", "")
        if node.get("server_ports"):
            proxy["ports"] = ",".join(p.replace(":", "-") for p in node["server_ports"])
    elif t == "tuic":
        proxy["type"] = "tuic"
        proxy["uuid"] = node["uuid"]
        proxy["password"] = node["password"]
        tls = node.get("tls") or {}
        proxy["sni"] = tls.get("server_name") or server
        proxy["skip-cert-verify"] = bool(tls.get("insecure"))
        proxy["congestion-controller"] = node.get("congestion_control", "bbr")
        proxy["udp-relay-mode"] = node.get("udp_relay_mode", "native")
        if tls.get("alpn"):
            proxy["alpn"] = tls["alpn"]
    elif t == "anytls":
        proxy["type"] = "anytls"
        proxy["password"] = node["password"]
        tls = node.get("tls") or {}
        proxy["sni"] = tls.get("server_name") or server
        proxy["skip-cert-verify"] = bool(tls.get("insecure"))
    else:
        return None
    return proxy


def outbound_to_v2ray_link(node: dict, name: str) -> str:
    """sing-box outbound → v2rayN 兼容 URI"""
    t = node.get("type")
    # 端口跳跃节点 (hy2 mport): 无 server_port 时取 server_ports 首区间起始端口
    if "server_port" in node:
        port = node["server_port"]
    elif node.get("server_ports"):
        port = int(str(node["server_ports"][0]).split(":")[0])
    else:
        return ""
    server = node["server"]
    tls = node.get("tls") or {}
    transport = node.get("transport") or {}

    if t == "vmess":
        ttype = transport.get("type", "tcp")
        data = {
            "v": "2", "ps": name, "add": server, "port": str(port),
            "id": node["uuid"], "aid": str(node.get("alter_id", 0)),
            "scy": "auto", "net": ttype,
            "type": "none",
            "host": "", "path": "",
            "tls": "tls" if tls.get("enabled") else "",
            "sni": tls.get("server_name", ""),
        }
        if ttype == "ws":
            if transport.get("path"):
                data["path"] = transport["path"]
            if (transport.get("headers") or {}).get("Host"):
                data["host"] = transport["headers"]["Host"]
            if transport.get("max_early_data"):
                data["path"] = (data["path"] or "") + f"?ed={transport['max_early_data']}"
        elif ttype == "grpc":
            if transport.get("service_name"):
                data["path"] = transport["service_name"]
        elif ttype == "http":
            if transport.get("path"):
                data["path"] = transport["path"]
            if transport.get("host"):
                data["host"] = ",".join(transport["host"])
        elif ttype == "httpupgrade":
            if transport.get("path"):
                data["path"] = transport["path"]
            if transport.get("host"):
                data["host"] = transport["host"]
        return "vmess://" + base64.b64encode(json.dumps(data, ensure_ascii=False).encode()).decode()
    if t == "vless":
        q = {}
        ttype = transport.get("type")
        if ttype:
            q["type"] = ttype
            if ttype == "ws":
                if transport.get("path"):
                    q["path"] = transport["path"]
                if (transport.get("headers") or {}).get("Host"):
                    q["host"] = transport["headers"]["Host"]
                if transport.get("max_early_data"):
                    q["ed"] = str(transport["max_early_data"])
            elif ttype == "grpc":
                if transport.get("service_name"):
                    q["serviceName"] = transport["service_name"]
            elif ttype == "http":
                if transport.get("host"):
                    q["host"] = ",".join(transport["host"])
                if transport.get("path"):
                    q["path"] = transport["path"]
            elif ttype == "httpupgrade":
                if transport.get("path"):
                    q["path"] = transport["path"]
                if transport.get("host"):
                    q["host"] = transport["host"]
        if tls.get("reality"):
            q["security"] = "reality"
            q["pbk"] = tls["reality"]["public_key"]
            q["sid"] = tls["reality"].get("short_id", "")
            q["fp"] = (tls.get("utls") or {}).get("fingerprint", "chrome")
            if tls.get("server_name"):
                q["sni"] = tls["server_name"]
        elif tls.get("enabled"):
            q["security"] = "tls"
            if tls.get("server_name"):
                q["sni"] = tls["server_name"]
            if tls.get("alpn"):
                q["alpn"] = ",".join(tls["alpn"])
            if tls.get("utls"):
                q["fp"] = tls["utls"].get("fingerprint", "chrome")
            if tls.get("insecure"):
                q["allowInsecure"] = "1"
        if node.get("flow"):
            q["flow"] = node["flow"]
        query = urllib.parse.urlencode(q)
        return f"vless://{node['uuid']}@{server}:{port}?{query}#{urllib.parse.quote(name)}"
    if t == "trojan":
        q = {"security": "tls"}
        if tls.get("server_name"):
            q["sni"] = tls["server_name"]
        if tls.get("alpn"):
            q["alpn"] = ",".join(tls["alpn"])
        if (tls.get("utls") or {}).get("fingerprint"):
            q["fp"] = tls["utls"]["fingerprint"]
        if tls.get("insecure"):
            q["allowInsecure"] = "1"
        ttype = transport.get("type")
        if ttype:
            q["type"] = ttype
            if ttype == "ws":
                if transport.get("path"):
                    q["path"] = transport["path"]
                if (transport.get("headers") or {}).get("Host"):
                    q["host"] = transport["headers"]["Host"]
                if transport.get("max_early_data"):
                    q["ed"] = str(transport["max_early_data"])
            elif ttype == "grpc":
                if transport.get("service_name"):
                    q["serviceName"] = transport["service_name"]
            elif ttype == "httpupgrade":
                if transport.get("path"):
                    q["path"] = transport["path"]
                if transport.get("host"):
                    q["host"] = transport["host"]
        query = urllib.parse.urlencode(q)
        return f"trojan://{urllib.parse.quote(node['password'])}@{server}:{port}?{query}#{urllib.parse.quote(name)}"
    if t == "shadowsocks":
        # SIP002: userinfo = urlsafe-base64(method:password), ★ 必须保留 padding ("=")
        # 实测: rstrip("=") 砍 padding 后 v2rayN 解析失败 (无 padding 的畸形 base64)
        # urlsafe 字母表 (A-Za-z0-9-_) + "=" 均为 URI 合法字符, 不需再 quote (quote 反而破坏 "=")
        userinfo = base64.urlsafe_b64encode(
            f"{node['method']}:{node['password']}".encode()).decode()
        return f"ss://{userinfo}@{server}:{port}#{urllib.parse.quote(name)}"
    if t == "hysteria2":
        q = {}
        if tls.get("server_name"):
            q["sni"] = tls["server_name"]
        if tls.get("insecure"):
            q["insecure"] = "1"
        if node.get("obfs"):
            q["obfs"] = node["obfs"].get("type", "salamander")
            q["obfs-password"] = node["obfs"].get("password", "")
        if node.get("server_ports"):
            q["mport"] = ",".join(p.replace(":", "-") for p in node["server_ports"])
        query = urllib.parse.urlencode(q)
        return f"hysteria2://{urllib.parse.quote(node['password'])}@{server}:{port}?{query}#{urllib.parse.quote(name)}"
    if t == "tuic":
        q = {
            "congestion_control": node.get("congestion_control", "bbr"),
            "udp_relay_mode": node.get("udp_relay_mode", "native"),
            "alpn": ",".join((tls.get("alpn") or ["h3"])),
        }
        if tls.get("server_name"):
            q["sni"] = tls["server_name"]
        if tls.get("insecure"):
            q["allow_insecure"] = "1"
        query = urllib.parse.urlencode(q)
        return f"tuic://{urllib.parse.quote(node['uuid'])}:{urllib.parse.quote(node['password'])}@{server}:{port}?{query}#{urllib.parse.quote(name)}"
    if t == "anytls":
        q = {}
        if tls.get("server_name"):
            q["sni"] = tls["server_name"]
        if tls.get("insecure"):
            q["insecure"] = "1"
        query = urllib.parse.urlencode(q)
        return f"anytls://{urllib.parse.quote(node['password'])}@{server}:{port}?{query}#{urllib.parse.quote(name)}"
    return ""


def outbound_to_singbox(node: dict, name: str) -> dict:
    n = dict(node)
    n["tag"] = name
    return n


# ═══════════════════════════════════════════N═══════════════════════
# 分类 + 导出
# ═══════════════════════════════════════════N═══════════════════════

def _is_res_like(net_type: str) -> bool:
    """家宽候选判定: 严格家宽 / 移动家宽 / 疑似家宽 都算候选
    (候选 ≠ 入库: 后续仍要过 ipapi.is 否决 / Scamalytics / 链式双跳 三道闸门)"""
    return net_type in ("residential", "mobile", RESIDENTIAL_SOFT)


def scamalytics_fraud_score(ip: str) -> int:
    """Scamalytics 免费风控评分 (HTML 抓取, subs-check 同款方案)
    返回 0-100: 越高越危险; 失败返回 -1 (不参与判定)"""
    try:
        r = DIRECT_SESSION.get(f"https://scamalytics.com/ip/{ip}", timeout=10)
        if r.status_code != 200:
            return -1
        m = re.search(r"Fraud Score:\s*(\d+)", r.text)
        return int(m.group(1)) if m else -1
    except Exception:
        return -1


def ipapi_is_verify(ip: str) -> dict:
    """ipapi.is 免费交叉源 (1000 req/天, 无 key)
    实测对 AS62610 Zenlayer (收购 speakeasy DSL 段伪装家宽) 能给出
    company=Bunny Communications; 对真家宽 (SK Broadband) 给运营商名。
    仅用其 company/asn 字段做家宽候选的二次否决。失败返回 {}"""
    try:
        r = DIRECT_SESSION.get(f"https://api.ipapi.is/?q={ip}", timeout=10)
        if r.status_code != 200:
            return {}
        j = r.json()
        return {"company": j.get("company") or "", "asn": j.get("asn") or "",
                "country": j.get("country") or ""}
    except Exception:
        return {}


# ══════════════════════════════════════════════════════════════════
# VPNGate 家宽情报 (志愿者 VPN 中继 —— 多为家庭宽带/个人服务器)
# ══════════════════════════════════════════════════════════════════
# 定位说明 (诚实边界, 写给维护者):
#   VPNGate 给的是 OpenVPN/L2TP/SSTP 端点, 不是 vless/vmess/trojan 等代理 URI,
#   无法直接进订阅 (Clash/Sing-box/V2Ray 订阅格式均不支持 OpenVPN)。
#   这里产出的是"高纯净家宽 IP 情报": 志愿者 IP 经严格判定确认为家宽后,
#   (1) 其民用 ASN 回填白名单 → 提升主池家宽召回;
#   (2) 落盘 output/vpngate-residential-intel.txt 备查/人工复核。
VPNGATE_API_URL = "http://www.vpngate.net/api/iphone/"
VPNGATE_TOP_N = 60              # 按 Score 取前 N 个志愿者节点
VPNGATE_MIN_SPEED = 10_000_000  # 10 Mbps (Speed 字段单位 bps)


def fetch_vpngate_intel():
    """抓取 VPNGate 志愿者节点并做高纯净家宽筛选.

    返回 (verified, new_asns):
      verified = [(ip, country, asn_int, org, confidence), ...]  # 仅严格家宽
      new_asns = {asn_int, ...}  # verified 中不在白名单的民用 ASN
    任何失败返回 ([], set()), 绝不抛异常阻断主流程.
    """
    try:
        r = http_get(VPNGATE_API_URL, timeout=30)
        if r.status_code != 200:
            print(f"[!] VPNGate API HTTP {r.status_code}, 跳过情报抓取")
            return [], set()
        rows = []
        for ln in r.text.splitlines():
            ln = ln.strip()
            if not ln or ln.startswith("*") or ln.startswith("#"):
                continue
            parts = ln.split(",")
            if len(parts) < 15:
                continue
            try:
                rows.append({
                    "ip": parts[1].strip(),
                    "score": int(parts[2] or 0),
                    "ping": int(parts[3] or -1),
                    "speed": int(parts[4] or 0),
                })
            except (ValueError, IndexError):
                continue
        if not rows:
            print("[!] VPNGate API 返回空, 跳过情报抓取")
            return [], set()
        # 质量过滤: 有测速数据且延迟可用, 按 Score 取前 N
        cand = [x for x in rows
                if x["speed"] >= VPNGATE_MIN_SPEED and x["ping"] >= 0
                and is_ip_literal(x["ip"])]
        cand.sort(key=lambda x: -x["score"])
        cand = cand[:VPNGATE_TOP_N]
        ips = [x["ip"] for x in cand]
        print(f"[*] VPNGate: {len(rows)} 个志愿者节点 → 质量过滤后 {len(ips)} 个候选")
        if not ips:
            return [], set()
        info = ip_api_batch_lookup(ips)
        verified, new_asns = [], set()
        for x in cand:
            rec = info.get(x["ip"])
            if not rec or rec.get("status") != "success":
                continue
            # ★ 用收紧后的同一套判定器 —— 情报纯净度与主池严格家宽同标准
            net, conf = classify_network_type(
                x["ip"], rec.get("countryCode"), rec.get("as"),
                rec.get("asname"), rec)
            if net == "residential":
                asn_int = None
                m = re.match(r"AS(\d+)", str(rec.get("as") or ""))
                if m:
                    asn_int = int(m.group(1))
                org = rec.get("org") or rec.get("isp") or ""
                verified.append((x["ip"], rec.get("countryCode"),
                                 asn_int, org, conf))
                if asn_int and asn_int not in RESIDENTIAL_ASNS:
                    new_asns.add(asn_int)
        # 落盘情报文件 (审计用)
        try:
            ensure_directories()
            p = os.path.join(OUTPUT_DIR, "vpngate-residential-intel.txt")
            with open(p, "w", encoding="utf-8") as f:
                f.write("# VPNGate 高纯净家宽 IP 情报\n")
                f.write(f"# 生成时间: {datetime.now(timezone.utc).isoformat()}\n")
                f.write("# 来源: VPNGate 志愿者 VPN 中继 (http://www.vpngate.net/api/iphone/)\n")
                f.write("# 注意: 这些是 OpenVPN/L2TP 端点 IP, 非代理订阅节点; "
                        "用途 = ASN 白名单回填 + 人工备查\n")
                f.write("# 判定标准: 与主池严格家宽同一套 classify_network_type "
                        "(仅 residential 入选)\n")
                f.write(f"# 本轮验证通过: {len(verified)} 个\n#\n")
                for ip, cc, asn, org, conf in verified:
                    f.write(f"{ip}  {cc}  AS{asn}  {org}  conf={conf}\n")
            print(f"[+] VPNGate 情报落盘: {p} ({len(verified)} 个高纯净家宽 IP)")
        except Exception as e:
            print(f"[!] VPNGate 情报落盘失败: {str(e)[:60]}")
        return verified, new_asns
    except Exception as e:
        print(f"[!] VPNGate 抓取失败 (不影响主流程): {str(e)[:80]}")
        return [], set()


def classify_and_export(test_results: list):
    print("[*] 出口 IP 情报与分类 ...")
    # 收集全部出口 IP
    all_exit_ips = []
    seen_ip = set()
    no_exit_ip = []
    for r in test_results:
        if r["exit_ip"] and r["exit_ip"] not in seen_ip:
            seen_ip.add(r["exit_ip"])
            all_exit_ips.append(r["exit_ip"])
    print(f"[*] 待查询出口 IP: {len(all_exit_ips)} 个 (ip-api.com 批量 {len(test_results)} 节点)")

    ip_api_info = {}
    scam_scores = {}
    if all_exit_ips:
        try:
            est_batches = (len(all_exit_ips) + IP_API_BATCH_SIZE - 1) // IP_API_BATCH_SIZE
            print(f"[*] ip-api 批量: {est_batches} 批 × ~4.2s ≈ {est_batches * 4.2:.0f}s (免费限 15 req/min, 请耐心) ...")
            ip_api_info = ip_api_batch_lookup(all_exit_ips)
            print(f"[+] ip-api.com 批量情报: {len(ip_api_info)}/{len(all_exit_ips)}")
        except Exception as e:
            print(f"[!] ip-api 批量失败, 将全量走离线: {e}")

    country_reader = asn_reader = None
    try:
        country_reader = maxminddb.open_database(os.path.join(RUNTIME_DIR, "Country.mmdb"))
        asn_reader = maxminddb.open_database(os.path.join(RUNTIME_DIR, "ASN.mmdb"))
    except Exception as e:
        print(f"[!] MaxMind 数据库打开失败: {e}")

    nodes = []
    for r in test_results:
        exit_ip = r["exit_ip"]
        online_country = r.get("exit_country_online")
        country = online_country
        asn, org = r.get("exit_asn_online"), r.get("exit_asn_org_online")
        if isinstance(asn, int):
            pass
        elif isinstance(asn, str):
            m = re.match(r"AS(\d+)", asn)
            asn = int(m.group(1)) if m else None

        # 在线情报缺失 → 离线 mmdb 兜底
        if country_reader and (not country or not asn):
            off_c, off_asn, off_org = offline_ip_lookup(exit_ip, country_reader, asn_reader)
            country = country or off_c
            asn = asn or off_asn
            org = org or off_org

        # ★ 出口 IP 查不到国家 (云内网/中转隧道) → 回退用入口服务器 IP 定位国家
        #    (中转节点出口常是内网地址, mmdb 也查不到; 入口国 ≠ 出口国但至少给用户可用地区)
        if (not country or country in ("OTHER", "ZZ")) and r.get("server"):
            srv_ip = r["server"] if is_ip_literal(r["server"]) else resolve_host(r["server"])
            if srv_ip and country_reader:
                off_c, srv_asn, srv_org = offline_ip_lookup(srv_ip, country_reader, asn_reader)
                if off_c and off_c not in ("OTHER", "ZZ"):
                    country = off_c
                    asn, org = asn or srv_asn, org or srv_org

        rec = ip_api_info.get(exit_ip, {})
        net_type, confidence = classify_network_type(
            exit_ip, country, asn, org, rec or None)

        # 无真实出口 IP 的节点: 国家未知, 不入家宽区
        if not exit_ip:
            country = country or "OTHER"

        nodes.append({
            "raw": r["raw"],
            "server": r["server"],
            "port": r["port"],
            "proto": r["proto"],
            "outbound": r.get("outbound"),
            "country": (country or "OTHER").upper(),
            "net_type": net_type,
            "confidence": confidence,
            "exit_ip": exit_ip,
            "asn": asn,
            "org": org,
            "isp": r.get("exit_isp_online") or (rec.get("isp") if rec else ""),
            "latency_ms": r["latency_ms"],
            "speed_bps": r["speed_bps"],
            "mitm_risk": r["mitm_risk"],
            "is_stalled": r["is_stalled"],
        })

    if country_reader:
        country_reader.close()
    if asn_reader:
        asn_reader.close()

    # ── 风险过滤 ──
    # MITM 劫持节点: 高危, 直接丢弃 (204 能通但证书被劫持 = 中间人)
    safe_nodes = [n for n in nodes if not n["mitm_risk"]]
    mitm_dropped = len(nodes) - len(safe_nodes)
    # 断流节点已无 (在 liveness 阶段淘汰), 但 double-check
    safe_nodes = [n for n in safe_nodes if not n["is_stalled"]]
    print(f"[*] MITM 劫持高风险节点已剔除: {mitm_dropped}")

    # ── Scamalytics 风控评分 (免费 HTML, 逐个; 只查家宽候选 + 抽样普通节点) ──
    # 家宽候选: 全查 (宁缺毋滥); 普通节点: 每 IP 查一次 (通常 <= 出口 IP 数)
    scam_candidates = set()
    for n in safe_nodes:
        if _is_res_like(n["net_type"]) and n["exit_ip"]:
            scam_candidates.add(n["exit_ip"])
    if scam_candidates:
        print(f"[*] Scamalytics 风控评分: 查询 {len(scam_candidates)} 个家宽候选出口 IP ...")
        def _scam(ip):
            return ip, scamalytics_fraud_score(ip)
        with ThreadPoolExecutor(max_workers=6) as ex:
            for ip, score in ex.map(_scam, scam_candidates):
                scam_scores[ip] = score
        got = sum(1 for v in scam_scores.values() if v >= 0)
        print(f"[+] Scamalytics 评分获得: {got}/{len(scam_candidates)}")

    # ── ipapi.is 交叉核验 (只查家宽候选, 免费 1000 次/天) ──
    # ip-api 判 hosting/proxy 也有漏 (伪装家宽: 收购 DSL 段的云边网络)。
    # ipapi.is 独立数据源: company 含 IDC 词 → 否决家宽
    ipapi_verify = {}
    verify_candidates = set()
    for n in safe_nodes:
        if _is_res_like(n["net_type"]) and n["exit_ip"]:
            verify_candidates.add(n["exit_ip"])
    if verify_candidates:
        print(f"[*] ipapi.is 交叉核验: {len(verify_candidates)} 个家宽候选 ...")
        def _verify(ip):
            return ip, ipapi_is_verify(ip)
        with ThreadPoolExecutor(max_workers=4) as ex:
            for ip, info in ex.map(_verify, verify_candidates):
                ipapi_verify[ip] = info
        # 否决: company/asn 含机房词
        vetoed = 0
        for n in safe_nodes:
            if not _is_res_like(n["net_type"]):
                continue
            info = ipapi_verify.get(n["exit_ip"]) or {}
            comp_asn = (info.get("company", "") + " " + info.get("asn", "")).lower()
            if any(kw in comp_asn for kw in (
                "zenlayer", "bunny", "cloudflare", "akamai", "fastly",
                "amazon", "google llc", "microsoft", "digitalocean", "vultr",
                "hetzner", "ovh", "contabo", "leaseweb", "datacamp",
                "serverius", "clouvider", "m247", "gcore", "g-core",
                "choopa", "linode", "alibaba", "tencent", "huawei cloud",
                # ★ 2026-09-30 补 (审计单 #10 实证): 枚举大厂名单永远追不完,
                #   漏掉的是"名字里就写着机房"的中小托管商。实测案例:
                #   exit 87.192.47.4 (GB) ip-api 判 hosting=False、org 是
                #   "Imagine Communications Group Limited" 看着像民用运营商,
                #   但 ipapi.is 给出 company="TakeHost OU" (AS204785) ——
                #   这就是家宽专区里混进机房的典型, 现已一票否决。
                "takehost", "hosting", "host ", " server", "servers",
                # ★ 2026-10-05 补 (家宽审计实证的转售商/小托管商; ASN 黑名单为主防线,
                #   这里是纵深 backup, 防换 ASN 马甲)
                "hivelocity", "2e telekomunikasyon", "jt telecom", "okay-telecom",
                "park-web", "private customer",
                #   注意: 不要用 "colo" —— 会误伤 Colombia / Colorado 等地理名;
                #   同理 "rack" 仅在末尾匹配更稳妥, 这里用 "rackspace" 精确名。
                "vps", "dedicated", "datacenter", "data center", "colocation",
                "rackspace", "cloud", "voxility", "psychz", "quadranet",
            )):
                n["net_type"] = "datacenter"
                n["confidence"] = 85
                vetoed += 1
        if vetoed:
            print(f"[*] ipapi.is 否决假家宽: {vetoed} 个 (云商收购家宽段伪装)")

    # 风险分 >= 75 的家宽候选降级为普通 (fraud 池/被滥用 IP 绝不入家宽区)
    downgraded = 0
    for n in safe_nodes:
        sc = scam_scores.get(n["exit_ip"], -1)
        n["fraud_score"] = sc
        # ★ 挂载原始情报快照, 供 output/residential-audit.txt 审计导出。
        #   判定结论必须可复现 —— 否则用户拿到一个标着"家宽"的节点,
        #   除了盲信没有任何办法验证, 这正是"家宽是不是真的"争议的根源。
        n["_audit_ipapi"] = ip_api_info.get(n["exit_ip"]) or {}
        n["_audit_ipapi_is"] = ipapi_verify.get(n["exit_ip"]) or {}
        if _is_res_like(n["net_type"]) and sc >= 75:
            n["net_type"] = "datacenter"  # 高 fraud 分: 大概率代理池滥用 IP
            n["confidence"] = 60
            downgraded += 1
    if downgraded:
        print(f"[*] 高 fraud 分 (≥75) 家宽候选降级: {downgraded} 个")

    # ── 去重 (同出口IP+端口 只留最快) ──
    best_by_key = {}
    for n in safe_nodes:
        key = f"{n['exit_ip']}:{n['port']}" if n["exit_ip"] else f"{n['server']}:{n['port']}|{n['raw'][:64]}"
        cur = best_by_key.get(key)
        if not cur or n["latency_ms"] < cur["latency_ms"]:
            best_by_key[key] = n
    unique_nodes = list(best_by_key.values())
    dup_dropped = len(safe_nodes) - len(unique_nodes)
    print(f"[*] 去重: {len(safe_nodes)} → {len(unique_nodes)} (剔除重复 {dup_dropped})")

    # 去重: 出口IP+端口 唯一化, 家宽区严格防同IP刷屏
    # ★ 链式复测 (chain_retest) 双跳失败的家宽候选 → 不进家宽专区 (降级普通)
    chain_failed_raws = set()
    for r in test_results:
        if r.get("_chain_failed"):
            chain_failed_raws.add(r.get("raw"))
    residential = []
    res_seen_ip = {}
    for n in unique_nodes:
        # 严格家宽/移动家宽需达到原置信度门槛; 疑似家宽为次级档但其 55 分是另一套标度, 单列放行
        if not _is_res_like(n["net_type"]):
            continue
        if n["confidence"] < 60 and n["net_type"] != RESIDENTIAL_SOFT:
            continue
        if n.get("raw") in chain_failed_raws:
            n["net_type"] = "datacenter"
            n["confidence"] = 70
            continue
        # ★ 原逻辑: 同一出口 IP 全球只留 1 个节点。过于浪费 ——
        #   一条家用宽带上常同时跑多个端口/多个协议的公益节点, 全被丢掉。
        #   放宽为同一出口 IP 最多保留 MAX_RES_PER_IP 个 (默认 3), 仍能有效防刷屏。
        if n["exit_ip"]:
            cnt = res_seen_ip.get(n["exit_ip"], 0)
            if cnt >= MAX_RES_PER_IP:
                continue
            res_seen_ip[n["exit_ip"]] = cnt + 1
            residential.append(n)
    # fraud 分极高 (≥90) 的节点整体剔除 (任何区都不要)
    before_total = len(unique_nodes)
    unique_nodes = [n for n in unique_nodes if not (0 <= n.get("fraud_score", -1) >= 90)]
    residential = [n for n in residential if not (0 <= n.get("fraud_score", -1) >= 90)]
    if len(unique_nodes) < before_total:
        print(f"[*] 极高危节点 (fraud≥90) 剔除: {before_total - len(unique_nodes)} 个")

    non_residential = [n for n in unique_nodes if n not in residential]
    print(f"[*] 家宽/移动网络节点: {len(residential)} | 普通(机房/CDN): {len(non_residential)}")

    # ── 家宽漏斗诊断 (便于后续调参, 不做任何改动) ──
    _degree = {}
    for n in unique_nodes:
        _degree[n["net_type"]] = _degree.get(n["net_type"], 0) + 1
    print("[*] 节点类型分布: " + ", ".join(f"{k}={v}" for k, v in
                                          sorted(_degree.items(), key=lambda x: -x[1])))
    _res_cc = {}
    for n in residential:
        _res_cc[n["country"]] = _res_cc.get(n["country"], 0) + 1
    if _res_cc:
        print(f"[*] 家宽国家分布 ({len(_res_cc)} 国): " + ", ".join(
            f"{k}={v}" for k, v in sorted(_res_cc.items(), key=lambda x: -x[1])))
    _soft = sum(1 for n in residential if n["net_type"] == RESIDENTIAL_SOFT)
    if _soft:
        print(f"[*] 其中次级判定(疑似家宽): {_soft} 个 "
              f"(关闭: RES_SOFT_TIER=0)")
    elif RES_SOFT_TIER:
        print("[*] 次级判定(疑似家宽) 本轮 0 命中")

    # 排序: 家宽在前, 延迟升序
    unique_nodes.sort(key=lambda x: (0 if x in residential else 1, x["latency_ms"]))
    residential.sort(key=lambda x: x["latency_ms"])
    non_residential.sort(key=lambda x: x["latency_ms"])
    # ★ 链式复测双跳失败的家宽 → 降级普通区 (v2rayN 链式场景不可靠)
    #    保留在总订阅/国家订阅里 (直连场景仍可用), 只是退出家宽专区

    # 重建 outbound: 优先用测活阶段实际验证过的 outbound (r["outbound"]),
    # 同一 raw 可能解析出多个 outbound (如 ss 多用户), parsed[0] 未必是测过的那个;
    # 剥离测试专用字段 (detour 等绝不入订阅)
    for n in unique_nodes:
        ob = n.get("outbound")
        if ob:
            ob = dict(ob)
        else:
            parsed = parse_node_uri(n["raw"])
            ob = parsed[0] if parsed else None
        if ob:
            ob.pop("detour", None)
            n["outbound"] = ob
        else:
            n["outbound"] = None

    return unique_nodes, residential, non_residential


def make_node_name(item, idx, force_residential=False):
    cc = item["country"]
    flag = get_country_flag(cc)
    cname = COUNTRY_NAMES.get(cc, cc)
    if force_residential:
        # 家宽专区内: 严格家宽打 (家宽), 移动网络打 (移动家宽), 次级判定打 (疑似家宽)
        is_res = True
    else:
        is_res = _is_res_like(item["net_type"]) and item["confidence"] >= 60
    tag = ""
    if is_res:
        if item["net_type"] == RESIDENTIAL_SOFT:
            tag = " (疑似家宽)"
        elif item["net_type"] == "mobile":
            tag = " (移动家宽)"
        else:
            tag = " (家宽)"
    # Scamalytics 风控分: 高风险节点名内标注 (R分数), 低危不标 (保持简洁)
    fraud = item.get("fraud_score", -1)
    risk_tag = f" R{fraud}" if 0 <= fraud < 75 and fraud >= 40 else (" ⚠R" if fraud >= 75 else "")
    return f"{flag} {cname} {idx:02d}{tag}{risk_tag} - xiaohe"


def export_residential_audit(residential, filepath):
    """导出家宽判定审计单 —— 让"家宽"这个标签可被独立复核, 而非只能盲信。

    背景: 订阅里一个节点标着"(家宽)", 用户看到的却是 URI 里的入口 IP
    (可能是 Cloudflare CDN 反代), 无从判断出口到底是什么网络, 于是只能怀疑
    "家宽根本不是真的"。本文件把判定所依据的原始情报全部摊开, 任何人都可以
    拿 exit_ip 去 ip-api / scamalytics / bgp.he.net 自行复核。
    """
    lines = [
        "=" * 78,
        "家宽判定审计单 / Residential IP Audit",
        f"生成时间: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "=" * 78,
        "",
        "说明:",
        "  · exit_ip  = sing-box 实测穿透后获取的真实出口 IP (判定的唯一依据)",
        "  · server   = 订阅 URI 里写的入口地址, 可能是 CDN 反代, 与出口无关",
        "  · 判定档位 :",
        "      residential      = 严格家宽 (rDNS/ASN 白名单等强特征)",
        "      residential_soft = 疑似家宽 (仅弱阳性信号, 可能混有小型 IDC)",
        "      mobile           = 移动网络",
        "  · hosting/proxy/mobile 为 ip-api.com 原始字段; fraud 为 Scamalytics 风控分",
        "    (越高越危险, >=75 会降级出家宽区, >=90 全池剔除)",
        "  · 复核建议 : 把 exit_ip 贴进 https://scamalytics.com/ip/<IP> 与",
        "               https://bgp.he.net/ip/<IP> 看 ASN 归属是否真是民用运营商",
        "",
        f"本轮家宽节点数: {len(residential)}",
        "",
    ]
    for i, n in enumerate(residential, 1):
        rec = n.get("_audit_ipapi") or {}
        vrf = n.get("_audit_ipapi_is") or {}
        tier = {"residential": "严格家宽",
                "residential_soft": "疑似家宽",
                "mobile": "移动网络"}.get(n["net_type"], n["net_type"])
        lines += [
            f"[{i}] {n.get('country', '??')}  {tier}  置信度 {n.get('confidence', 0)}",
            f"     exit_ip : {n.get('exit_ip') or '(未知)'}",
            f"     server  : {n.get('server')}:{n.get('port')}  ({n.get('proto')})",
            f"     ASN     : {rec.get('as') or '-'}",
            f"     ISP     : {rec.get('isp') or '-'}",
            f"     ORG     : {rec.get('org') or '-'}",
            f"     ip-api  : hosting={rec.get('hosting')} proxy={rec.get('proxy')} "
            f"mobile={rec.get('mobile')} reverse={rec.get('reverse') or '-'}",
            f"     ipapi.is: company={vrf.get('company') or '-'} asn={vrf.get('asn') or '-'}",
            f"     fraud   : {n.get('fraud_score', -1)}  (-1 = 未取到评分)",
            "",
        ]
    if not residential:
        lines += ["(本轮无节点通过家宽判定)", ""]
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        print(f"[+] 家宽审计单已导出: {filepath} ({len(residential)} 条)")
    except Exception as e:
        print(f"[!] 家宽审计单导出失败: {e}")


def export_all(unique_nodes, residential, non_residential):
    ensure_directories()

    def build_group(nodes_list, force_res=False):
        links, proxies, sb_nodes = [], [], []
        for idx, item in enumerate(nodes_list, start=1):
            name = make_node_name(item, idx, force_res)
            ob = item["outbound"]
            if not ob:
                continue
            link = outbound_to_v2ray_link(ob, name)
            if link:  # 空链接 (未知协议/缺端口) 不写入订阅, 避免客户端出现空节点
                links.append(link)
            cp = outbound_to_clash(ob, name)
            if cp:
                proxies.append(cp)
            sb_nodes.append(outbound_to_singbox(ob, name))
        return links, proxies, sb_nodes

    # 1) 全量
    all_links, all_proxies, all_sb = build_group(unique_nodes)
    with open(os.path.join(OUTPUT_DIR, "v2ray.txt"), "w", encoding="utf-8") as f:
        f.write(base64.b64encode("\n".join(all_links).encode()).decode())
    export_clash_yaml(all_proxies, os.path.join(OUTPUT_DIR, "clash.yaml"))
    export_singbox_json(all_sb, os.path.join(OUTPUT_DIR, "singbox.json"))

    # 2) 家宽总订阅
    # ★ 2026-09-29: 本轮 0 命中时保留上一版 (不覆盖手动验证文件, 不删除已有 clash/singbox)
    #    避免池子波动导致订阅被清空; 有命中时正常覆盖更新
    res_links, res_proxies, res_sb = build_group(residential, force_res=True)
    if res_links:
        with open(os.path.join(OUTPUT_DIR, "residential.txt"), "w", encoding="utf-8") as f:
            f.write(base64.b64encode("\n".join(res_links).encode()).decode())
        if res_proxies:
            export_clash_yaml(res_proxies, os.path.join(OUTPUT_DIR, "residential-clash.yaml"))
            export_singbox_json(res_sb, os.path.join(OUTPUT_DIR, "residential-singbox.json"))
        else:
            for fn in ("residential-clash.yaml", "residential-singbox.json"):
                p = os.path.join(OUTPUT_DIR, fn)
                if os.path.exists(p):
                    os.remove(p)
    else:
        print("[*] 本轮家宽 0 命中, 保留上一版 residential.* (不覆盖、不删除)")

    # 2b) ★ 家宽判定审计单 (可复现证据) —— 无论本轮是否命中都导出
    #     目的: 判定结论可被任何人拿原始 IP 去第三方独立复核, 而不是只能盲信。
    export_residential_audit(residential, os.path.join(OUTPUT_DIR, "residential-audit.txt"))

    # 3) 按国家 - 普通区
    shutil.rmtree(COUNTRY_DIR, ignore_errors=True)
    os.makedirs(COUNTRY_DIR, exist_ok=True)
    by_cc = {}
    for n in non_residential:
        by_cc.setdefault(n["country"], []).append(n)
    for cc, lst in by_cc.items():
        l, p, s = build_group(lst)
        with open(os.path.join(COUNTRY_DIR, f"{cc}.txt"), "w", encoding="utf-8") as f:
            f.write(base64.b64encode("\n".join(l).encode()).decode())
        export_clash_yaml(p, os.path.join(COUNTRY_DIR, f"clash-{cc}.yaml"))
        export_singbox_json(s, os.path.join(COUNTRY_DIR, f"singbox-{cc}.json"))

    # 4) 按国家 - 家宽区
    shutil.rmtree(RESIDENTIAL_COUNTRY_DIR, ignore_errors=True)
    os.makedirs(RESIDENTIAL_COUNTRY_DIR, exist_ok=True)
    res_by_cc = {}
    for n in residential:
        res_by_cc.setdefault(n["country"], []).append(n)
    for cc, lst in res_by_cc.items():
        l, p, s = build_group(lst, force_res=True)
        with open(os.path.join(RESIDENTIAL_COUNTRY_DIR, f"{cc}.txt"), "w", encoding="utf-8") as f:
            f.write(base64.b64encode("\n".join(l).encode()).decode())
        export_clash_yaml(p, os.path.join(RESIDENTIAL_COUNTRY_DIR, f"clash-{cc}.yaml"))
        export_singbox_json(s, os.path.join(RESIDENTIAL_COUNTRY_DIR, f"singbox-{cc}.json"))

    print(f"[*] 导出完毕: 全量 {len(all_links)} | 家宽 {len(res_links)}")
    return len(all_links), len(res_links)


def export_clash_yaml(clash_proxies, filepath):
    names = [p["name"] for p in clash_proxies]
    config = {
        "port": 7890,
        "socks-port": 7891,
        "allow-lan": True,
        "mode": "rule",
        "log-level": "info",
        "proxies": clash_proxies,
        "proxy-groups": [
            {"name": "PROXIES", "type": "select", "proxies": ["AUTO"] + names},
            {"name": "AUTO", "type": "url-test", "url": "https://www.gstatic.com/generate_204",
             "interval": 300, "proxies": names},
        ],
        "rules": ["MATCH,PROXIES"],
    }
    with open(filepath, "w", encoding="utf-8") as f:
        yaml.dump(config, f, allow_unicode=True, sort_keys=False, default_flow_style=False)


def export_singbox_json(sb_nodes, filepath):
    names = [n["tag"] for n in sb_nodes]
    outbounds = sb_nodes + [
        {"type": "selector", "tag": "select", "outbounds": ["auto"] + names},
        {"type": "urltest", "tag": "auto", "outbounds": names,
         "url": "https://www.gstatic.com/generate_204"},
        {"type": "direct", "tag": "direct"},
        {"type": "block", "tag": "block"},
    ]
    config = {"log": {"level": "warn"},
              "outbounds": outbounds}
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)


# ═══════════════════════════════════════════N═══════════════════════
# README 生成
# ═══════════════════════════════════════════N═══════════════════════

def update_readme(total_count, res_count):
    repo_name = os.environ.get("GITHUB_REPOSITORY", "cheshi888/freesub-v2").strip()
    cache_bust = ""
    # 私有化部署 Worker 脚本里的仓库参数 (默认值兜底)
    try:
        owner, repo = repo_name.split("/", 1)
    except ValueError:
        owner, repo = "cheshi888", "freesub-v2"

    def count_file(path):
        if not os.path.exists(path):
            return 0
        try:
            with open(path, "r", encoding="utf-8") as f:
                c = f.read().strip()
                if not c:
                    return 0
                decoded = base64.b64decode(c).decode("utf-8", errors="ignore")
                return len([ln for ln in decoded.splitlines() if ln.strip()])
        except Exception:
            return 0

    res_counts, normal_counts = {}, {}
    for d, store in ((RESIDENTIAL_COUNTRY_DIR, res_counts), (COUNTRY_DIR, normal_counts)):
        if os.path.exists(d):
            for fn in os.listdir(d):
                if fn.endswith(".txt"):
                    cnt = count_file(os.path.join(d, fn))
                    if cnt > 0:
                        store[fn[:-4]] = cnt

    def table_rows(counts, sub):
        rows = []
        for cc in sorted(counts, key=lambda x: counts[x], reverse=True):
            flag = get_country_flag(cc)
            name = COUNTRY_NAMES.get(cc, cc)
            cnt = counts[cc]
            v2 = f"[CDN 直链](https://cdn.jsdelivr.net/gh/{repo_name}@main/output/{sub}/{cc}.txt) · [Raw 直链](https://raw.githubusercontent.com/{repo_name}/main/output/{sub}/{cc}.txt)"
            cl = f"[CDN 直链](https://cdn.jsdelivr.net/gh/{repo_name}@main/output/{sub}/clash-{cc}.yaml) · [Raw 直链](https://raw.githubusercontent.com/{repo_name}/main/output/{sub}/clash-{cc}.yaml)"
            sb = f"[CDN 直链](https://cdn.jsdelivr.net/gh/{repo_name}@main/output/{sub}/singbox-{cc}.json) · [Raw 直链](https://raw.githubusercontent.com/{repo_name}/main/output/{sub}/singbox-{cc}.json)"
            rows.append(f"| {flag} {name} | {cnt} | {v2} | {cl} | {sb} |")
        return "\n".join(rows) if rows else "| 暂无可用节点 | 0 | - | - | - |"

    res_table = table_rows(res_counts, "residential-by-country")
    normal_table = table_rows(normal_counts, "by-country")

    readme = f"""# 🚀 免费节点自动测活订阅池 (含真实家宽/住宅IP甄选)

> 👤 **定制规范命名**: 所有订阅节点均重命名为 `国旗 地区 序号 (家宽) - xiaohe`
> ⚡ **真实可用保障**: 所有节点由 `sing-box v{SINGBOX_VERSION}` 内核建立实际代理隧道, 完成真实 HTTPS 双向传输握手 + 出口 IP 穿透验证 + Cloudflare 限速下载断流检测 + TLS 证书校验 (MITM 劫持识别), 拒绝虚假通畅、断流节点与高危劫持节点。
> 🛡️ **全协议支持**: VLESS (Reality/Vision) · VMESS · Trojan · Shadowsocks · Hysteria2 · TUIC · AnyTLS

---

## 📌 全部节点总订阅链接

| 客户端 / 格式类型 | 节点总数 | 免翻 CDN 订阅直链 (国内直连) | 官方原生 Raw 直链 (开启代理) |
| :--- | :---: | :--- | :--- |
| 🚀 **Clash (YAML 格式)** | `{total_count}` | [免翻 CDN 直链](https://cdn.jsdelivr.net/gh/{repo_name}@main/output/clash.yaml) | [官方 Raw 直链](https://raw.githubusercontent.com/{repo_name}/main/output/clash.yaml) |
| ⚡ **V2RayN (Base64 格式)** | `{total_count}` | [免翻 CDN 直链](https://cdn.jsdelivr.net/gh/{repo_name}@main/output/v2ray.txt) | [官方 Raw 直链](https://raw.githubusercontent.com/{repo_name}/main/output/v2ray.txt) |
| 📦 **sing-box (JSON 格式)** | `{total_count}` | [免翻 CDN 直链](https://cdn.jsdelivr.net/gh/{repo_name}@main/output/singbox.json) | [官方 Raw 直链](https://raw.githubusercontent.com/{repo_name}/main/output/singbox.json) |

---

## 🏠 按照家宽分类节点订阅 (住宅 IP 专区)

> **标注规则**: `(家宽)` = 严格家宽 · `(移动家宽)` = 民用移动网络 · `(疑似家宽)` = 次级判定 (详见下方第 ⑦ 条)
>
> **家宽判定七重信号**: ① ip-api.com `hosting` 字段 ② `mobile` 移动网络字段 ③ Cloudflare/主流 CDN Anycast 网段比对 ④ MaxMind GeoLite2 ASN 白/黑名单 (覆盖 80+ 国家主流民用运营商) ⑤ rDNS/ISP 组织名特征 ⑥ Scamalytics 风控评分复核 (fraud ≥75 降级、≥90 剔除) ⑦ **ip-api 显式 `hosting=false` 且 `proxy=false` 的运营商-无罪推定层** —— 静态白名单注定覆盖不全 (全球数万个消费者运营商), 这一层与国家无关, 用于把白名单漏掉的小众国家民用宽带捞回来; 因其只有"无机房证据"这一个弱信号, 命中节点以 `(疑似家宽)` 单独标注, 与严格家宽区分。
>
> ### ⚠️ 关于家宽数量，请先读这段
>
> **免费公开节点池里真正的家宽极其稀少，请按真实预期使用。** 2026-09-29 CI 实测：785 个通过全部测活的节点中 `datacenter=714 / cdn=24 / unknown=44`，**家宽仅 3 个（约 0.4%）**。这不是漏判，而是免费池的真实构成——公益节点绝大多数跑在廉价 VPS / 云主机上。
>
> **判据看的是出口 IP，不是订阅里写的地址**：URI 里的 `server` 常常是 CDN 反代入口（例如 Cloudflare `108.162.x.x`），与真实出口无关。本项目依据的是 sing-box 实测穿透后取到的**真实出口 IP**（`exit_ip`）。所以"订阅里写着 Cloudflare 的 IP、却标着家宽"是 CDN 入口 + 家宽出口的正常组合，并非误判。
>
> **判定结论可自查，不必盲信**：每轮生成 [`output/residential-audit.txt`](output/residential-audit.txt)，逐条列出每个家宽节点的 `exit_ip` / ASN / ISP / ORG / ip-api `hosting·proxy·mobile` / ipapi.is 交叉结果 / Scamalytics 风控分 / 判定档位。把 `exit_ip` 贴进 <https://scamalytics.com/ip/…> 或 <https://bgp.he.net/ip/…> 即可独立复核。
>
> **已知局限**（调参解决不了）：
> - `(疑似家宽)` 只基于弱信号，其中必然混有小型 IDC。电信公司同样卖 VPS 和机柜，组织名含 telecom 不能证明该 IP 是家庭宽带。
> - ip-api 的 `hosting` 字段对小型运营商覆盖不全，双向误差都存在。
> - 需要**稳定且量大**的真家宽，免费聚合源做不到，只能接住宅代理上游（付费的 rotary residential / 静态住宅 IP）。
>
> 三级候选一律还要通过 **ipapi.is 交叉源二次否决 + Scamalytics 欺诈分 + 链式双跳复测** 三道闸门才入库。排除所有云主机/数据中心/CDN 任播, 保留真实民用宽带与移动网络。

| 家宽地区 | 节点数 | V2RayN 专属订阅 | Clash 专属订阅 | sing-box 专属订阅 |
| :--- | :---: | :---: | :---: | :---: |
{res_table}

---

## 🗺️ 按照国家分类节点订阅 (非家宽/数据中心节点)

| 地区/国家 | 节点数 | V2RayN 专属订阅 | Clash 专属订阅 | sing-box 专属订阅 |
| :--- | :---: | :---: | :---: | :---: |
{normal_table}

---

## 🔒 私有仓库（Private）无感免翻订阅方案 (基于 Cloudflare Workers)

> 如果你希望将本 GitHub 仓库设置为 **Private (私有仓库)** 保护节点资产，外部客户端无法直接拉取原生 Raw 或公共 CDN 链接，可以通过以下 Cloudflare Worker 搭建轻量级私密网关反代：

### 1. 获取 GitHub 永久个人令牌 (PAT)
1. 进入 GitHub -> **Settings** -> **Developer Settings** -> **Personal access tokens (classic)**。
2. 点击 **Generate new token (classic)**，勾选 `repo` 权限，有效期设为 `No expiration`（永不过期）。
3. 复制保存生成的以 `ghp_` 开头的 Token。

### 2. 部署 Cloudflare Worker
登录 Cloudflare Dashboard，创建一个新的 Worker，复制以下脚本粘贴并部署（把 `OWNER`/`REPO`/`GITHUB_TOKEN` 改成你自己的）：

```javascript
export default {{
  async fetch(request) {{
    const GITHUB_TOKEN = "ghp_你的GitHub永久访问令牌";
    const OWNER = "{owner}";
    const REPO = "{repo}";
    const BRANCH = "main";

    const url = new URL(request.url);
    const filePath = "output" + url.pathname;
    const ghUrl = "https://raw.githubusercontent.com/" + OWNER + "/" + REPO + "/" + BRANCH + "/" + filePath;

    const res = await fetch(ghUrl, {{
      headers: {{
        "Authorization": "token " + GITHUB_TOKEN,
        "User-Agent": "Cloudflare-Worker"
      }}
    }});

    if (!res.ok) {{
      return new Response("Not Found", {{ status: 404 }});
    }}

    return new Response(await res.text(), {{
      headers: {{
        "Content-Type": "text/plain; charset=utf-8",
        "Cache-Control": "no-cache"
      }}
    }});
  }}
}}
```

### 3. 私有订阅链接映射方式
部署后 Worker 会分配一个专属域名（例如 `my-sub.yourname.workers.dev`），你的客户端可以直接无感订阅：
* **总 V2RayN 订阅**: `https://你的域名.workers.dev/v2ray.txt`
* **总 Clash 订阅**: `https://你的域名.workers.dev/clash.yaml`
* **总 sing-box 订阅**: `https://你的域名.workers.dev/singbox.json`
* **台湾家宽 V2RayN**: `https://你的域名.workers.dev/residential-by-country/TW.txt`
* **香港家宽 Clash**: `https://你的域名.workers.dev/residential-by-country/clash-HK.yaml`
* **日本家宽 sing-box**: `https://你的域名.workers.dev/residential-by-country/singbox-JP.json`

---

## ⭐ 项目热度

[![Star History Chart](https://api.star-history.com/svg?repos={repo_name}&type=Date)](https://star-history.com/#{repo_name}&Date)

---

## 🛠️ 项目使用说明
1. **自动更新机制**：GitHub Actions 每 6 小时全自动运行并刷新上述全部订阅与数据。
2. **订阅源规模**：当前接入 {len(SOURCE_URLS)} 个公开订阅源 —— 基础 14 个 + 大容量聚合/分国家/分协议源，用于最大化家宽 IP 的命中基数（家宽在免费池中是稀缺资源，扩大样本量是最直接的提升手段）。单个源失效自动跳过，不影响整体。
3. **测活标准**：节点必须通过 ① 端口预检 ② sing-box 实际隧道 3 个 generate_204 探测 ③ 真实出口 IP 穿透获取 ④ 限时下载测速 (吞吐 ≥ 70KB/s 断流检测) ⑤ TLS 证书校验非 MITM，方可入库。
4. **多客户端兼容**：Clash / v2rayN / sing-box 全格式订阅。
"""
    with open(os.path.join(BASEDIR, "README.md"), "w", encoding="utf-8") as f:
        f.write(readme)
    print(f"[+] README.md 更新完毕: 总节点 {total_count}, 家宽 {res_count}")


# ═══════════════════════════════════════════N═══════════════════════
# 主流程
# ═══════════════════════════════════════════N═══════════════════════

def cred_fingerprint(outbound: dict, proto: str) -> str:
    """连接凭据指纹: 同一 server:port:proto 下区分不同凭据/配置。
    用于测前去重与测后回填的完整 key (server, port, proto, fingerprint)。
    注意: 只含"身份凭据", 不含 TLS/SNI/传输等参数 —— 相同凭据不同传输的
    节点会被视为同一组 (回填时 raw 不同但凭据相同, 服务端行为一致)。"""
    try:
        if proto == "vless":
            return f"{outbound.get('uuid','')}"
        if proto == "vmess":
            return f"{outbound.get('uuid','') or outbound.get('user_id','')}"
        if proto == "trojan":
            return f"{outbound.get('password','')}"
        if proto == "shadowsocks":
            return f"{outbound.get('method','')}|{outbound.get('password','')}"
        if proto == "hysteria2":
            return f"{outbound.get('password','') or ''}|{outbound.get('server_ports','')}"
        if proto == "tuic":
            return f"{outbound.get('uuid','')}|{outbound.get('password','')}"
        if proto == "anytls":
            return f"{outbound.get('password','')}"
        return json.dumps({k: v for k, v in outbound.items()
                          if k in ("uuid", "password", "user_id", "method")}, sort_keys=True)
    except Exception:
        return ""  # 指纹失败 → 不合并 (宁慢不错)


def main():
    t_start = time.time()
    print(f"==== 免费节点测活订阅池 v2 · 启动于 {datetime.now(timezone.utc).isoformat()} ====")
    ensure_directories()
    setup_environment()

    # 1.5 ★ VPNGate 家宽情报 (志愿者节点多为家庭宽带)
    #     验证通过的民用 ASN 回填白名单 → 提升主池家宽召回; 情报落盘备查。
    #     失败绝不阻断主流程 (try/except 在函数内部已兜底)。
    try:
        _vg_verified, _vg_asns = fetch_vpngate_intel()
        if _vg_asns:
            RESIDENTIAL_ASNS |= _vg_asns
            print(f"[+] VPNGate 回填民用 ASN: {sorted(_vg_asns)} "
                  f"(白名单现 {len(RESIDENTIAL_ASNS)} 个)")
    except Exception as e:
        print(f"[!] VPNGate 情报异常 (已跳过): {str(e)[:80]}")

    # 1. 抓取
    raw_nodes = fetch_raw_nodes()

    # 2. 解析
    candidates = []
    parse_fail = 0
    for uri in raw_nodes:
        parsed = parse_node_uri(uri)
        if not parsed:
            parse_fail += 1
            continue
        outbound, server, port, proto = parsed
        # 屏蔽占位/广告节点
        if BLACKLIST_NAME_HINTS.search(urllib.parse.unquote(uri.split("#", 1)[-1] if "#" in uri else "")):
            continue
        candidates.append((uri, outbound, server, port, proto))

    # 2.5 ★ 测前强去重 (凭据指纹去重: 同 凭据+目标+协议 只测一次, 结果回填全部重复节点)
    #     key = (server, port, proto, 凭据指纹): 凭据不同 → 服务端校验结果可能不同, 不可合并
    #     凭据指纹: uuid/password 各协议的核心身份字段 (vless uuid / vmess id+alterId /
    #               trojan password / ss 2022密钥 / hy2 auth / tuic uuid+passwd / anytls password)
    #     完全相同 = 同一节点被多源重复收录 (免费池常态, 30+ 份不同名字) → 只测一次
    seen_keys, deduped, dup_count = {}, [], 0
    for item in candidates:
        uri, outbound, server, port, proto = item
        key = (server.lower() if server else "", port, proto, cred_fingerprint(outbound, proto))
        if key in seen_keys:
            seen_keys[key].append(uri)  # 记录重复 URI, 测活后回填
            dup_count += 1
        else:
            seen_keys[key] = [uri]
            deduped.append(item)
    if dup_count:
        print(f"[*] 测前去重(凭据指纹): {len(candidates)} → {len(deduped)} (剔除重复 {dup_count} — 结果将回填)")
    DEDUP_MAP = seen_keys  # 供测活后回填 (全局)
    candidates = deduped

    proto_stat = {}
    for _, _, _, _, p in candidates:
        proto_stat[p] = proto_stat.get(p, 0) + 1
    print(f"[*] 解析成功(去重后): {len(candidates)} | 失败 {parse_fail} | 协议分布 {proto_stat}")

    if not candidates:
        print("[!] 无可测节点 (订阅源全部失效?) — 保留上次 output, 不覆盖订阅文件")
        return

    # 3. 端口预检
    candidates = prefilter_candidates(candidates)

    # 3.5 ★ 家宽优先编排 + 规模上限 (扩充订阅源后的运行时护栏)
    #   顺序: ① 自称家宽/住宅的节点 ② 预检通过的普通节点 ③ 其余
    #   理由: MAX_TEST_NODES 截断时, 最后被砍的永远是最不可能是家宽的那批。
    #   注意: 自称家宽只影响排序, 不影响判定 (判定仍走 sing-box 实测 + 六信号),
    #        免费池虚标率极高, 把它当证据会污染家宽专区。
    def _res_hint(item):
        raw = item[0]
        frag = urllib.parse.unquote(raw.split("#", 1)[1]) if "#" in raw else ""
        return bool(RESIDENTIAL_HINT_RE.search(frag))

    if candidates:
        hinted = [c for c in candidates if _res_hint(c)]
        others = [c for c in candidates if not _res_hint(c)]
        candidates = hinted + others
        if hinted:
            print(f"[*] 上游自称家宽/住宅的节点 {len(hinted)} 个已前置 (仅影响测活顺序, 不作判定依据)")

    if MAX_TEST_NODES > 0 and len(candidates) > MAX_TEST_NODES:
        print(f"[!] 待测节点 {len(candidates)} 超过上限 {MAX_TEST_NODES}, 按优先级截断 "
              f"(调大: MAX_TEST_NODES=12000)")
        candidates = candidates[:MAX_TEST_NODES]

    # 4. 真实测活 (只测去重后的代表节点)
    print(f"[*] 本轮实际进入测活: {len(candidates)} 个")
    if not candidates:
        print("[!] 预检后无可测节点 (订阅源全部失效?) — 保留上次 output, 不覆盖订阅文件")
        return
    test_results = run_liveness_test(candidates)

    # 4.5 ★ 重复节点结果回填: 同 凭据+目标 的重复 URI 继承测活结果 (凭据相同 → 服务端表现一致)
    #   修复 (2026-09-29): 回填 key 必须与去重 key 完全一致, 含凭据指纹 4 段。
    #   旧逻辑只用 (server, port, proto) 查找且后写覆盖先写, 同一目标不同凭据的组会
    #   互相串结果 → 错误凭据的节点被标活 (用户端连不上) / 正确凭据的节点被标死 (被丢弃)。
    if DEDUP_MAP:
        result_by_key = {}
        for r in test_results:
            key = ((r["server"] or "").lower(), r["port"], r["proto"],
                   r.get("cred_fp") or "")
            result_by_key[key] = r
        expanded = list(test_results)
        backfilled = 0
        for key, uris in DEDUP_MAP.items():
            if len(uris) <= 1:
                continue
            r = result_by_key.get(key)  # 完整 4 段 key: 凭据不同不互串
            if not r or not r.get("alive"):
                continue
            for extra_uri in uris[1:]:
                clone = dict(r)
                clone["raw"] = extra_uri
                expanded.append(clone)
                backfilled += 1
        if backfilled:
            print(f"[+] 重复节点回填: +{backfilled} (继承代表测活结果)")
        test_results = expanded

    # 5. ★ 家宽链式复测: 用最快存活节点做前置双跳复测家宽候选
    #    (模拟用户 v2rayN 链式场景, 双跳失败的家宽降级普通区 — 提高链式可用率)
    test_results = chain_retest(test_results)

    # 6. 分类 + 导出 (无真活节点时保留上次 output, 不写空订阅覆盖线上数据)
    if not test_results:
        print("[!] 全部节点测活失败 — 保留上次 output, 不覆盖订阅文件")
        return
    unique_nodes, residential, non_residential = classify_and_export(test_results)
    if not unique_nodes:
        print("[!] 分类后无存活节点 — 保留上次 output")
        return
    total, res = export_all(unique_nodes, residential, non_residential)
    update_readme(total, res)


    # 统计报告
    elapsed = time.time() - t_start
    print("\n===== 运行报告 =====")
    print(f"总耗时: {elapsed:.0f}s | 抓取 {len(raw_nodes)} → 解析成功 {len(candidates)} → 真活 {len(test_results)} → 去重后 {len(unique_nodes)} → 家宽 {len(residential)}")
    by_type = {}
    for n in unique_nodes:
        by_type[n["net_type"]] = by_type.get(n["net_type"], 0) + 1
    print(f"节点类型分布: {by_type}")
    by_proto = {}
    for n in unique_nodes:
        by_proto[n["proto"]] = by_proto.get(n["proto"], 0) + 1
    print(f"协议分布(出库): {by_proto}")
    by_country = {}
    for n in unique_nodes:
        by_country[n["country"]] = by_country.get(n["country"], 0) + 1
    top_c = sorted(by_country.items(), key=lambda x: -x[1])[:10]
    print(f"国家 Top10: {top_c}")


if __name__ == "__main__":
    main()
