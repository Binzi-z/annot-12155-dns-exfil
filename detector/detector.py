"""DNS 隧道外传 + 横向移动检测器.

不再对单行日志逐条告警，而是先聚合再关联:

1. dns_tunnel —— 按 (源 IP, 注册域) 聚合 dnsmasq 查询，三个判定因子加权:
     查询频率 (0.30) / 子域熵 (0.40) / 目标域集中度 (0.30)
   CDN 与监控探测域走威胁情报白名单，直接排除，构造上零误报。
2. lateral_movement —— 同一账号在时间窗内从不同主机登录成功。
    svc-dns 这类服务号整夜跨机登录，单靠时间窗必然误报，因此要求
   与 dns_tunnel 告警实体关联，或两个源 IP 都是全日志稀有来源。
3. 拿不准的进入 needs_review 并写明缺什么证据，不进 findings。

输出 findings.json: {findings, needs_review, summary}，每条 finding 含
rule / first_seen / last_seen / entities / evidence / factors(权重) / event_chain(按序)。
"""

from __future__ import annotations

import json
import math
import re
import sys
from collections import defaultdict
from datetime import datetime

# ---------------------------------------------------------------- 解析

LINE = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<hms>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<rest>.*)$"
)
SSH_OK = re.compile(r"Accepted publickey for (?P<user>\S+) from (?P<ip>[\d.]+)")
SSH_FAIL = re.compile(r"Failed password for (?P<user>\S+) from (?P<ip>[\d.]+)")
DNS = re.compile(
    r"dnsmasq\[\d+\]: query\[(?P<qtype>\w+)\]\s+(?P<name>\S+)\s+from\s+(?P<ip>[\d.]+)"
)
WEB = re.compile(r'nginx: (?P<ip>[\d.]+) - - "(?P<path>\S+)" (?P<status>\d{3})')

MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}

# 威胁情报白名单: CDN / 监控探测域。命中即排除，不参与隧道评分。
CDN_SUFFIXES = (
    "cloudfront.net", "akamai.net", "akamaized.net", "edgesuite.net",
    "fastly.net", "cloudflare.net", "azureedge.net", "amazonaws.com",
    "cdn.example.com",
)
MONITOR_SUFFIXES = (
    "monitoring.example.com", "probe.example.com", "health.example.com",
)
ALLOWLIST = CDN_SUFFIXES + MONITOR_SUFFIXES

# 判定因子权重(告警中随 factors 一起输出)
W_FREQ, W_ENTROPY, W_CONC = 0.30, 0.40, 0.30   # dns_tunnel
W_GAP, W_HOSTS, W_CORR = 0.40, 0.20, 0.40      # lateral_movement

MIN_QUERIES_ALERT = 8      # 隧道告警最少查询数(监控探测通常 1-2 条)
SCORE_ALERT = 0.75         # 加权分 >= 此值告警
SCORE_REVIEW = 0.50        # 加权分 >= 此值但不够告警 -> needs_review
MIN_QUERIES_REVIEW = 4
LATERAL_GAP_S = 120        # 同账号跨主机登录间隔上限
RARE_SSH_SEEN = 2          # 全日志 ssh 来源次数 <= 此值视为稀有 IP
CORR_WINDOW_S = 30 * 60    # 隧道前后关联登录的窗口


def parse_ts(mon: str, day: str, hms: str) -> datetime:
    h, m, s = (int(x) for x in hms.split(":"))
    return datetime(2000, MONTHS[mon], int(day), h, m, s)


def fmt(ts: datetime) -> str:
    return ts.strftime("%b %d %H:%M:%S").replace(" 0", " ", 1) \
        if ts.day < 10 else ts.strftime("%b %d %H:%M:%S")


def registered_domain(name: str) -> str:
    parts = name.rstrip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else name


def parent_domain(name: str) -> str:
    """目标域: 去掉最左侧(承载数据的)标签。label.exfil.example.com -> exfil.example.com"""
    parts = name.rstrip(".").split(".")
    return ".".join(parts[1:]) if len(parts) > 2 else registered_domain(name)


def subdomain_of(name: str) -> str:
    parent = parent_domain(name)
    return name[: -(len(parent) + 1)] if name != parent else ""


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = defaultdict(int)
    for ch in text:
        counts[ch] += 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def allowlisted(name: str) -> bool:
    return any(name == s or name.endswith("." + s) for s in ALLOWLIST)


def parse_log(path: str) -> dict:
    events: dict[str, list] = {"dns": [], "ssh_ok": [], "ssh_fail": [], "web": []}
    stats = {"lines": 0, "dns_allowlisted": 0}
    with open(path, encoding="utf-8") as fh:
        for no, raw in enumerate(fh, start=1):
            stats["lines"] += 1
            m = LINE.match(raw.rstrip("\n"))
            if not m:
                continue
            ts = parse_ts(m.group("mon"), m.group("day"), m.group("hms"))
            rest = m.group("rest")
            base = {"ts": ts, "ts_str": f"{m.group('mon')} {m.group('day')} {m.group('hms')}",
                    "line": no}
            d = DNS.search(rest)
            if d:
                name = d.group("name").lower()
                if allowlisted(name):
                    stats["dns_allowlisted"] += 1
                    continue
                events["dns"].append({**base, "qtype": d.group("qtype"),
                                      "name": name, "ip": d.group("ip")})
                continue
            s = SSH_OK.search(rest)
            if s:
                events["ssh_ok"].append({**base, "user": s.group("user"),
                                         "ip": s.group("ip")})
                continue
            f = SSH_FAIL.search(rest)
            if f:
                events["ssh_fail"].append({**base, "user": f.group("user"),
                                           "ip": f.group("ip")})
                continue
            w = WEB.search(rest)
            if w:
                events["web"].append({**base, "ip": w.group("ip"),
                                      "path": w.group("path"),
                                      "status": int(w.group("status"))})
    return {"events": events, "stats": stats}


# ---------------------------------------------------------------- dns_tunnel

def score_dns_group(grp: list[dict], total_from_ip: int) -> dict:
    """对 (源 IP, 注册域) 一组查询打分，返回各因子明细。"""
    n = len(grp)
    first, last = grp[0]["ts"], grp[-1]["ts"]
    span_min = max((last - first).total_seconds() / 60.0, 1.0 / 60.0)
    qpm = n / span_min

    labels = [subdomain_of(g["name"]) for g in grp]
    uniq_labels = sorted(set(labels))
    avg_entropy = (sum(shannon_entropy(x) for x in uniq_labels) / len(uniq_labels)
                   if uniq_labels else 0.0)
    concentration = n / total_from_ip if total_from_ip else 0.0

    freq_score = min(1.0, qpm / 10.0)        # 10 次/分钟即满分
    ent_score = min(1.0, avg_entropy / 4.0)  # 4 bit/字符即满分(随机 base32 约 5)
    conc_score = concentration
    score = W_FREQ * freq_score + W_ENTROPY * ent_score + W_CONC * conc_score

    return {
        "n": n, "qpm": round(qpm, 2), "avg_entropy": round(avg_entropy, 2),
        "unique_labels": len(uniq_labels), "concentration": round(concentration, 3),
        "score": round(score, 3),
        "factors": {
            "query_frequency": {"value": f"{qpm:.1f} qpm", "score": round(freq_score, 3),
                                "weight": W_FREQ,
                                "contribution": round(W_FREQ * freq_score, 3)},
            "subdomain_entropy": {"value": f"{avg_entropy:.2f} bit/char",
                                  "score": round(ent_score, 3), "weight": W_ENTROPY,
                                  "contribution": round(W_ENTROPY * ent_score, 3)},
            "domain_concentration": {"value": f"{concentration:.0%} 查询指向该域",
                                     "score": round(conc_score, 3), "weight": W_CONC,
                                     "contribution": round(W_CONC * conc_score, 3)},
        },
    }


def detect_dns_tunnel(events: dict) -> tuple[list[dict], list[dict], dict]:
    dns = sorted(events["dns"], key=lambda e: (e["ip"], e["ts"]))
    by_ip: dict[str, list] = defaultdict(list)
    for e in dns:
        by_ip[e["ip"]].append(e)
    groups: dict[tuple[str, str], list] = defaultdict(list)
    for e in dns:
        groups[(e["ip"], parent_domain(e["name"]))].append(e)

    findings, reviews, tunnel_ips = [], [], {}
    for (ip, domain), grp in sorted(groups.items(), key=lambda kv: kv[1][0]["ts"]):
        s = score_dns_group(grp, len(by_ip[ip]))
        first, last = grp[0], grp[-1]
        entities = {"ips": [ip], "domains": [domain], "users": []}
        chain = [{"ts": g["ts_str"], "line": g["line"], "type": "dns_query",
                  "detail": f"query[{g['qtype']}] {g['name']}"} for g in grp]
        # 解析前后的主机登录: 源 IP 在窗口内的 ssh 成功登录并入事件链
        for login in events["ssh_ok"]:
            if login["ip"] == ip and abs(
                    (login["ts"] - last["ts"]).total_seconds()) <= CORR_WINDOW_S:
                chain.append({"ts": login["ts_str"], "line": login["line"],
                              "type": "ssh_login",
                              "detail": f"Accepted publickey for {login['user']} "
                                        f"from {login['ip']}"})
                if login["user"] not in entities["users"]:
                    entities["users"].append(login["user"])
        chain.sort(key=lambda c: (c["ts"], c["line"]))

        if s["n"] >= MIN_QUERIES_ALERT and s["score"] >= SCORE_ALERT:
            findings.append({
                "rule": "dns_tunnel",
                "severity": "high",
                "first_seen": first["ts_str"],
                "last_seen": chain[-1]["ts"],
                "entities": entities,
                "score": s["score"],
                "factors": s["factors"],
                "evidence": [
                    f"{ip} 在 {first['ts_str']}–{last['ts_str']} 内向 {domain} "
                    f"发出 {s['n']} 条查询({s['qpm']} 次/分钟)",
                    f"子域唯一标签 {s['unique_labels']} 个,平均熵 "
                    f"{s['avg_entropy']} bit/字符,符合编码外传特征",
                    f"该源 IP 的查询 {s['concentration']:.0%} 集中于 {domain}",
                ],
                "event_chain": chain,
            })
            tunnel_ips[ip] = {"domain": domain, "first": first, "last": last,
                              "n": s["n"]}
        elif (s["n"] >= MIN_QUERIES_REVIEW and s["score"] >= SCORE_REVIEW) \
                or s["score"] >= SCORE_ALERT:
            missing = []
            if s["n"] < MIN_QUERIES_ALERT:
                missing.append(f"样本量不足: {s['n']} 条 < 告警下限 {MIN_QUERIES_ALERT} 条")
            if s["score"] < SCORE_ALERT:
                weak = min(s["factors"].items(),
                           key=lambda kv: kv[1]["contribution"])
                missing.append(
                    f"加权分 {s['score']} < {SCORE_ALERT},最弱因子 "
                    f"{weak[0]}({weak[1]['value']}),需更多查询确认频率/熵")
            reviews.append({
                "rule": "dns_tunnel",
                "first_seen": first["ts_str"], "last_seen": last["ts_str"],
                "entities": entities, "score": s["score"], "factors": s["factors"],
                "missing": missing,
                "evidence": [f"{ip} 对 {domain} 的 {s['n']} 条查询未达告警阈值"],
            })
    return findings, reviews, tunnel_ips


# ---------------------------------------------------------------- lateral_movement

def detect_lateral(events: dict, tunnel_ips: dict) -> tuple[list[dict], list[dict]]:
    logins = sorted(events["ssh_ok"], key=lambda e: e["ts"])
    ssh_count: dict[str, int] = defaultdict(int)
    for l in logins:
        ssh_count[l["ip"]] += 1
    by_user: dict[str, list] = defaultdict(list)
    for l in logins:
        by_user[l["user"]].append(l)

    findings, reviews = [], []
    for user, rows in sorted(by_user.items()):
        # 逐对评估: 只有"与隧道告警关联"或"双 IP 均稀有"的对才可疑,
        # 否则 svc-dns 这类服务号的常规跨机登录会把整个账号卷进来。
        suspicious, near_miss = [], []
        for i in range(len(rows)):
            for j in range(i + 1, len(rows)):
                gap = (rows[j]["ts"] - rows[i]["ts"]).total_seconds()
                if gap > LATERAL_GAP_S:
                    break
                a, b = rows[i], rows[j]
                if a["ip"] == b["ip"]:
                    continue
                correlated = a["ip"] in tunnel_ips or b["ip"] in tunnel_ips
                both_rare = (ssh_count[a["ip"]] <= RARE_SSH_SEEN
                             and ssh_count[b["ip"]] <= RARE_SSH_SEEN)
                if correlated or both_rare:
                    suspicious.append((a, b, gap, correlated, both_rare))
                elif ssh_count[a["ip"]] <= RARE_SSH_SEEN \
                        or ssh_count[b["ip"]] <= RARE_SSH_SEEN:
                    near_miss.append((a, b, gap))  # 一侧稀有但无关联: 拿不准
        # 共享 IP 的可疑对合并为一个簇(一次移动可能跨多台)
        clusters: list[dict] = []
        for pair in suspicious:
            ips = {pair[0]["ip"], pair[1]["ip"]}
            for c in clusters:
                if c["ips"] & ips:
                    c["ips"] |= ips
                    c["pairs"].append(pair)
                    break
            else:
                clusters.append({"ips": set(ips), "pairs": [pair]})
        for c in clusters:
            ips = sorted(c["ips"])
            correlated = [x for x in ips if x in tunnel_ips]
            min_gap = min(p[2] for p in c["pairs"])
            gap_score = 1.0 - min_gap / LATERAL_GAP_S
            corr_score = 1.0 if correlated else 0.5
            factors = {
                "time_gap": {"value": f"{int(min_gap)}s", "score": round(gap_score, 3),
                             "weight": W_GAP,
                             "contribution": round(W_GAP * gap_score, 3)},
                "distinct_hosts": {"value": f"{len(ips)} 台主机", "score": 1.0,
                                   "weight": W_HOSTS, "contribution": W_HOSTS},
                "tunnel_correlation": {
                    "value": ("源 IP 命中 dns_tunnel 告警" if correlated
                              else "双 IP 均为稀有登录来源"),
                    "score": corr_score, "weight": W_CORR,
                    "contribution": round(W_CORR * corr_score, 3)},
            }
            score = round(sum(f["contribution"] for f in factors.values()), 3)
            chain, seen_lines = [], set()
            for ip in correlated:
                t = tunnel_ips[ip]
                chain.append({"ts": t["first"]["ts_str"], "line": t["first"]["line"],
                              "type": "dns_tunnel",
                              "detail": f"{ip} 向 {t['domain']} 的 {t['n']} 条隧道查询"
                                        f"({t['first']['ts_str']}–{t['last']['ts_str']})"})
                seen_lines.add(t["first"]["line"])
            for a, b, _gap, _c, _r in c["pairs"]:
                for l in (a, b):
                    if l["line"] not in seen_lines:
                        chain.append({"ts": l["ts_str"], "line": l["line"],
                                      "type": "ssh_login",
                                      "detail": f"Accepted publickey for {user} "
                                                f"from {l['ip']}"})
                        seen_lines.add(l["line"])
            chain.sort(key=lambda e: (e["ts"], e["line"]))
            findings.append({
                "rule": "lateral_movement",
                "severity": "high",
                "first_seen": chain[0]["ts"],
                "last_seen": chain[-1]["ts"],
                "entities": {"ips": ips, "users": [user],
                             "domains": sorted({tunnel_ips[x]["domain"]
                                                for x in correlated})},
                "score": score,
                "factors": factors,
                "evidence": [
                    f"{user} 在 {int(min_gap)} 秒内从 {'、'.join(ips)} "
                    f"{len(ips)} 台主机登录成功(同一 key 跨主机)",
                    *(f"{x} 是 dns_tunnel 告警源 IP" for x in correlated),
                    *(["两个源 IP 在全日志中均为稀有登录来源"]
                      if not correlated else []),
                ],
                "event_chain": chain,
            })
        for a, b, gap in near_miss:
            reviews.append({
                "rule": "lateral_movement",
                "first_seen": a["ts_str"], "last_seen": b["ts_str"],
                "entities": {"ips": sorted([a["ip"], b["ip"]]),
                             "users": [user], "domains": []},
                "missing": ["一侧源 IP 稀有但与任何 dns_tunnel 告警无关联;"
                            "需要进程/会话日志或堡垒机记录确认是否为同一 key"],
                "evidence": [f"{user} 在 {int(gap)} 秒内跨 "
                             f"{a['ip']}、{b['ip']} 登录"],
            })
    return findings, reviews


# ---------------------------------------------------------------- main

def scan(path: str) -> dict:
    parsed = parse_log(path)
    events, stats = parsed["events"], parsed["stats"]
    dns_findings, dns_reviews, tunnel_ips = detect_dns_tunnel(events)
    lat_findings, lat_reviews = detect_lateral(events, tunnel_ips)
    return {
        "findings": dns_findings + lat_findings,
        "needs_review": dns_reviews + lat_reviews,
        "summary": {
            "lines": stats["lines"],
            "dns_queries": len(events["dns"]),
            "dns_allowlisted_skipped": stats["dns_allowlisted"],
            "ssh_accepted": len(events["ssh_ok"]),
            "ssh_failed": len(events["ssh_fail"]),
            "web_requests": len(events["web"]),
            "weights": {
                "dns_tunnel": {"query_frequency": W_FREQ,
                               "subdomain_entropy": W_ENTROPY,
                               "domain_concentration": W_CONC},
                "lateral_movement": {"time_gap": W_GAP,
                                     "distinct_hosts": W_HOSTS,
                                     "tunnel_correlation": W_CORR},
            },
        },
    }


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: detector.py <log> <out.json>")
        return 2
    result = scan(sys.argv[1])
    with open(sys.argv[2], "w", encoding="utf-8") as fh:
        json.dump(result, fh, ensure_ascii=False, indent=2)
    print(f"{len(result['findings'])} findings, "
          f"{len(result['needs_review'])} needs_review -> {sys.argv[2]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
