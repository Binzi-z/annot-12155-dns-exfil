import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG = os.path.join(ROOT, "logs", "auth.log")


def run(tmp_path, log=LOG):
    out = tmp_path / "out.json"
    r = subprocess.run(
        [sys.executable, os.path.join(ROOT, "detector", "detector.py"), log, str(out)],
        capture_output=True, text=True,
    )
    return r, out


def load(out):
    return json.loads(out.read_text(encoding="utf-8"))


def write_log(tmp_path, lines):
    p = tmp_path / "case.log"
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(p)


def test_corpus_and_labels():
    assert os.path.exists(LOG)
    with open(os.path.join(ROOT, "labels.json"), encoding="utf-8") as fh:
        data = json.load(fh)
    assert len(data["events"]) == 2


def test_detector_runs(tmp_path):
    r, out = run(tmp_path)
    assert r.returncode == 0, r.stderr
    assert "findings" in load(out)


def test_findings_have_required_fields(tmp_path):
    _, out = run(tmp_path)
    findings = load(out)["findings"]
    assert findings, "expected at least one finding on the corpus"
    for f in findings:
        for key in ("rule", "first_seen", "last_seen", "entities", "evidence"):
            assert f.get(key), f"{key} missing in {f}"
        # 每条告警都要给出因子权重与按序事件链
        assert f["factors"] and all(
            "weight" in v and "contribution" in v for v in f["factors"].values()
        )
        assert f["event_chain"], "event chain required"
        weights = [v["weight"] for v in f["factors"].values()]
        assert abs(sum(weights) - 1.0) < 1e-9


def test_labels_all_hit(tmp_path):
    """labels.json 两个标注事件必须全部命中。"""
    _, out = run(tmp_path)
    findings = load(out)["findings"]
    by_rule = {}
    for f in findings:
        by_rule.setdefault(f["rule"], []).append(f)

    tunnels = by_rule.get("dns_tunnel", [])
    assert any("10.20.1.51" in t["entities"]["ips"] for t in tunnels), \
        "dns_tunnel on 10.20.1.51 not detected"

    laterals = by_rule.get("lateral_movement", [])
    assert any(
        {"10.20.1.51", "10.20.1.52"} <= set(l["entities"]["ips"])
        and "svc-dns" in l["entities"]["users"] for l in laterals
    ), "lateral movement of svc-dns across .51/.52 not detected"


def test_zero_false_positives_on_lookalikes(tmp_path):
    """良性相似流量(失败后成功 .77 / 403 探测 .88)任何命中都算误报。"""
    _, out = run(tmp_path)
    data = load(out)
    assert len(data["findings"]) == 2, \
        f"unexpected findings: {[f['rule'] for f in data['findings']]}"
    for section in ("findings", "needs_review"):
        for item in data[section]:
            ips = item["entities"].get("ips", [])
            assert "10.20.1.77" not in ips and "10.20.1.88" not in ips


def test_empty_log_yields_no_findings(tmp_path):
    empty = tmp_path / "empty.log"
    empty.write_text("", encoding="utf-8")
    r, out = run(tmp_path, str(empty))
    assert r.returncode == 0
    data = load(out)
    assert data["findings"] == []
    assert data["needs_review"] == []


def test_cdn_and_monitoring_queries_no_fp(tmp_path):
    """CDN 长域名与监控探测: 不告警、不进 needs_review。"""
    lines = [
        # CDN: 域名也长, 但走白名单
        f"Oct 01 03:0{i}:00 web01 dnsmasq[811]: query[A] "
        f"assets-{i}-static.cdn.example.com from 10.20.1.60" for i in range(9)
    ] + [
        # 监控探测: 低频、低熵、固定域名
        "Oct 01 04:00:00 web01 dnsmasq[811]: query[A] "
        "probe1.monitoring.example.com from 10.20.1.61",
        "Oct 01 04:05:00 web01 dnsmasq[811]: query[A] "
        "probe1.monitoring.example.com from 10.20.1.61",
        # 普通短查询, 量小
        "Oct 01 05:00:00 web01 dnsmasq[811]: query[A] mail.example.org from 10.20.1.62",
        "Oct 01 05:01:00 web01 dnsmasq[811]: query[A] www.example.org from 10.20.1.62",
    ]
    r, out = run(tmp_path, write_log(tmp_path, lines))
    assert r.returncode == 0, r.stderr
    data = load(out)
    assert data["findings"] == []
    assert data["needs_review"] == []


def test_borderline_tunnel_goes_to_needs_review(tmp_path):
    """高熵但样本量不足: 不告警, 进 needs_review 并写明缺什么。"""
    names = ["a1b2c3d4e5f6g7h8i9j0k1l2", "z9y8x7w6v5u4t3s2r1q0p9o8",
             "m3n4b5v6c7x8z9a0s1d2f3g4", "q1w2e3r4t5y6u7i8o9p0a1s2",
             "h5j6k7l8p9o0i1u2y3t4r5e6"]
    lines = [
        f"Oct 01 02:1{i}:00 web01 dnsmasq[811]: query[A] "
        f"{n}.data.example.net from 10.20.1.70" for i, n in enumerate(names)
    ]
    r, out = run(tmp_path, write_log(tmp_path, lines))
    assert r.returncode == 0, r.stderr
    data = load(out)
    assert data["findings"] == []
    reviews = [x for x in data["needs_review"] if x["rule"] == "dns_tunnel"]
    assert len(reviews) == 1
    assert reviews[0]["missing"], "needs_review must say what evidence is missing"
    assert "10.20.1.70" in reviews[0]["entities"]["ips"]


def test_real_tunnel_synthetic_alert(tmp_path):
    """足量高频高熵查询 -> 告警, 因子权重齐全。"""
    names = [f"{c * 3}x{i}k{c}9z{i}q{c}w{i}e{c}r{i}t{c}"
             for i, c in enumerate("abcdefghjklm")]
    lines = [
        f"Oct 01 01:00:{i:02d} web01 dnsmasq[811]: query[TXT] "
        f"{n}.tunnel.example.net from 10.20.1.80" for i, n in enumerate(names)
    ]
    r, out = run(tmp_path, write_log(tmp_path, lines))
    assert r.returncode == 0, r.stderr
    data = load(out)
    tunnels = [f for f in data["findings"] if f["rule"] == "dns_tunnel"]
    assert len(tunnels) == 1
    t = tunnels[0]
    assert t["entities"]["ips"] == ["10.20.1.80"]
    assert t["entities"]["domains"] == ["tunnel.example.net"]
    assert t["first_seen"] and t["last_seen"]
