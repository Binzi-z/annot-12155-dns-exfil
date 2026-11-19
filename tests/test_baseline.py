"""语料自检：labels 行号、baseline 召回/误报、50 条样本、JS 语法。

跑法：python -m pytest tests -q
"""
import glob
import json
import os
import re
import shutil
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SINK_RE = re.compile(
    r"fs\.(?:promises\.)?(?:readFile|readFileSync|createReadStream|"
    r"writeFile|writeFileSync|copyFile|copyFileSync|rename|renameSync|rm|rmSync|cp|cpSync)\s*\("
    r"|res\.(?:sendFile|download)\s*\("
    r"|require\s*\(\s*(?![\"'])|require\s*\([^)]*\+"
    r"|express\.static\s*\("
)


def load_labels():
    with open(os.path.join(ROOT, "labels.json"), encoding="utf-8") as fh:
        return json.load(fh)["vulns"]


def scan_findings():
    proc = subprocess.run(
        [sys.executable, os.path.join(ROOT, "baseline", "scan.py")],
        capture_output=True, text=True, encoding="utf-8", cwd=ROOT, check=True,
    )
    return json.loads(proc.stdout)["findings"]


def read_lines(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
        return fh.read().splitlines()


def test_labels_have_required_fields():
    labels = load_labels()
    assert len(labels) >= 20, "题面要求至少 20 条真漏洞标注"
    for v in labels:
        for key in ("id", "ruleId", "sink", "file", "line", "label"):
            assert v.get(key) not in (None, ""), "%s 缺字段 %s" % (v.get("id"), key)
        assert os.path.exists(os.path.join(ROOT, v["file"])), v["file"]


def test_labels_point_at_sink_lines():
    for v in load_labels():
        lines = read_lines(v["file"])
        assert 1 <= int(v["line"]) <= len(lines), "%s:%s 越界" % (v["file"], v["line"])
        line = lines[int(v["line"]) - 1]
        assert SINK_RE.search(line), "%s:%s 不是 sink 调用：%s" % (v["file"], v["line"], line)


def test_baseline_recall_and_false_positives():
    truth = {(v["file"], int(v["line"])) for v in load_labels()}
    got = {(f["file"], int(f["line"])) for f in scan_findings()}
    tp = len(truth & got)
    fp = len(got - truth)
    recall = tp / len(truth) if truth else 0.0
    fp_rate = fp / len(got) if got else 0.0
    assert recall >= 0.90, "baseline 召回 %.1f%% < 90%%" % (recall * 100)
    assert fp_rate > 0.20, "baseline 误报率 %.1f%% <= 20%%，题目就没有改进空间了" % (fp_rate * 100)


def test_fifty_labelled_changes():
    paths = sorted(glob.glob(os.path.join(ROOT, "samples", "changes", "*.json")))
    assert len(paths) == 50, "题面要求 50 条标注样本，实际 %d" % len(paths)

    truth = {(v["file"], int(v["line"])) for v in load_labels()}
    covered = set()
    kinds = {"vulnerable": 0, "safe": 0, "benign": 0}
    for path in paths:
        with open(path, encoding="utf-8") as fh:
            s = json.load(fh)
        assert s["kind"] in kinds, path
        kinds[s["kind"]] += 1
        assert s.get("before") and s.get("after"), "%s 缺 before/after" % path
        assert s["after"] in "\n".join(read_lines(s["file"])), "%s after 不在语料中" % path
        key = (s["file"], int(s["line"]))
        if s["kind"] == "vulnerable":
            assert key in truth, "%s 标了漏洞但不在 labels.json" % path
            assert s["after"].find(read_lines(s["file"])[int(s["line"]) - 1]) >= 0
            covered.add(key)
        else:
            assert key not in truth, "%s 是 decoy/benign，不能进 labels.json" % path

    assert covered == truth, "有 labels 没被 vulnerable 样本覆盖：%s" % sorted(truth - covered)
    assert kinds == {"vulnerable": 25, "safe": 12, "benign": 13}, kinds


def test_js_ts_source_tree():
    files = [
        p for p in glob.glob(os.path.join(ROOT, "src", "**", "*"), recursive=True)
        if p.endswith((".js", ".ts"))
    ]
    assert len(files) >= 12, "题面要求 JS/TS 源码树至少 12 个文件"
    assert any(p.endswith(".ts") for p in files), "缺 TypeScript 文件"


def test_js_syntax():
    node = shutil.which("node")
    if not node:
        pytest.skip("node 不在 PATH，跳过语法检查")
    files = sorted(glob.glob(os.path.join(ROOT, "src", "**", "*.js"), recursive=True))
    assert files, "src/ 下没有 .js 文件"
    for path in files:
        proc = subprocess.run(
            [node, "--check", path], capture_output=True, text=True, encoding="utf-8",
        )
        assert proc.returncode == 0, path + "\n" + proc.stdout + proc.stderr


def test_ts_syntax():
    node = shutil.which("node")
    if not node:
        pytest.skip("node 不在 PATH，跳过语法检查")
    version = subprocess.run(
        [node, "--version"], capture_output=True, text=True, encoding="utf-8", check=True,
    ).stdout.strip()
    major = int(version.lstrip("v").split(".")[0])
    if major < 22:
        pytest.skip("node %s 不支持 --check 解析 .ts" % version)
    files = sorted(glob.glob(os.path.join(ROOT, "src", "**", "*.ts"), recursive=True))
    assert files, "src/ 下没有 .ts 文件"
    for path in files:
        proc = subprocess.run(
            [node, "--check", path], capture_output=True, text=True, encoding="utf-8",
        )
        assert proc.returncode == 0, path + "\n" + proc.stdout + proc.stderr


def test_sarif_output_and_eval(tmp_path):
    sarif = tmp_path / "findings.sarif"
    proc = subprocess.run(
        [sys.executable, os.path.join(ROOT, "baseline", "scan.py"), "--sarif", str(sarif)],
        capture_output=True, text=True, encoding="utf-8", cwd=ROOT, check=True,
    )
    assert sarif.exists()
    doc = json.loads(sarif.read_text(encoding="utf-8"))
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"], "SARIF 里没有 results"

    evaluated = subprocess.run(
        [sys.executable, os.path.join(ROOT, "eval.py"), str(sarif)],
        capture_output=True, text=True, encoding="utf-8", cwd=ROOT, check=True,
    )
    assert "recall=100.0%" in evaluated.stdout
    assert "false_positive_rate=32.4%" in evaluated.stdout


def test_samples_backtest_script():
    proc = subprocess.run(
        [sys.executable, os.path.join(ROOT, "samples", "eval_samples.py")],
        capture_output=True, text=True, encoding="utf-8", cwd=ROOT, check=True,
    )
    assert "samples=50 vulnerable=25 safe=12 benign=13" in proc.stdout
    assert "recall=100.0%" in proc.stdout
    assert "false_positive_rate=32.4%" in proc.stdout


def test_no_dns_leftovers():
    assert not os.path.exists(os.path.join(ROOT, "detector"))
    assert not os.path.exists(os.path.join(ROOT, "logs"))
