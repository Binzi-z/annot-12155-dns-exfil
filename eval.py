#!/usr/bin/env python3
"""eval.py —— 拿分析器输出和 labels.json 对比

用法：
    python baseline/scan.py > findings.json
    python eval.py findings.json

findings 支持两种格式：
  1. 简单 JSON：{"findings":[{"file":..,"line":..}, ...]}
  2. SARIF 2.1.0：runs[].results[].locations[].physicalLocation

Windows PowerShell 5.1 的 `>` 重定向会把 stdout 写成 UTF-16LE，
所以这里按 UTF-8 / UTF-16 / GB18030 依次尝试解码。

可选门槛（默认关闭，方便看 baseline 的真实数字）：
    --min-recall 0.85 --max-fp-rate 0.15
"""
from __future__ import annotations

import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))


def load_doc(path: str) -> dict:
    with open(path, "rb") as fh:
        raw = fh.read()
    for enc in ("utf-8-sig", "utf-16", "gb18030"):
        try:
            return json.loads(raw.decode(enc))
        except (UnicodeDecodeError, ValueError):
            continue
    raise SystemExit("无法解析 findings 文件（试过 utf-8/utf-16/gb18030）: %s" % path)


def normalize_uri(uri: str) -> str:
    uri = uri.replace("\\", "/")
    if uri.startswith("file:///"):
        uri = uri[len("file:///"):]
    return uri.lstrip("./")


def load_findings(path: str) -> set[tuple[str, int]]:
    doc = load_doc(path)
    out: set[tuple[str, int]] = set()
    if "findings" in doc:
        for f in doc["findings"]:
            out.add((normalize_uri(str(f.get("file", ""))), int(f.get("line", 0))))
        return out
    for run in doc.get("runs", []):
        for res in run.get("results", []):
            for loc in res.get("locations", []):
                physical = loc.get("physicalLocation", {})
                artifact = physical.get("artifactLocation", {})
                region = physical.get("region", {})
                uri = normalize_uri(str(artifact.get("uri", "")))
                if uri:
                    out.add((uri, int(region.get("startLine", 0))))
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="evaluate findings against labels.json")
    parser.add_argument("findings", help="JSON or SARIF findings file")
    parser.add_argument("--min-recall", type=float, default=None)
    parser.add_argument("--max-fp-rate", type=float, default=None)
    args = parser.parse_args()

    with open(os.path.join(ROOT, "labels.json"), encoding="utf-8") as fh:
        labels = json.load(fh)["vulns"]
    truth = {(v["file"], int(v["line"])) for v in labels}
    got = load_findings(args.findings)

    tp = len(truth & got)
    fp = len(got - truth)
    fn = len(truth - got)
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    fp_rate = fp / (tp + fp) if (tp + fp) else 0.0

    print("labels=%d findings=%d TP=%d FP=%d FN=%d" % (len(truth), len(got), tp, fp, fn))
    print(
        "recall=%.1f%% precision=%.1f%% false_positive_rate=%.1f%%"
        % (recall * 100, precision * 100, fp_rate * 100)
    )

    if fn:
        print("missed:")
        for path, line in sorted(truth - got):
            print("  %s:%d" % (path, line))
    if fp:
        print("false positives (unlabelled sink lines): %d" % fp)

    if args.min_recall is not None and recall < args.min_recall:
        print("FAIL: recall %.1f%% < %.1f%%" % (recall * 100, args.min_recall * 100), file=sys.stderr)
        return 1
    if args.max_fp_rate is not None and fp_rate > args.max_fp_rate:
        print(
            "FAIL: false_positive_rate %.1f%% > %.1f%%" % (fp_rate * 100, args.max_fp_rate * 100),
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
