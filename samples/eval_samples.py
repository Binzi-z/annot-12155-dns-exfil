#!/usr/bin/env python3
"""对 samples/changes 的 50 条标注样本做一次 baseline 回测。

这里只验证「样本与 baseline 的关系」：vulnerable 期望命中，safe/benign 期望不命中。
真正的分析器评测仍以 eval.py + labels.json 为准。
"""
import glob
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHANGES = os.path.join(ROOT, "samples", "changes")


def baseline_findings():
    proc = subprocess.run(
        [sys.executable, os.path.join(ROOT, "baseline", "scan.py")],
        capture_output=True, text=True, encoding="utf-8", cwd=ROOT, check=True,
    )
    return {(f["file"], int(f["line"])) for f in json.loads(proc.stdout)["findings"]}


def main():
    findings = baseline_findings()
    tp = fp = fn = tn = 0
    counts = {"vulnerable": 0, "safe": 0, "benign": 0}
    for path in sorted(glob.glob(os.path.join(CHANGES, "*.json"))):
        with open(path, encoding="utf-8") as fh:
            sample = json.load(fh)
        counts[sample["kind"]] += 1
        hit = (sample["file"], int(sample["line"])) in findings
        if sample["kind"] == "vulnerable":
            if hit:
                tp += 1
            else:
                fn += 1
        else:
            if hit:
                fp += 1
            else:
                tn += 1

    recall = tp / (tp + fn) if (tp + fn) else 0.0
    fp_rate = fp / (tp + fp) if (tp + fp) else 0.0
    print("samples=%d vulnerable=%d safe=%d benign=%d" % (
        sum(counts.values()), counts["vulnerable"], counts["safe"], counts["benign"]))
    print("TP=%d FN=%d FP=%d TN=%d" % (tp, fn, fp, tn))
    print("recall=%.1f%% false_positive_rate=%.1f%%" % (recall * 100, fp_rate * 100))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
