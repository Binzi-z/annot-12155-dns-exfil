#!/usr/bin/env python3
"""baseline/scan.py —— 正则版路径穿越扫描器（改进前起点）

不做 AST、不做符号表、不做跨过程传播：只要某一行出现 sink 调用就报一条。
因此 src/admin 与 src/ts/safe-report.ts 里已经做了 resolveWithin / basename /
白名单校验的调用点也会中招，这正是本题要改进的误报来源。

用法：
    python baseline/scan.py                # JSON findings -> stdout
    python baseline/scan.py --sarif out.sarif
    python baseline/scan.py --sarif -       # SARIF -> stdout
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src")
EXTS = (".js", ".ts")

# 命中所有 sink 形态（包括净化后的形态），少一个函数名，召回就不够。
SINK_RE = re.compile(
    r"fs\.(?:promises\.)?(?:readFile|readFileSync|createReadStream|"
    r"writeFile|writeFileSync|copyFile|copyFileSync|rename|renameSync|rm|rmSync|cp|cpSync)\s*\("
    r"|res\.(?:sendFile|download)\s*\("
    r"|require\s*\(\s*(?![\"'])|require\s*\([^)]*\+"
    r"|express\.static\s*\("
    r"|res\.render\s*\("
)

RULE_META = {
    "PT-FS-READ-001": (
        "path-traversal-fs-read",
        "fs 读文件时使用了未净化的动态路径",
    ),
    "PT-PATH-JOIN-002": (
        "path-traversal-fs-write",
        "path.join 结果未做目录边界校验就用于写/复制/改名",
    ),
    "PT-SEND-FILE-003": (
        "path-traversal-send-file",
        "sendFile/download 使用了动态路径",
    ),
    "PT-DYNAMIC-REQUIRE-004": (
        "path-traversal-dynamic-require",
        "require 的模块路径包含动态输入",
    ),
    "PT-STATIC-ROOT-005": (
        "path-traversal-static-root",
        "express.static 的根目录来自动态输入",
    ),
    "PT-ZIP-SLIP-006": (
        "path-traversal-zip-slip",
        "压缩包条目路径未校验即落盘",
    ),
    "PT-TEMPLATE-INCLUDE-007": (
        "path-traversal-template-include",
        "模板 include 的文件名来自动态输入",
    ),
}


def rule_for(line: str) -> str:
    """按行内特征给出最接近的规则编号；只是给 SARIF 分类，不参与判定。"""
    if "TEMPLATE_DIR" in line or "res.render(" in line or "includePartial(" in line:
        return "PT-TEMPLATE-INCLUDE-007"
    if "EXTRACT_DIR" in line and ("writeFile" in line or "entry" in line):
        return "PT-ZIP-SLIP-006"
    if "sendFile" in line or "download" in line:
        return "PT-SEND-FILE-003"
    if "express.static" in line:
        return "PT-STATIC-ROOT-005"
    if "require(" in line:
        return "PT-DYNAMIC-REQUIRE-004"
    if re.search(r"fs\.(?:promises\.)?(?:readFile|readFileSync|createReadStream)", line):
        return "PT-FS-READ-001"
    return "PT-PATH-JOIN-002"


def scan() -> list[dict]:
    findings: list[dict] = []
    for dirpath, dirnames, names in os.walk(SRC):
        dirnames.sort()
        for name in sorted(names):
            if not name.endswith(EXTS):
                continue
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, ROOT).replace(os.sep, "/")
            with open(path, encoding="utf-8") as fh:
                for no, line in enumerate(fh, 1):
                    if SINK_RE.search(line):
                        findings.append({
                            "file": rel,
                            "line": no,
                            "ruleId": rule_for(line),
                            "message": line.strip()[:200],
                        })
    findings.sort(key=lambda f: (f["file"], f["line"]))
    return findings


def to_sarif(findings: list[dict]) -> dict:
    used = sorted({f["ruleId"] for f in findings})
    rules = []
    for rid in used:
        name, desc = RULE_META.get(rid, (rid, rid))
        rules.append({
            "id": rid,
            "name": name,
            "shortDescription": {"text": desc},
            "defaultConfiguration": {"level": "error"},
        })
    results = []
    for f in findings:
        results.append({
            "ruleId": f["ruleId"],
            "level": "error",
            "message": {"text": "路径穿越候选点：" + f["message"]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f["file"]},
                    "region": {"startLine": f["line"], "startColumn": 1},
                }
            }],
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "path-guard-baseline",
                    "informationUri": "https://github.com/Binzi-z",
                    "rules": rules,
                }
            },
            "results": results,
        }],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="regex path-traversal baseline")
    parser.add_argument("--sarif", metavar="PATH", help="把 SARIF 2.1.0 写到 PATH（- 表示 stdout）")
    args = parser.parse_args()

    findings = scan()
    if args.sarif:
        text = json.dumps(to_sarif(findings), ensure_ascii=False, indent=2) + "\n"
        if args.sarif == "-":
            sys.stdout.write(text)
        else:
            with open(args.sarif, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(text)
            print(
                "wrote %d findings (%d rules) -> %s"
                % (len(findings), len({f["ruleId"] for f in findings}), args.sarif),
                file=sys.stderr,
            )
    else:
        json.dump({"findings": findings}, sys.stdout, ensure_ascii=False, indent=1)
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
