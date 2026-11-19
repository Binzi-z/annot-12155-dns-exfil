# JS/TS 源码树路径穿越静态分析（topic 12155）

交接文档只有一句手写批注：**路径穿越的坑有四处，别信 grep**。这个仓库是那四处的
真实语料：一个 Node/Express 报表网关，既包含直接拼路径的漏洞，也包含同一批 sink
的净化写法（`path.resolve` + 前缀校验、`path.basename`、白名单）。

`baseline/scan.py` 是改进前的正则扫描器：召回 100%，误报 32.4%。目标实现要把它
换成语义/污点分析，并在 50 条标注样本上做到召回 ≥85%、误报 ≤15%。

## 语料概览

| 项 | 数量 | 说明 |
|---|---|---|
| JS/TS 源文件 | 28 | 24 个 `.js` + 4 个 `.ts` |
| 真漏洞标注 | 25 | `labels.json`，含 file/line/sink/ruleId |
| 未标注 decoy | 12 | 同类 sink，但先做了目录边界检查或白名单 |
| 标注变更样本 | 50 | `samples/changes/*.json`：25 vulnerable + 12 safe + 13 benign |

## 目录

```
src/index.js                  Express 装配，业务路由 + 管理后台路由
src/routes/                   9 个业务路由：直接拼路径，25 条真漏洞都在这里
  reports.js                  fs.readFileSync / readFile / createReadStream / Promise 链
  exports.js                  res.sendFile / res.download
  uploads.js                  上传落盘 / 复制 / 改名
  plugins.js                  require(动态路径) ×2
  archive.js                  zip 解压落盘 / 归档恢复（zip slip）
  templates.js                调用模板 include（sink 在 lib/template-engine.js）
  assets.js                   express.static 动态根目录 / sendFile
  logs.js                     按服务名、日期读日志
  backup.js                   备份快照复制 / 目录复制
src/admin/                    9 个管理后台路由：同样的 sink，先过 resolveWithin / 白名单
src/lib/
  util.js                     DATA_DIR 等常量 + forward()（只 trim，不净化）
  paths.js                    resolveWithin()（path.resolve + 前缀校验）+ safeBasename()
  request-params.js           跨模块取参：query / header / upload originalname
  registry.js                 插件白名单 + 动态 require
  template-engine.js          模板 include（2 个漏洞 + 1 个白名单 decoy）
src/ts/
  report-service.ts           请求头租户 + 查询参数 -> readFileSync / require
  plugin-loader.ts            配置项 -> require（动态模块路径）
  static-assets.ts            x-tenant-id -> express.static 根目录
  safe-report.ts              resolveWithin 之后的 readFileSync / sendFile（decoy）
labels.json                   25 条真漏洞（file/line/sink/ruleId/source/entry）
samples/changes/              50 条变更样本（before/after）
samples/eval_samples.py       对 50 条样本做 baseline 回测
baseline/scan.py              正则 baseline，支持 JSON 与 SARIF 2.1.0
eval.py                       读简单 JSON 或 SARIF，算 recall / precision / FP rate
tests/test_baseline.py        labels 行号、召回/误报、50 样本、node --check、SARIF
```

## 四类落点与七类规则

题面点名的四处落点都已覆盖，另外补了 `sendFile`、动态 `require`、写/复制/改名三类。

| 规则 | sink 形态 | 真漏洞 | decoy |
|---|---|---|---|
| `PT-FS-READ-001` | `fs.readFile` / `readFileSync` / `createReadStream` + 动态路径 | 7 | 3 |
| `PT-PATH-JOIN-002` | `path.join` 结果未校验就写/复制/改名 | 5 | 3 |
| `PT-SEND-FILE-003` | `res.sendFile` / `res.download` 动态路径 | 3 | 2 |
| `PT-DYNAMIC-REQUIRE-004` | `require(动态路径)` | 4 | 1 |
| `PT-STATIC-ROOT-005` | `express.static` 动态根目录 | 2 | 1 |
| `PT-ZIP-SLIP-006` | 解压条目路径未校验即落盘 | 2 | 1 |
| `PT-TEMPLATE-INCLUDE-007` | 模板 include 文件名来自动态输入 | 2 | 1 |

## 源与传播

- **源**：`req.query`、`req.params`、`req.body`、上传文件 `originalname`、
  `x-tenant-id` 请求头、`process.env` 配置项，六类都有真实调用点。
- **跨模块**：`src/routes/templates.js` 只传模板名，真正的 `fs.readFileSync` 在
  `src/lib/template-engine.js`；`src/lib/request-params.js` 把 query/header/upload
  抽出来后交给不同路由。
- **对象解构**：`const { report } = req.query;`、`const { name } = req.params;`。
- **可选链**：`req.headers?.["x-tenant-id"]`、`req.body?.from`、`file?.originalname`。
- **Promise 链**：`src/routes/reports.js` 的 `/api/reports/stream`，请求参数经
  `Promise.resolve(...).then(...).then(...)` 传到 `fs.readFileSync`。
- **净化写法**：`resolveWithin()`（`path.resolve` 后校验 `startsWith(root + sep)`）、
  `path.basename()`、固定 Map/Set 白名单。没有用 `path.normalize` 冒充净化。

## decoy 的净化方式

| 位置 | 净化写法 |
|---|---|
| `src/admin/reports.js`、`src/admin/exports.js`、`src/ts/safe-report.ts` | `resolveWithin()` |
| `src/admin/uploads.js` | `safeBasename()` / `ALLOWED_UPLOADS` 白名单 |
| `src/lib/registry.js` | `ALLOWED_PLUGINS` 白名单后再 `require` |
| `src/lib/template-engine.js` 的 `renderKnown` | `KNOWN_TEMPLATES` 白名单 |
| `src/admin/archive.js` | 每个 zip 条目先 `resolveWithin` |
| `src/admin/assets.js` | 固定 `TENANT_ROOTS` Map |
| `src/admin/logs.js` | `SERVICES` 白名单 |

这些 decoy 故意不进 `labels.json`，任何命中都算误报。

## 基线现状（实测）

```
labels=25 findings=37 TP=25 FP=12 FN=0
recall=100.0% precision=67.6% false_positive_rate=32.4%
```

`baseline/scan.py` 只做行级正则：只要出现 sink 调用就报，12 个 decoy 全部中招。
这正好对应题面要解决的误报来源：**同形状但已净化的写法**、**包装函数内部的 sink**
、**白名单分支**。目标实现应把误报压到 15% 以下，同时保持 ≥85% 召回。

## 跑法

```powershell
# 1. 基线 + 评测（JSON）
python baseline/scan.py > findings.json
python eval.py findings.json

# 2. SARIF 输出 + 同一套评测
python baseline/scan.py --sarif findings.sarif
python eval.py findings.sarif

# 3. 50 条标注样本回测
python samples/eval_samples.py

# 4. 语料自检（labels 行号、样本、node --check、SARIF）
python -m pytest tests -q
```

可选门槛：`python eval.py findings.json --min-recall 0.85 --max-fp-rate 0.15`
（baseline 会在误报门槛上失败，这是预期的）。

> Windows PowerShell 5.1 的 `>` 会把 stdout 写成 UTF-16LE；`eval.py` 已依次尝试
> UTF-8 / UTF-16 / GB18030 解码，换 cmd、bash 或 PowerShell 都能跑。

## 样本格式

`samples/changes/cNNN.json` 每条包含：

```json
{
  "id": "c001",
  "kind": "vulnerable",
  "file": "src/routes/reports.js",
  "line": 20,
  "ruleId": "PT-FS-READ-001",
  "sink": "fs.readFileSync(path.join(...))",
  "summary": "引入路径穿越：报表下载…",
  "source": "req.query.report",
  "entry": "GET /api/reports/download",
  "before": "…改动前代码…",
  "after": "…改动后代码（与当前语料逐字一致）…",
  "expect": { "vulnerable": true }
}
```

`safe` 样本的 `before` 是未净化写法、`after` 是当前净化写法，`expect.reason`
写明用了哪条边界检查；`benign` 是与路径无关的重构。

## 题面七条要求的语料支撑度

| # | 要求 | 状态 |
|---|---|---|
| 1 | 分析对象是 JavaScript/TypeScript 源码树 | ✅ 28 个 JS/TS 文件，含 4 个 `.ts` |
| 2 | 落点覆盖 fs 拼接、静态目录、解压落盘、模板 include | ✅ 四处都有真漏洞和 decoy |
| 3 | 源覆盖路由参数、上传文件名、请求头、配置项 | ✅ 六类源都有调用点 |
| 4 | 跨模块传播，含解构、可选链、Promise 链；识别 `path.normalize` 之外的净化 | ✅ 跨模块 + 三种写法 + `resolveWithin`/basename/白名单 |
| 5 | 不许引现成规则集，只允许语法解析库自建 AST 与符号表 | ✅ 仓库没有 semgrep/eslint 规则包，baseline 只是待替换的正则起点 |
| 6 | 输出 SARIF，CI 新增即阻断 | ⚠️ 部分：`--sarif` 与 `eval.py` 的 SARIF 读取已就绪；CI gate 未接线，留给实现者 |
| 7 | 50 条样本召回 ≥85%/误报 ≤15%；20 万行 <3 分钟、增量 <15 秒 | ⚠️ 部分：50 条样本与评测脚本已就绪；20 万行性能语料和增量 harness 不在本仓库 |

## 边界自证素材

- 反例：`src/routes/assets.js` 用了 `path.resolve(PUBLIC_DIR, req.query.path)`，
  但没有前缀校验，仍然可以跳出目录；`path.resolve` 本身不是 sanitizer。
- 正例：`src/lib/paths.js` 的 `resolveWithin()` 先 `path.resolve` 再比较
  `root + path.sep` 前缀，`src/admin/*` 和 `src/ts/safe-report.ts` 都在用。
- 路径比较的坑：`startsWith(root)` 会误放行 `root-evil/`，所以正例比较的是
  `root + path.sep`；Windows 下还要考虑 `\` 与大小写，题面要求实现者说明怎么防。
