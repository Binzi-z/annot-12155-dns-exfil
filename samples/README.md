# samples/changes

50 条标注变更样本，对应 `src/` 下的真实代码。

| kind | 数量 | 含义 |
|---|---|---|
| `vulnerable` | 25 | 引入路径穿越；`file` + `line` 必须命中 `labels.json` |
| `safe` | 12 | 加固：同一 sink 改成 `resolveWithin` / basename / 白名单之后 |
| `benign` | 13 | 与路径无关的重构，不涉及 sink |

每条样本都有 `before` / `after` 两段代码，`after` 与当前仓库逐字一致。`expect`
给出回测期望：`vulnerable` 应被报出，`safe` / `benign` 不应被报出。

```powershell
python samples/eval_samples.py
```

当前 baseline 的回测结果：`recall=100.0%`、`false_positive_rate=32.4%`。误报全部
来自 12 条 `safe` 样本——正则 baseline 分不清「同一个 sink + 已净化」的写法。
