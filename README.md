# DNS 外传追踪

超长子域查询与主机登录交织，夜间解析量翻倍。

```
logs/auth.log   860 行（合成，含 2 起真实事件）
labels.json     2 个标注事件
detector/detector.py  基线检测器
tests/          骨架测试
```

## Run

```bash
python -m pytest tests -q
python detector/detector.py logs/auth.log findings.json
```

## 检测逻辑

`detector/detector.py` 先聚合再关联，产出 `findings` + `needs_review`:

- `dns_tunnel`: 按 (源 IP, 目标域) 聚合查询，三因子加权 ——
  查询频率 0.30 / 子域熵 0.40 / 目标域集中度 0.30，≥0.75 且 ≥8 条才告警；
  CDN/监控域走白名单直接排除。
- `lateral_movement`: 同账号 120 秒内跨主机登录，且与隧道告警关联或双 IP 稀有，
  避免 svc-dns 常规跨机登录误报。
- 每条告警含时间窗口、实体、按序事件链和各因子权重；拿不准的进
  `needs_review` 并写明缺什么证据。

## 标注事件

| kind | 说明 |
|---|---|
| `dns_tunnel` | DNS 隧道外传 |
| `lateral_movement` | 同一凭据跨主机横向移动 |

日志里另有故意放入的**良性相似流量**（少量失败后成功、被拒绝的少量探测），任何命中都算误报。
