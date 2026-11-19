/**
 * 备份快照：恢复与导出归档文件。
 *
 * 快照名来自请求体与查询串，参与 BACKUP_DIR 下的路径计算。
 */
const fs = require("fs");
const path = require("path");
const express = require("express");
const { BACKUP_DIR, forward } = require("../lib/util");

const router = express.Router();

router.post("/api/backups/restore", (req, res) => {
  const { snapshot } = req.body;
  const src = path.join(BACKUP_DIR, snapshot);
  fs.copyFileSync(src, path.join(BACKUP_DIR, "restored.db"));
  res.json({ restored: true });
});

router.post("/api/backups/export", (req, res) => {
  const name = forward(req.body?.name);
  fs.cpSync(path.join(BACKUP_DIR, "latest"), path.join(BACKUP_DIR, name), { recursive: true });
  res.json({ ok: true });
});

module.exports = router;
