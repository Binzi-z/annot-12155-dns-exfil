/**
 * 管理后台：备份恢复，快照名先过 resolveWithin。
 */
const fs = require("fs");
const path = require("path");
const express = require("express");
const { BACKUP_DIR, forward } = require("../lib/util");
const { resolveWithin } = require("../lib/paths");

const router = express.Router();

router.post("/backups/restore", (req, res) => {
  const name = forward(req.body?.snapshot);
  const src = resolveWithin(BACKUP_DIR, name);
  fs.copyFileSync(src, path.join(BACKUP_DIR, "restored.db"));
  res.json({ restored: true });
});

module.exports = router;
