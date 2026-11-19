/**
 * 管理后台：导出文件下载，路径先过 resolveWithin。
 */
const express = require("express");
const { EXPORT_DIR, forward } = require("../lib/util");
const { resolveWithin } = require("../lib/paths");

const router = express.Router();

router.get("/exports/invoice", (req, res) => {
  const name = forward(req.query.invoice);
  const target = resolveWithin(EXPORT_DIR, "invoices", name);
  return res.sendFile(target);
});

module.exports = router;
