/**
 * 导出文件下载：发票 PDF 与对账单归档。
 *
 * sendFile / download 的路径由查询串与路由参数决定。
 */
const path = require("path");
const express = require("express");
const { EXPORT_DIR, forward } = require("../lib/util");

const router = express.Router();

router.get("/api/exports/invoice", (req, res) => {
  const name = forward(req.query.invoice);
  // 动态路径直接交给 sendFile
  return res.sendFile(path.join(EXPORT_DIR, "invoices", name));
});

router.get("/api/exports/statement/:period", (req, res) => {
  const { period } = req.params;
  const file = path.join(EXPORT_DIR, "statements", period + ".pdf");
  res.download(file, "statement.pdf");
});

module.exports = router;
