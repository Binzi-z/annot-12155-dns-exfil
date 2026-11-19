/**
 * 管理后台：报表下载，统一走 resolveWithin 做目录边界校验。
 */
const fs = require("fs");
const express = require("express");
const { DATA_DIR, forward } = require("../lib/util");
const { resolveWithin } = require("../lib/paths");

const router = express.Router();

router.get("/reports/download", (req, res) => {
  const name = forward(req.query.report);
  const target = resolveWithin(DATA_DIR, "reports", name);
  const body = fs.readFileSync(target, "utf8");
  res.type("text/csv").send(body);
});

module.exports = router;
