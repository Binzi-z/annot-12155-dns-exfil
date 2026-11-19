/**
 * 管理后台：日志查看，服务名必须在 SERVICES 白名单内。
 */
const fs = require("fs");
const path = require("path");
const express = require("express");
const { LOG_DIR } = require("../lib/util");

const SERVICES = new Set(["api", "worker", "scheduler"]);
const router = express.Router();

router.get("/logs/:service", (req, res) => {
  const { service } = req.params;
  if (!SERVICES.has(service)) {
    return res.status(404).json({ error: "unknown service" });
  }
  const body = fs.readFileSync(path.join(LOG_DIR, service + ".log"), "utf8");
  res.type("text/plain").send(body);
});

module.exports = router;
