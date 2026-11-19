/**
 * 日志查看：按服务名与日期读取运行日志。
 *
 * 服务名来自路由参数，日期也来自路由参数，直接拼进 LOG_DIR。
 */
const fs = require("fs");
const path = require("path");
const express = require("express");
const { LOG_DIR } = require("../lib/util");

const router = express.Router();

router.get("/api/logs/:service", (req, res) => {
  const { service } = req.params;
  const body = fs.readFileSync(path.join(LOG_DIR, service + ".log"), "utf8");
  res.type("text/plain").send(body);
});

router.get("/api/logs/date/:date", (req, res) => {
  const { date } = req.params;
  const stream = fs.createReadStream(LOG_DIR + "/" + date + "/app.log");
  stream.on("error", () => res.status(404).end());
  stream.pipe(res);
});

module.exports = router;
