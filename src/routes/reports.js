/**
 * 报表下载：从 DATA_DIR/reports 读取 CSV，支持按报表名与原始路径两种入口。
 *
 * 入口参数来自 req.query / req.params，forward() 只去空白。
 */
const fs = require("fs");
const path = require("path");
const express = require("express");
const { DATA_DIR, forward } = require("../lib/util");
const { fileParam } = require("../lib/request-params");

const router = express.Router();

router.get("/api/reports/download", (req, res) => {
  const { report } = req.query;
  const name = forward(report);
  const target = path.join(DATA_DIR, "reports", name);

  // 直接按请求参数读取数据目录下的文件
  const body = fs.readFileSync(target, "utf8");
  res.type("text/csv").send(body);
});

router.get("/api/reports/raw", (req, res) => {
  const file = fileParam(req);

  // 字符串拼接后再交给 readFile
  fs.readFile(DATA_DIR + "/raw/" + file, "utf8", (err, data) => {
    if (err) return res.status(404).json({ error: "not found" });
    res.type("text/plain").send(data);
  });
});

router.get("/api/reports/preview/:name", (req, res) => {
  const { name } = req.params;
  const stream = fs.createReadStream(path.join(DATA_DIR, "previews", name));
  stream.on("error", () => res.status(404).end());
  stream.pipe(res);
});

router.get("/api/reports/stream", (req, res) => {
  const name = forward(req.query.report);
  Promise.resolve(name)
    .then((value) => path.join(DATA_DIR, "streams", value))
    .then((target) => fs.readFileSync(target, "utf8"))
    .then((body) => res.type("text/csv").send(body))
    .catch(() => res.status(404).end());
});

module.exports = router;
