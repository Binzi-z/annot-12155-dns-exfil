/**
 * 静态资源：按租户目录挂载 public，以及发送单个资源文件。
 *
 * 租户来自路由参数，资源相对路径来自查询串；两者都没有目录边界校验。
 */
const path = require("path");
const express = require("express");
const { DATA_DIR } = require("../lib/util");

const PUBLIC_DIR = path.join(DATA_DIR, "public");
const router = express.Router();

router.use("/assets/:tenant", (req, res, next) => {
  const root = path.join(PUBLIC_DIR, req.params.tenant);
  express.static(root)(req, res, next);
});

router.get("/api/assets/file", (req, res) => {
  const target = path.resolve(PUBLIC_DIR, String(req.query.path || ""));
  res.sendFile(target);
});

module.exports = router;
