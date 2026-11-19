/**
 * 管理后台：静态资源挂载，租户根目录来自固定映射表。
 */
const path = require("path");
const express = require("express");
const { DATA_DIR } = require("../lib/util");

const TENANT_ROOTS = new Map([
  ["acme", path.join(DATA_DIR, "public", "acme")],
  ["globex", path.join(DATA_DIR, "public", "globex")],
]);

const router = express.Router();

router.use("/assets/:tenant", (req, res, next) => {
  const root = TENANT_ROOTS.get(req.params.tenant);
  if (!root) return res.status(404).end();
  express.static(root)(req, res, next);
});

module.exports = router;
