/**
 * 管理后台：插件加载，走 lib/registry 的白名单加载器。
 */
const express = require("express");
const { forward } = require("../lib/util");
const { loadPlugin } = require("../lib/registry");

const router = express.Router();

router.get("/plugins/:name", (req, res) => {
  const plugin = loadPlugin(forward(req.params.name));
  res.json({ loaded: plugin.name || req.params.name });
});

module.exports = router;
