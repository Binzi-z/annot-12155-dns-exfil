/**
 * 插件加载：按名称从 plugins 目录载入扩展。
 *
 * 插件名来自路由参数或请求体，直接参与 require 的路径计算。
 */
const path = require("path");
const express = require("express");
const { forward } = require("../lib/util");

const PLUGIN_DIR = path.join(__dirname, "..", "..", "plugins");
const router = express.Router();

router.get("/api/plugins/:name", (req, res) => {
  const { name } = req.params;
  const plugin = require(path.join(PLUGIN_DIR, name));
  res.json({ loaded: plugin.name || name });
});

router.post("/api/plugins/select", (req, res) => {
  const { plugin: selected } = req.body;
  const mod = require("../../plugins/" + forward(selected));
  res.json({ loaded: mod.name || selected });
});

module.exports = router;
