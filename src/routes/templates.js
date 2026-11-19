/**
 * 模板预览：业务侧按主题名与片段名渲染，名字来自查询串与请求体。
 *
 * 实际的文件读取发生在 src/lib/template-engine.js 的 renderTemplate /
 * includePartial 里，属于跨模块传播的 sink。
 */
const express = require("express");
const { forward } = require("../lib/util");
const { renderTemplate, includePartial } = require("../lib/template-engine");

const router = express.Router();

router.get("/api/templates/preview", (req, res) => {
  const html = renderTemplate(forward(req.query.theme), { body: req.query.body });
  res.type("text/html").send(html);
});

router.post("/api/templates/partial", (req, res) => {
  const html = includePartial(forward(req.body?.partial), { rows: [] });
  res.type("text/html").send(html);
});

module.exports = router;
