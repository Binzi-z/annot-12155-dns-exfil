/**
 * 管理后台：模板预览，只允许 KNOWN_TEMPLATES 里的模板名。
 */
const express = require("express");
const { forward } = require("../lib/util");
const { renderKnown } = require("../lib/template-engine");

const router = express.Router();

router.get("/templates/preview", (req, res) => {
  const html = renderKnown(forward(req.query.theme), { body: req.query.body });
  res.type("text/html").send(html);
});

module.exports = router;
