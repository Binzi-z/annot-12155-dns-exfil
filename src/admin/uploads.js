/**
 * 管理后台：附件落盘与复制。
 *
 * 落盘只保留 basename；复制先查 UPLOAD_ALLOWLIST。
 */
const fs = require("fs");
const path = require("path");
const express = require("express");
const { UPLOAD_DIR } = require("../lib/util");
const { safeBasename } = require("../lib/paths");
const { uploadName } = require("../lib/request-params");

const ALLOWED_UPLOADS = new Set(["avatar.png", "report.csv", "invoice.pdf"]);
const router = express.Router();

router.post("/uploads", async (req, res) => {
  const base = safeBasename(uploadName(req.file));
  const dest = path.join(UPLOAD_DIR, "incoming", base);
  await fs.promises.writeFile(dest, req.file.buffer);
  res.json({ stored: base });
});

router.post("/uploads/copy", async (req, res) => {
  const { name } = req.body;
  if (!ALLOWED_UPLOADS.has(name)) {
    return res.status(400).json({ error: "not allowed" });
  }
  await fs.promises.copyFile(
    path.join(UPLOAD_DIR, "incoming", name),
    path.join(UPLOAD_DIR, "final", name)
  );
  res.json({ ok: true });
});

module.exports = router;
