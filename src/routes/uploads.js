/**
 * 附件上传：落盘、复制与改名。
 *
 * 文件名来自 multer 的 originalname 或请求体，未做目录边界检查。
 */
const fs = require("fs");
const path = require("path");
const express = require("express");
const multer = require("multer");
const { UPLOAD_DIR } = require("../lib/util");
const { uploadName } = require("../lib/request-params");

const router = express.Router();
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
});

router.post("/api/uploads", upload.single("file"), async (req, res) => {
  const name = uploadName(req.file);
  const dest = path.join(UPLOAD_DIR, "incoming", name);

  await fs.promises.writeFile(dest, req.file.buffer);
  res.json({ stored: name });
});

router.post("/api/uploads/copy", async (req, res) => {
  const from = path.join(UPLOAD_DIR, "incoming", req.body?.from || "");
  const to = path.join(UPLOAD_DIR, "final", req.body?.to || "");
  await fs.promises.copyFile(from, to);
  res.json({ ok: true });
});

router.post("/api/uploads/rename", async (req, res) => {
  const { oldName, newName } = req.body;
  await fs.promises.rename(
    path.join(UPLOAD_DIR, "final", oldName),
    path.join(UPLOAD_DIR, "final", newName)
  );
  res.json({ ok: true });
});

module.exports = router;
