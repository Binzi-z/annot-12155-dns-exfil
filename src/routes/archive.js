/**
 * 归档解压：把 zip 内的文件按条目路径落盘。
 *
 * 条目路径来自上传的压缩包本身，攻击者可以写入 ../ 跳出 EXTRACT_DIR。
 */
const fs = require("fs");
const path = require("path");
const express = require("express");
const AdmZip = require("adm-zip");
const { DATA_DIR } = require("../lib/util");

const EXTRACT_DIR = path.join(DATA_DIR, "archive");
const router = express.Router();

router.post("/api/archive/extract", async (req, res) => {
  const zip = new AdmZip(Buffer.from(req.body.archive, "base64"));
  for (const entry of zip.getEntries()) {
    await fs.promises.writeFile(path.join(EXTRACT_DIR, entry.entryName), entry.getData());
  }
  res.json({ extracted: zip.getEntries().length });
});

router.post("/api/archive/restore", async (req, res) => {
  const { entries } = req.body;
  for (const item of entries) {
    await fs.promises.mkdir(path.dirname(path.join(EXTRACT_DIR, item.path)), { recursive: true });
    await fs.promises.writeFile(path.join(EXTRACT_DIR, item.path), Buffer.from(item.data, "base64"));
  }
  res.json({ restored: entries.length });
});

module.exports = router;
