/**
 * 管理后台：归档解压，每个条目先过 resolveWithin 再落盘。
 */
const fs = require("fs");
const path = require("path");
const express = require("express");
const AdmZip = require("adm-zip");
const { DATA_DIR } = require("../lib/util");
const { resolveWithin } = require("../lib/paths");

const EXTRACT_DIR = path.join(DATA_DIR, "archive-admin");
const router = express.Router();

router.post("/archive/extract", async (req, res) => {
  const zip = new AdmZip(Buffer.from(req.body.archive, "base64"));
  for (const entry of zip.getEntries()) {
    const target = resolveWithin(EXTRACT_DIR, entry.entryName);
    await fs.promises.writeFile(target, entry.getData());
  }
  res.json({ extracted: zip.getEntries().length });
});

module.exports = router;
