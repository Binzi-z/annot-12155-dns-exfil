/**
 * 报表网关入口：装配各业务路由与兜底错误处理。
 *
 * 业务路由在 src/routes 下，管理后台路由在 src/admin 下；
 * 两者都从请求中取路径片段，但只有 admin 侧统一走 paths.resolveWithin。
 */
const express = require("express");

const reports = require("./routes/reports");
const exportsRouter = require("./routes/exports");
const uploads = require("./routes/uploads");
const plugins = require("./routes/plugins");
const archive = require("./routes/archive");
const templates = require("./routes/templates");
const assets = require("./routes/assets");
const logs = require("./routes/logs");
const backup = require("./routes/backup");
const adminReports = require("./admin/reports");
const adminExports = require("./admin/exports");
const adminUploads = require("./admin/uploads");
const adminPlugins = require("./admin/plugins");
const adminArchive = require("./admin/archive");
const adminTemplates = require("./admin/templates");
const adminAssets = require("./admin/assets");
const adminLogs = require("./admin/logs");
const adminBackup = require("./admin/backup");

const app = express();
app.use(express.json({ limit: "2mb" }));

app.use("/", reports);
app.use("/", exportsRouter);
app.use("/", uploads);
app.use("/", plugins);
app.use("/", archive);
app.use("/", templates);
app.use("/", assets);
app.use("/", logs);
app.use("/", backup);
app.use("/admin", adminReports);
app.use("/admin", adminExports);
app.use("/admin", adminUploads);
app.use("/admin", adminPlugins);
app.use("/admin", adminArchive);
app.use("/admin", adminTemplates);
app.use("/admin", adminAssets);
app.use("/admin", adminLogs);
app.use("/admin", adminBackup);

app.get("/healthz", (req, res) => res.json({ ok: true }));

// 兜底错误处理：路径越界与未知异常分开返回，不把栈信息回给调用方
app.use((err, req, res, _next) => {
  if (err && err.code === "EPATHBOUNDARY") {
    return res.status(400).json({ error: "bad path" });
  }
  console.error("[gateway] unhandled error:", err && err.message);
  res.status(500).json({ error: "internal error" });
});

const port = Number(process.env.PORT || 8080);
app.listen(port, () => {
  console.log("[gateway] listening on " + port);
});

module.exports = app;
