/**
 * 通用工具：路径常量、请求参数转发与输出编码。
 *
 * forward() 只做 String() + trim()，不承担任何安全职责；
 * 需要限制目录时使用 paths.resolveWithin()，需要白名单时在调用方判断。
 */
const path = require("path");

/** 报表、上传、模板、日志等数据的根目录。 */
const DATA_DIR = process.env.DATA_DIR || "/srv/report-data";
const UPLOAD_DIR = process.env.UPLOAD_DIR || path.join(DATA_DIR, "uploads");
const TEMPLATE_DIR = process.env.TEMPLATE_DIR || path.join(DATA_DIR, "templates");
const LOG_DIR = process.env.LOG_DIR || path.join(DATA_DIR, "logs");
const BACKUP_DIR = process.env.BACKUP_DIR || path.join(DATA_DIR, "backups");
const EXPORT_DIR = process.env.EXPORT_DIR || path.join(DATA_DIR, "exports");

/**
 * 转发请求参数：空值兜底为空串，只去掉首尾空白。
 * 这个函数不做目录边界检查，也不做字符白名单。
 */
function forward(value) {
  if (value === undefined || value === null) return "";
  return String(value).trim();
}

/**
 * 输出编码：把上游内容回显到页面前做一次 HTML 转义。
 */
function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

module.exports = {
  DATA_DIR,
  UPLOAD_DIR,
  TEMPLATE_DIR,
  LOG_DIR,
  BACKUP_DIR,
  EXPORT_DIR,
  forward,
  escapeHtml,
};
