/**
 * 模板渲染：读取 HBS 片段并按 {{key}} 占位符替换。
 *
 * 渲染器只负责文件读取与变量替换；模板名合法性由调用方保证。
 * 业务路由把主题名直接传进来，管理后台走 KNOWN_TEMPLATES 白名单。
 */
const fs = require("fs");
const path = require("path");
const { TEMPLATE_DIR } = require("./util");

const KNOWN_TEMPLATES = {
  report: "report.hbs",
  notice: "notice.hbs",
  dashboard: "dashboard.hbs",
};

function fill(source, data) {
  return source.replace(/\{\{(\w+)\}\}/g, (match, key) => {
    const value = data ? data[key] : "";
    return value === undefined || value === null ? "" : String(value);
  });
}

/**
 * 主题模板：name 直接决定模板文件名。
 */
function renderTemplate(name, data) {
  const source = fs.readFileSync(path.join(TEMPLATE_DIR, name + ".hbs"), "utf8");
  return fill(source, data);
}

/**
 * 局部片段：partials 子目录下的 include。
 */
function includePartial(name, data) {
  const source = fs.readFileSync(path.join(TEMPLATE_DIR, "partials", name + ".hbs"), "utf8");
  return fill(source, data);
}

/**
 * 已知模板：先从白名单取文件名，再读取。
 */
function renderKnown(name, data) {
  const file = KNOWN_TEMPLATES[name];
  if (!file) {
    throw new Error("unknown template: " + name);
  }
  const source = fs.readFileSync(path.join(TEMPLATE_DIR, "known", file), "utf8");
  return fill(source, data);
}

module.exports = { renderTemplate, includePartial, renderKnown };
