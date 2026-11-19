/**
 * 插件注册表：按名字加载 plugins 目录下的扩展。
 *
 * 插件名必须命中 ALLOWED_PLUGINS；命中后再拼路径，
 * 因此这里的 path.join / require 组合是受白名单保护的加载点。
 */
const path = require("path");
const { forward } = require("./util");

const PLUGIN_DIR = path.join(__dirname, "..", "..", "plugins");
const ALLOWED_PLUGINS = new Set(["csv", "pdf", "xlsx"]);

function loadPlugin(name) {
  const key = forward(name);
  if (!ALLOWED_PLUGINS.has(key)) {
    const err = new Error("plugin not allowed: " + key);
    err.code = "EPLUGIN";
    throw err;
  }
  return require(path.join(PLUGIN_DIR, key));
}

module.exports = { ALLOWED_PLUGINS, loadPlugin };
