/**
 * 插件加载器：插件目录来自环境变量配置。
 *
 * 配置项被直接拼进 require 路径，没有白名单校验。
 */
import * as path from "path";

const PLUGIN_ROOT = process.env.PLUGIN_ROOT || path.join(__dirname, "..", "..", "plugins");

export function loadConfiguredPlugin(): unknown {
  const configured = process.env.PLUGIN_NAME || "default";
  return require(path.join(PLUGIN_ROOT, configured));
}
