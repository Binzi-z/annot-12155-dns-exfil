/**
 * 路径边界工具：在拼接后做一次 resolve + 前缀校验。
 *
 * 注意：本文件的 resolveWithin() 是仓库里唯一被认可的目录边界检查。
 * 直接 path.join(DATA_DIR, name) 不保证结果仍落在 DATA_DIR 内，因为
 * name 可以包含 ../ 或绝对路径。
 */
const path = require("path");

const SEP = path.sep;

/**
 * 把用户提供的相对路径限制在 base 目录内。
 * 越界或绝对路径一律抛错，由调用方转成 400。
 */
function resolveWithin(base, ...parts) {
  const root = path.resolve(base);
  const target = path.resolve(root, ...parts);
  if (target !== root && !target.startsWith(root + SEP)) {
    const err = new Error("path escapes base directory");
    err.code = "EPATHBOUNDARY";
    throw err;
  }
  return target;
}

/**
 * 只保留文件名最后一段，用于上传落盘。
 * 这个写法能挡住 ../，但挡不住同目录下的符号链接。
 */
function safeBasename(name) {
  return path.basename(String(name || ""));
}

module.exports = { resolveWithin, safeBasename };
