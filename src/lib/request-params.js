/**
 * 请求参数抽取：把不同来源统一成字符串，供路由层使用。
 *
 * 这里只负责取值与去空白，不做路径边界判断。
 * 三个函数的调用方分布在不同路由文件中，属于跨模块传播的入口。
 */
const { forward } = require("./util");

/**
 * 从查询串取文件名。支持 ?file=... 与 ?file[]=... 两种历史写法。
 */
function fileParam(req) {
  const { file } = req.query || {};
  const raw = Array.isArray(file) ? file[file.length - 1] : file;
  return forward(raw);
}

/**
 * 从请求头取租户标识；缺省时回落到 query 上的 tenant。
 */
function tenantFromHeader(req) {
  const tenant = req.headers?.["x-tenant-id"];
  const fallback = req.query?.tenant;
  return forward(tenant ?? fallback);
}

/**
 * 从上传对象取原始文件名；multer 给出的字段可能缺失。
 */
function uploadName(file) {
  return forward(file?.originalname);
}

module.exports = { fileParam, tenantFromHeader, uploadName };
