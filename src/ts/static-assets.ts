/**
 * 静态资源路由：按请求头里的租户选择 public 子目录。
 *
 * 租户值来自 x-tenant-id，直接拼到 PUBLIC_ROOT 下。
 */
import express from "express";
import * as path from "path";
import { DATA_DIR } from "../lib/util";

export function mountTenantAssets(app: express.Express): void {
  app.use("/assets", (req, res, next) => {
    const tenant = String(req.headers["x-tenant-id"] || "public");
    const root = path.join(DATA_DIR, "public", tenant);
    express.static(root)(req, res, next);
  });
}
