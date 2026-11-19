/**
 * 多租户报表服务：租户来自请求头，报表名来自查询串。
 *
 * TypeScript 入口，读取与插件加载都在本文件内完成。
 */
import * as fs from "fs";
import * as path from "path";
import { DATA_DIR, forward } from "../lib/util";
import { tenantFromHeader } from "../lib/request-params";

interface ReportRequest {
  headers: Record<string, string | undefined>;
  query: Record<string, string | undefined>;
}

export function readTenantReport(req: ReportRequest): string {
  const tenant = tenantFromHeader(req);
  const report = forward(req.query.report);

  const file = path.join(DATA_DIR, "tenants", tenant, "reports", report);
  return fs.readFileSync(file, "utf8");
}

export function loadExporter(name: string): unknown {
  const exporter = require(path.join(DATA_DIR, "exporters", name));
  return exporter;
}
