/**
 * 安全版本：所有路径先过 resolveWithin 再交给 fs / sendFile。
 *
 * 这是同一份报表服务里的对照实现，用来区分真正的目录边界检查。
 */
import * as fs from "fs";
import { DATA_DIR, forward } from "../lib/util";
import { resolveWithin } from "../lib/paths";

export function readSafeReport(name: string): string {
  const target = resolveWithin(DATA_DIR, "reports", forward(name));
  return fs.readFileSync(target, "utf8");
}

export function sendSafeExport(
  res: { sendFile: (pathname: string) => void },
  name: string
): void {
  res.sendFile(resolveWithin(DATA_DIR, "exports", forward(name)));
}
