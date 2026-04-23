/* istanbul ignore file */

import fs from "fs";
import os from "os";
import path from "path";
import { execute } from "./Executor";

/**
 * Pattern to detect a GitHub archive URL so we can build from source.
 * e.g. https://github.com/idlab-discover/aibomgen-cli/archive/refs/heads/main.zip
 */
const archivePattern = /https:..github.com.([-\w]+).([-\w]+).archive.refs.heads.([-\w]+).zip/;

/**
 * Downloads and builds aibomgen-cli from a GitHub archive URL using `go build`.
 * Returns the path to the built binary, or an empty string if the URL is not
 * an archive URL.
 *
 * aibomgen-cli is a Go CLI tool; building from source requires Go to be
 * available on the runner.
 */
export async function downloadAIBoMGenFromZip(url: string): Promise<string> {
  const groups = url.match(archivePattern);
  if (groups && groups.length > 3) {
    const repoName = groups[2];
    const branch = groups[3];
    const cwd = process.cwd();
    try {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "aibomgen"));
      process.chdir(tmpDir);
      await execute("curl", ["-L", "-o", `${branch}.zip`, url]);
      await execute("unzip", [`${branch}.zip`]);
      const repoDir = path.join(tmpDir, `${repoName}-${branch}`);
      process.chdir(repoDir);
      // Build the Go binary
      await execute("go", ["build", "-o", "aibomgenbin", "."]);
      return path.join(repoDir, "aibomgenbin");
    } finally {
      process.chdir(cwd);
    }
  }
  return "";
}
