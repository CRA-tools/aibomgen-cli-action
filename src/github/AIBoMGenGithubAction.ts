import * as core from "@actions/core";
import * as github from "@actions/github";
import * as cache from "@actions/tool-cache";
import { Release, ReleaseEvent } from "@octokit/webhooks-types";
import * as fs from "fs";
import os from "os";
import path from "path";
import { AIBoMGenOptions } from "../AIBoMGen";
import { VERSION } from "../AIBoMGenVersion";
import { downloadAIBoMGenFromZip } from "./AIBoMGenDownloader";
import { execute } from "./Executor";
import { dashWrap, debugLog, getClient } from "./GithubClient";
import { stringify } from "./Util";

export const AIBOMGEN_BINARY_NAME = "aibomgen-cli";
export const AIBOMGEN_VERSION = core.getInput("aibomgen-version") || VERSION;

const exeSuffix = process.platform === "win32" ? ".exe" : "";

/**
 * Maps the Node.js platform/arch to the goreleaser release asset name.
 *
 * goreleaser .goreleaser.yaml archive template:
 *   {{ .ProjectName }}_{{ .Version }}_{{ .Os }}_{{ .Arch }}
 *
 * {{ .Version }} does NOT include the leading "v" (e.g. "0.1.0" not "v0.1.0").
 * Extension: .tar.gz on Linux/macOS, .zip on Windows.
 */
function getReleaseAssetName(version: string): string {
  // Strip leading "v" to match goreleaser's {{ .Version }} template variable
  const versionNoV = version.replace(/^v/, "");

  const platformMap: Record<string, string> = {
    linux: "linux",
    darwin: "darwin",
    win32: "windows",
  };
  const archMap: Record<string, string> = {
    x64: "amd64",
    arm64: "arm64",
  };

  const platform = platformMap[process.platform] ?? process.platform;
  const arch = archMap[os.arch()] ?? os.arch();
  const ext = process.platform === "win32" ? "zip" : "tar.gz";

  return `${AIBOMGEN_BINARY_NAME}_${versionNoV}_${platform}_${arch}.${ext}`;
}

/**
 * Downloads the aibomgen-cli release binary for the current platform from
 * the GitHub Releases page of idlab-discover/aibomgen-cli.
 */
export async function downloadAIBoMGen(): Promise<string> {
  const version = AIBOMGEN_VERSION;
  const assetName = getReleaseAssetName(version);
  const url = `https://github.com/idlab-discover/aibomgen-cli/releases/download/${version}/${assetName}`;

  core.info(`Downloading aibomgen-cli from ${url}`);

  const downloadPath = await cache.downloadTool(url);

  let extractedDir: string;
  if (process.platform === "win32") {
    extractedDir = await cache.extractZip(downloadPath);
  } else {
    extractedDir = await cache.extractTar(downloadPath);
  }

  return path.join(extractedDir, `${AIBOMGEN_BINARY_NAME}${exeSuffix}`);
}

/**
 * Resolves (and caches) the path to the aibomgen-cli binary.
 *
 * Precedence:
 *   1. Build from a GitHub archive URL passed as aibomgen-version
 *   2. Previously cached binary for this version
 *   3. Fresh download from GitHub Releases
 */
export async function getAIBoMGenCommand(): Promise<string> {
  const name = AIBOMGEN_BINARY_NAME + exeSuffix;
  const version = AIBOMGEN_VERSION;

  // Allow passing a GitHub archive URL to build from source via go build
  const sourceBuilt = await downloadAIBoMGenFromZip(version);
  if (sourceBuilt) {
    core.info(`Using source-built aibomgen-cli: '${sourceBuilt}'`);
    return sourceBuilt;
  }

  let binaryPath = cache.find(name, version);
  if (!binaryPath) {
    binaryPath = await downloadAIBoMGen();
    binaryPath = await cache.cacheFile(binaryPath, name, name, version);
  }

  core.debug(`aibomgen-cli cached at: ${binaryPath}/${name}`);
  core.addPath(binaryPath);
  return `${binaryPath}/${name}`;
}

/**
 * Returns the output format from the action input.
 * Accepts "json" (CycloneDX JSON), "xml" (CycloneDX XML), or "auto".
 * Defaults to "json".
 */
export function getAIBomFormat(): AIBoMGenOptions["format"] {
  return (core.getInput("format") as AIBoMGenOptions["format"]) || "json";
}

/**
 * Returns a unique artifact name for the generated AIBOM file.
 */
export function getArtifactName(): string {
  const fileName = core.getInput("artifact-name");
  if (fileName) {
    return fileName;
  }

  const format = getAIBomFormat();
  const extension = format === "xml" ? "cyclonedx.xml" : "cyclonedx.json";

  const {
    repo: { repo },
    job,
    action,
  } = github.context;
  let stepName = action.replace(/__[-_a-z]+/, "");
  if (stepName) {
    stepName = `-${stepName}`;
  }
  return `${repo}-${job}${stepName}.${extension}`;
}

/**
 * Runs the aibomgen-cli `scan` subcommand.
 *
 * The scan command discovers Hugging Face model imports in source files inside
 * the given directory, fetches model metadata from the HF Hub, and writes one
 * AIBOM file per discovered model to the output path.
 *
 * IMPORTANT: output is written to files on disk — NOT to stdout.
 * The function returns the path where the CLI wrote the output file.
 *
 * CLI invocation shape:
 *   aibomgen-cli [--config <file>] scan \
 *     --input <dir> \
 *     --output <file> \
 *     --format json|xml \
 *     [--spec 1.4|1.5|1.6] \
 *     [--hf-token <token>] \
 *     [--hf-mode online|dummy] \
 *     [--hf-timeout <sec>] \
 *     --log-level quiet|standard|debug
 */
async function executeAIBoMGenScan(opts: AIBoMGenOptions): Promise<string[]> {
  const cmd = await getAIBoMGenCommand();

  // --config is a persistent root-level flag; it must appear before the subcommand
  const rootArgs: string[] = [];
  if (opts.configFile) {
    rootArgs.push("--config", opts.configFile);
  }

  const scanArgs: string[] = ["scan"];

  scanArgs.push("--input", opts.input.path);

  // Determine the output directory so we can glob for files after the scan.
  // The CLI names files like <modelid>_aibom.json — one per discovered model.
  let outputDir: string;
  if (opts.outputFile) {
    scanArgs.push("--output", opts.outputFile);
    outputDir = path.dirname(opts.outputFile);
  } else {
    // CLI default output directory
    outputDir = "dist";
  }

  if (opts.format && opts.format !== "auto") {
    scanArgs.push("--format", opts.format);
  }

  if (opts.specVersion) {
    scanArgs.push("--spec", opts.specVersion);
  }

  if (opts.hfToken) {
    scanArgs.push("--hf-token", opts.hfToken);
  }

  if (opts.hfMode) {
    scanArgs.push("--hf-mode", opts.hfMode);
  }

  if (opts.hfTimeout > 0) {
    scanArgs.push("--hf-timeout", String(opts.hfTimeout));
  }

  scanArgs.push("--log-level", opts.logLevel || "standard");

  const args = [...rootArgs, ...scanArgs];
  core.info(`[command]${cmd} ${args.join(" ")}`);

  const exitCode = await core.group("Executing aibomgen-cli scan...", async () =>
    execute(cmd, args, {
      listeners: {
        stdout(buffer) {
          core.info(buffer.toString());
        },
        stderr(buffer) {
          core.info(buffer.toString());
        },
        debug(message) {
          core.debug(message);
        },
      },
    }),
  );

  if (exitCode > 0) {
    throw new Error("aibomgen-cli scan failed");
  }

  // Glob the output directory for all AIBOM files written by the CLI.
  // Files are named <modelid>_aibom.json (or .xml) — one per discovered model.
  const aibomSuffix = opts.format === "xml" ? "aibom.xml" : "aibom.json";
  if (!fs.existsSync(outputDir)) {
    return [];
  }
  return fs
    .readdirSync(outputDir)
    .filter((f) => f.endsWith(aibomSuffix))
    .map((f) => path.join(outputDir, f));
}

/**
 * Uploads all generated AIBOM files as a single workflow artifact.
 */
async function uploadAIBomArtifact(filePaths: string[]): Promise<void> {
  const { repo } = github.context;
  const client = getClient(repo, core.getInput("github-token"));

  // Use a shared artifact name; individual file names are preserved inside.
  const artifactName =
    core.getInput("artifact-name") || path.basename(path.dirname(filePaths[0])) + "-aibom";
  const retentionDays = parseInt(core.getInput("upload-artifact-retention") || "0");

  core.info(dashWrap("Uploading workflow artifact"));
  for (const f of filePaths) core.info(f);

  await client.uploadWorkflowArtifact({
    files: filePaths,
    rootDir: path.dirname(filePaths[0]),
    name: artifactName,
    retention: retentionDays,
  });
}

/**
 * Attaches AIBOM artifacts to a GitHub release when the workflow runs in a
 * release or tag-push context.
 */
export async function attachReleaseAssets(): Promise<void> {
  const doRelease = (core.getInput("upload-release-assets") || "true").toLowerCase() === "true";

  if (!doRelease) {
    return;
  }

  const { eventName, ref, payload, repo } = github.context;
  const client = getClient(repo, core.getInput("github-token"));

  let release: Release | undefined = undefined;

  if (eventName === "release") {
    release = (payload as ReleaseEvent).release;
    debugLog("Got releaseEvent:", release);
  } else {
    const releaseRefPrefix = core.getInput("release-ref-prefix") || "refs/tags/";
    if (eventName === "push" && ref.startsWith(releaseRefPrefix)) {
      const tag = ref.substring(releaseRefPrefix.length);
      release = await client.findRelease({ tag });
      debugLog("Found release for ref push:", release);
    }
  }

  if (!release) {
    return;
  }

  const aibomArtifactInput = core.getInput("aibom-artifact-match");
  const artifactPattern = aibomArtifactInput || `^${getArtifactName()}$`;
  const matcher = new RegExp(artifactPattern);

  const artifacts = await client.listCurrentWorkflowArtifacts();
  const matched = artifacts.filter((a) => matcher.test(a.name));

  if (!matched.length && aibomArtifactInput) {
    core.warning(`WARNING: no AIBOMs found matching ${aibomArtifactInput}`);
    return;
  }

  core.info(dashWrap(`Attaching AIBOMs to release: '${release.tag_name}'`));
  for (const artifact of matched) {
    const dir = await client.downloadWorkflowArtifact(artifact);
    const files = fs.readdirSync(dir);
    for (const fileName of files) {
      const filePath = path.join(dir, fileName);
      core.info(filePath);
      const contents = fs.readFileSync(filePath);

      const assets = await client.listReleaseAssets({ release });
      const existing = assets.find((a) => a.name === fileName);
      if (existing) {
        await client.deleteReleaseAsset({ release, asset: existing });
      }

      await client.uploadReleaseAsset({
        release,
        assetName: fileName,
        contents: contents.toString(),
        contentType: fileName.endsWith(".xml") ? "application/xml" : "application/json",
      });
    }
  }
}

/**
 * Main action entry point: runs aibomgen-cli scan and uploads the output file
 * as a workflow artifact.
 */
export async function runAIBoMGenAction(): Promise<void> {
  core.info(dashWrap("Running aibomgen-cli Action"));
  debugLog("GitHub context:", github.context);

  const start = Date.now();
  const doUpload = (core.getInput("upload-artifact") || "true").toLowerCase() === "true";

  const hfTimeout = parseInt(core.getInput("hf-timeout") || "0");

  const writtenFiles = await executeAIBoMGenScan({
    input: { path: core.getInput("path") || "." },
    format: getAIBomFormat(),
    specVersion: core.getInput("spec-version"),
    outputFile: core.getInput("output-file"),
    hfToken: core.getInput("hf-token"),
    hfMode: (core.getInput("hf-mode") as AIBoMGenOptions["hfMode"]) || "online",
    hfTimeout,
    logLevel: (core.getInput("log-level") as AIBoMGenOptions["logLevel"]) || "standard",
    configFile: core.getInput("config"),
  });

  core.info(`AIBOM scan completed in: ${(Date.now() - start) / 1000}s`);

  if (writtenFiles.length === 0) {
    core.warning(
      `No AIBOM output files found in output directory — no models may have been discovered.`,
    );
    return;
  }

  core.info(`Found ${writtenFiles.length} AIBOM file(s).`);

  if (doUpload) {
    await uploadAIBomArtifact(writtenFiles);
  }
}

/**
 * Wraps the callback and marks the build as failed on any unhandled error.
 */
export async function runAndFailBuildOnException<T>(fn: () => Promise<T>): Promise<T | void> {
  try {
    return await fn();
  } catch (e) {
    if (e instanceof Error) {
      core.setFailed(e.message);
    } else if (e instanceof Object) {
      core.setFailed(`Action failed: ${stringify(e)}`);
    } else {
      core.setFailed(`An unknown error occurred: ${stringify(e)}`);
    }
  }
}
