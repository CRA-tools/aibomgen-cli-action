import * as core from "@actions/core";
import * as exec from "@actions/exec";
import * as github from "@actions/github";
import * as cache from "@actions/tool-cache";
import { Release, ReleaseEvent } from "@octokit/webhooks-types";
import { createHash } from "crypto";
import * as fs from "fs";
import os from "os";
import path from "path";
import {
  AIBoMGenCommand,
  AIBoMGenFormat,
  AIBoMGenHFMode,
  AIBoMGenLogLevel,
  AIBoMGenSeverity,
} from "../AIBoMGen";
import { dashWrap, debugLog, getClient } from "./GithubClient";
import { stringify } from "./Util";

const BINARY_NAME = "aibomgen-cli";
const exeSuffix = process.platform === "win32" ? ".exe" : "";
// aibomgen-cli's default output directory for scan and generate.
const OUTPUT_DIR = "dist";

const COMMANDS: readonly AIBoMGenCommand[] = [
  "download",
  "scan",
  "generate",
  "validate",
  "completeness",
  "vuln-scan",
  "merge",
];
const FORMATS: readonly AIBoMGenFormat[] = ["json", "xml"];
const HF_MODES: readonly AIBoMGenHFMode[] = ["online", "dummy"];
const LOG_LEVELS: readonly AIBoMGenLogLevel[] = ["quiet", "standard", "debug"];
const SEVERITIES: readonly AIBoMGenSeverity[] = ["critical", "high", "medium", "low", "info"];

const LOG_LEVEL_ARGS: Record<AIBoMGenLogLevel, string[]> = {
  quiet: ["--quiet"],
  standard: [],
  debug: ["-vv"],
};

const DEFAULT_ARTIFACT_NAMES: Partial<Record<AIBoMGenCommand, string>> = {
  scan: "output-aiboms",
  generate: "output-aiboms",
  "vuln-scan": "output-aiboms-vuln",
  merge: "merged",
};

type InputGetter = (name: string) => string;
type SecretSetter = (value: string) => void;

const actionInput: InputGetter = (name) => core.getInput(name);
const actionSecret: SecretSetter = (value) => core.setSecret(value);

type BuildCommandResult = {
  /** One aibomgen-cli invocation per entry. */
  argsList: string[][];
  env: Record<string, string>;
  /** Files the invocations write, when known up front. */
  outputFiles: string[];
  /** When set, outputs are discovered in OUTPUT_DIR by this suffix instead. */
  outputSuffix?: string;
};

function parseBooleanInput(name: string, defaultValue: boolean, getInput: InputGetter): boolean {
  const raw = getInput(name).trim().toLowerCase();
  if (!raw) {
    return defaultValue;
  }
  if (raw !== "true" && raw !== "false") {
    throw new Error(`Input '${name}' must be 'true' or 'false', got '${raw}'.`);
  }
  return raw === "true";
}

function parseNumberInput(
  name: string,
  getInput: InputGetter,
  { min, max, integer = false }: { min?: number; max?: number; integer?: boolean } = {},
): number | undefined {
  const raw = getInput(name).trim();
  if (!raw) {
    return undefined;
  }
  const value = Number(raw);
  if (Number.isNaN(value) || (integer && !Number.isInteger(value))) {
    throw new Error(`Input '${name}' must be ${integer ? "an integer" : "a number"}, got '${raw}'.`);
  }
  if ((min !== undefined && value < min) || (max !== undefined && value > max)) {
    throw new Error(`Input '${name}' must be between ${min ?? "-∞"} and ${max ?? "∞"}, got '${raw}'.`);
  }
  return value;
}

function parseListInput(name: string, getInput: InputGetter): string[] {
  const values = getInput(name)
    .split(/[\n,]/)
    .map((v) => v.trim())
    .filter((v) => v.length > 0);
  return [...new Set(values)];
}

function parseEnumInput<T extends string>(
  name: string,
  values: readonly T[],
  defaultValue: T,
  getInput: InputGetter,
): T {
  const raw = getInput(name).trim();
  if (!raw) {
    return defaultValue;
  }
  if (!values.includes(raw as T)) {
    throw new Error(`Input '${name}' must be one of: ${values.join(", ")}. Got '${raw}'.`);
  }
  return raw as T;
}

function requireListInput(name: string, command: AIBoMGenCommand, getInput: InputGetter): string[] {
  const values = parseListInput(name, getInput);
  if (values.length === 0) {
    throw new Error(`Input '${name}' is required when command=${command}.`);
  }
  return values;
}

function requireInput(name: string, command: AIBoMGenCommand, getInput: InputGetter): string {
  return requireListInput(name, command, getInput)[0];
}

function getReleaseAssetName(version: string): string {
  const platform = { win32: "windows" }[process.platform as string] ?? process.platform;
  const arch = { x64: "amd64" }[os.arch() as string] ?? os.arch();
  const ext = process.platform === "win32" ? "zip" : "tar.gz";
  return `${BINARY_NAME}_${version.replace(/^v/, "")}_${platform}_${arch}.${ext}`;
}

async function downloadAIBoMGen(version: string): Promise<string> {
  const url = `https://github.com/idlab-discover/aibomgen-cli/releases/download/${version}/${getReleaseAssetName(version)}`;
  core.info(`Downloading aibomgen-cli from ${url}`);
  const downloadPath = await cache.downloadTool(url);

  const expectedSha256 = core.getInput("aibomgen-sha256").trim().toLowerCase();
  if (expectedSha256) {
    const hash = createHash("sha256").update(fs.readFileSync(downloadPath)).digest("hex");
    if (hash !== expectedSha256) {
      throw new Error(`SHA256 mismatch for downloaded aibomgen-cli archive. Expected ${expectedSha256}, got ${hash}.`);
    }
  }

  const extractedDir =
    process.platform === "win32" ? await cache.extractZip(downloadPath) : await cache.extractTar(downloadPath);
  return path.join(extractedDir, BINARY_NAME + exeSuffix);
}

export async function getAIBoMGenCommand(): Promise<string> {
  const name = BINARY_NAME + exeSuffix;
  const version = core.getInput("aibomgen-version", { required: true });

  let binaryDir = cache.find(name, version);
  if (!binaryDir) {
    binaryDir = await cache.cacheFile(await downloadAIBoMGen(version), name, name, version);
  }

  core.addPath(binaryDir);
  return path.join(binaryDir, name);
}

function getArtifactName(command: AIBoMGenCommand, getInput: InputGetter = actionInput): string {
  return getInput("artifact-name") || DEFAULT_ARTIFACT_NAMES[command] || `${command}-aibom`;
}

/** The deepest directory that contains every file, so the artifact keeps relative paths. */
function getArtifactRootDir(filePaths: string[]): string {
  const files = filePaths.map((f) => path.resolve(f));
  let root = path.dirname(files[0]);
  while (files.some((f) => path.relative(root, f).split(path.sep).includes(".."))) {
    root = path.dirname(root);
  }
  return root;
}

function buildCommandArgs(
  command: AIBoMGenCommand,
  getInput: InputGetter = actionInput,
  setSecret: SecretSetter = actionSecret,
): BuildCommandResult {
  const logLevel = parseEnumInput("log-level", LOG_LEVELS, "standard", getInput);
  const configFile = getInput("config").trim();
  const specVersion = getInput("spec-version").trim();
  const hfTimeout = parseNumberInput("hf-timeout", getInput, { min: 0, integer: true }) ?? 0;
  // Passed as env instead of a flag, so the token never appears in the logged command line.
  const hfToken = getInput("hf-token").trim();
  if (hfToken) {
    setSecret(hfToken);
  }

  const env: Record<string, string> = hfToken ? { HF_TOKEN: hfToken } : {};
  const globalArgs = ["--no-input", ...LOG_LEVEL_ARGS[logLevel], ...(configFile ? ["--config", configFile] : [])];
  const specArgs = specVersion ? ["--spec", specVersion] : [];
  const timeoutArgs = hfTimeout > 0 ? ["--hf-timeout", String(hfTimeout)] : [];
  const run = (...argsList: string[][]) => argsList.map((args) => [...globalArgs, ...args]);

  switch (command) {
    case "scan":
    case "generate": {
      const target =
        command === "scan"
          ? ["scan", "--input", getInput("scan-input").trim() || "."]
          : [
              "generate",
              ...requireListInput("generate-model-ids", command, getInput).flatMap((id) => ["--model-id", id]),
            ];
      const format = parseEnumInput("format", FORMATS, "json", getInput);
      const hfMode = parseEnumInput("hf-mode", HF_MODES, "online", getInput);
      const noSecurityScan = parseBooleanInput("no-security-scan", false, getInput);

      return {
        argsList: run([
          ...target,
          "--format",
          format,
          ...specArgs,
          "--hf-mode",
          hfMode,
          ...timeoutArgs,
          ...(noSecurityScan ? ["--no-security-scan"] : []),
        ]),
        env,
        outputFiles: [],
        outputSuffix: `.aibom.cdx.${format}`,
      };
    }

    case "validate": {
      const inputFiles = requireListInput("validate-input", command, getInput);
      const strict = parseBooleanInput("validate-strict", false, getInput);
      const failSeverity = parseEnumInput("validate-fail-severity", SEVERITIES, "medium", getInput);
      const minScore = parseNumberInput("validate-min-score", getInput, { min: 0, max: 1 });
      const flags = [
        ...(strict ? ["--strict", "--fail-severity", failSeverity] : []),
        ...(minScore !== undefined ? ["--min-score", String(minScore)] : []),
      ];

      return {
        argsList: run(...inputFiles.map((f) => ["validate", "--input", f, ...flags])),
        env,
        outputFiles: [],
      };
    }

    case "completeness":
      return {
        argsList: run(["completeness", "--input", requireInput("completeness-input", command, getInput)]),
        env,
        outputFiles: [],
      };

    case "vuln-scan": {
      const inputFiles = requireListInput("vuln-scan-input", command, getInput);
      const enrich = parseBooleanInput("vuln-scan-enrich", false, getInput);
      // --yes: the action never has a terminal to confirm the in-place write.
      const flags = enrich ? ["--enrich", "--yes", ...specArgs] : [];

      return {
        argsList: run(...inputFiles.map((f) => ["vuln-scan", "--input", f, ...flags, ...timeoutArgs])),
        env,
        outputFiles: enrich ? inputFiles : [],
      };
    }

    case "merge": {
      const aibomFiles = requireListInput("merge-aibom-files", command, getInput);
      const sbomFile = requireInput("merge-sbom-file", command, getInput);
      const outputFile = requireInput("merge-output-file", command, getInput);
      const deduplicate = parseBooleanInput("merge-deduplicate", true, getInput);

      return {
        argsList: run([
          "merge",
          ...aibomFiles.flatMap((f) => ["--aibom", f]),
          "--sbom",
          sbomFile,
          "--output",
          outputFile,
          ...(deduplicate ? [] : ["--no-deduplicate"]),
        ]),
        env,
        outputFiles: [outputFile],
      };
    }

    default:
      throw new Error(`Command '${command}' does not run aibomgen-cli.`);
  }
}

export const __test = {
  buildCommandArgs,
  getArtifactName,
  getArtifactRootDir,
  getReleaseAssetName,
};

async function runCliCommand(command: AIBoMGenCommand): Promise<string[]> {
  const cmd = await getAIBoMGenCommand();
  const build = buildCommandArgs(command);

  for (const args of build.argsList) {
    const stderr: string[] = [];
    const exitCode = await core.group(`Executing aibomgen-cli ${command}...`, () =>
      exec.exec(cmd, args, {
        env: { ...process.env, ...build.env } as Record<string, string>,
        ignoreReturnCode: true,
        listeners: { stderr: (buffer) => stderr.push(buffer.toString()) },
      }),
    );

    if (exitCode !== 0) {
      throw new Error(`aibomgen-cli ${command} failed with exit code ${exitCode}.\n${stderr.join("").slice(-4000)}`);
    }
  }

  if (!build.outputSuffix) {
    return build.outputFiles.filter((f) => fs.existsSync(f));
  }
  if (!fs.existsSync(OUTPUT_DIR)) {
    return [];
  }
  // ponytail: also picks up matching files an earlier step left in dist/; diff the directory if that bites.
  return fs
    .readdirSync(OUTPUT_DIR)
    .filter((f) => f.endsWith(build.outputSuffix!))
    .map((f) => path.join(OUTPUT_DIR, f));
}

async function uploadAIBomArtifact(command: AIBoMGenCommand, filePaths: string[]): Promise<void> {
  if (!parseBooleanInput("upload-artifact", true, actionInput)) {
    return;
  }

  const retention = parseNumberInput("upload-artifact-retention", actionInput, { min: 0, max: 90, integer: true });
  const client = getClient(github.context.repo, core.getInput("github-token"));

  core.info(dashWrap("Uploading workflow artifact"));
  filePaths.forEach((f) => core.info(f));

  await client.uploadWorkflowArtifact({
    files: filePaths,
    rootDir: getArtifactRootDir(filePaths),
    name: getArtifactName(command),
    retention: retention ?? 0,
  });
}

export async function attachReleaseAssets(filePaths: string[]): Promise<void> {
  if (filePaths.length === 0 || !parseBooleanInput("upload-release-assets", true, actionInput)) {
    return;
  }

  const { eventName, ref, payload, repo } = github.context;
  const client = getClient(repo, core.getInput("github-token"));

  let release: Release | undefined;
  if (eventName === "release") {
    release = (payload as ReleaseEvent).release;
  } else if (eventName === "push" && ref.startsWith("refs/tags/")) {
    release = await client.findRelease({ tag: ref.slice("refs/tags/".length) });
  }
  debugLog("Release", release);
  if (!release) {
    return;
  }

  core.info(dashWrap(`Attaching AIBOMs to release '${release.tag_name}'`));
  const assets = await client.listReleaseAssets({ release });

  for (const filePath of filePaths) {
    const assetName = path.basename(filePath);
    const existing = assets.find((asset) => asset.name === assetName);
    if (existing) {
      await client.deleteReleaseAsset({ asset: existing });
    }

    await client.uploadReleaseAsset({
      release,
      assetName,
      contents: fs.readFileSync(filePath).toString(),
      contentType: assetName.endsWith(".xml") ? "application/xml" : "application/json",
    });
  }
}

/** Runs the selected command and returns the files it wrote. */
export async function runAIBoMGenAction(): Promise<string[]> {
  core.info(dashWrap("Running aibomgen-cli Action"));
  debugLog("GitHub context", github.context);

  const githubToken = core.getInput("github-token");
  if (githubToken) {
    core.setSecret(githubToken);
  }

  const command = parseEnumInput("command", COMMANDS, "scan", actionInput);
  core.setOutput("executed-command", command);

  if (command === "download") {
    core.setOutput("cmd", await getAIBoMGenCommand());
    return [];
  }

  const start = Date.now();
  const writtenFiles = await runCliCommand(command);
  core.info(`aibomgen-cli ${command} completed in ${(Date.now() - start) / 1000}s`);
  core.info(`Found ${writtenFiles.length} output file(s).`);
  core.setOutput("written-files", writtenFiles.join("\n"));

  if (writtenFiles.length > 0) {
    await uploadAIBomArtifact(command, writtenFiles);
  }
  return writtenFiles;
}

export async function runAndFailBuildOnException<T>(fn: () => Promise<T>): Promise<T | void> {
  try {
    return await fn();
  } catch (e) {
    core.setFailed(e instanceof Error ? e.message : `Action failed: ${stringify(e)}`);
  }
}
