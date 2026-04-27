import * as core from "@actions/core";
import * as github from "@actions/github";
import * as cache from "@actions/tool-cache";
import { createHash } from "crypto";
import * as fs from "fs";
import os from "os";
import path from "path";
import { Release, ReleaseEvent } from "@octokit/webhooks-types";
import {
  AIBoMGenActionArtifactOptions,
  AIBoMGenCommand,
  AIBoMGenFormat,
  AIBoMGenHFMode,
  AIBoMGenLogLevel,
} from "../AIBoMGen";
import { VERSION } from "../AIBoMGenVersion";
import { downloadAIBoMGenFromZip } from "./AIBoMGenDownloader";
import { execute } from "./Executor";
import { dashWrap, debugLog, getClient } from "./GithubClient";
import { stringify } from "./Util";

export const AIBOMGEN_BINARY_NAME = "aibomgen-cli";
export const AIBOMGEN_VERSION = core.getInput("aibomgen-version") || VERSION;

const exeSuffix = process.platform === "win32" ? ".exe" : "";
const DEFAULT_OUTPUT_DIR = "dist";

const COMMANDS: readonly AIBoMGenCommand[] = [
  "download",
  "scan",
  "generate",
  "validate",
  "completeness",
  "vuln-scan",
  "merge",
];

const FORMATS: readonly AIBoMGenFormat[] = ["json", "xml", "auto"];
const HF_MODES: readonly AIBoMGenHFMode[] = ["online", "dummy"];
const LOG_LEVELS: readonly AIBoMGenLogLevel[] = ["quiet", "standard", "debug"];

type InputGetter = (name: string) => string;
type SecretSetter = (value: string) => void;

type BuildCommandResult = {
  args: string[];
  sensitiveValues: string[];
  expectedOutputFiles: string[];
  outputDirectory: string;
  outputSuffix: string;
};

function parseBooleanInput(name: string, defaultValue: boolean, getInput: InputGetter): boolean {
  const raw = getInput(name);
  if (!raw) {
    return defaultValue;
  }

  const value = raw.trim().toLowerCase();
  if (value === "true") {
    return true;
  }
  if (value === "false") {
    return false;
  }

  throw new Error(`Input '${name}' must be 'true' or 'false', got '${raw}'.`);
}

function parseIntegerInput(
  name: string,
  defaultValue: number,
  options?: { min?: number; max?: number },
  getInput?: InputGetter,
): number {
  const safeGetInput = getInput ?? ((inputName: string) => core.getInput(inputName));
  const raw = safeGetInput(name);
  if (!raw) {
    return defaultValue;
  }

  const value = Number(raw);
  if (!Number.isInteger(value)) {
    throw new Error(`Input '${name}' must be an integer, got '${raw}'.`);
  }

  if (options?.min !== undefined && value < options.min) {
    throw new Error(`Input '${name}' must be >= ${options.min}, got '${value}'.`);
  }

  if (options?.max !== undefined && value > options.max) {
    throw new Error(`Input '${name}' must be <= ${options.max}, got '${value}'.`);
  }

  return value;
}

function parseNumberInput(name: string, getInput: InputGetter): number | undefined {
  const raw = getInput(name);
  if (!raw) {
    return undefined;
  }
  const value = Number(raw);
  if (Number.isNaN(value)) {
    throw new Error(`Input '${name}' must be a number, got '${raw}'.`);
  }
  return value;
}

function parseListInput(name: string, getInput: InputGetter): string[] {
  const raw = getInput(name);
  if (!raw) {
    return [];
  }

  const out = raw
    .split(/[\n,]/)
    .map((v) => v.trim())
    .filter((v) => v.length > 0);

  return [...new Set(out)];
}

function parseEnumInput<T extends string>(
  name: string,
  values: readonly T[],
  defaultValue: T,
  getInput: InputGetter,
): T {
  const raw = getInput(name);
  if (!raw) {
    return defaultValue;
  }

  const value = raw.trim() as T;
  if (!values.includes(value)) {
    throw new Error(`Input '${name}' must be one of: ${values.join(", ")}. Got '${raw}'.`);
  }

  return value;
}

function getActionCommand(
  getInput: InputGetter = (name: string) => core.getInput(name),
  setSecret: SecretSetter = (value: string) => core.setSecret(value),
): AIBoMGenCommand {
  const githubToken = getInput("github-token");
  if (githubToken) {
    setSecret(githubToken);
  }

  return parseEnumInput("command", COMMANDS, "scan", getInput);
}

function getArtifactOptions(
  getInput: InputGetter = (name: string) => core.getInput(name),
): AIBoMGenActionArtifactOptions {
  return {
    artifactMatch: getInput("aibom-artifact-match"),
    artifactMatchMode: parseEnumInput(
      "aibom-artifact-match-mode",
      ["exact", "glob"],
      "exact",
      getInput,
    ),
    artifactName: getInput("artifact-name"),
    releaseRefPrefix: getInput("release-ref-prefix") || "refs/tags/",
    uploadArtifact: parseBooleanInput("upload-artifact", true, getInput),
    uploadArtifactRetention: parseIntegerInput(
      "upload-artifact-retention",
      0,
      { min: 0, max: 90 },
      getInput,
    ),
    uploadReleaseAssets: parseBooleanInput("upload-release-assets", true, getInput),
  };
}

function getReleaseAssetName(version: string): string {
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

function verifySha256(filePath: string, expectedSha256: string): void {
  const hash = createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
  if (hash.toLowerCase() !== expectedSha256.toLowerCase()) {
    throw new Error(`SHA256 mismatch for downloaded aibomgen-cli archive. Expected ${expectedSha256}, got ${hash}.`);
  }
}

function globToRegExp(pattern: string): RegExp {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  const regex = `^${escaped.replace(/\*/g, ".*").replace(/\?/g, ".")}$`;
  return new RegExp(regex);
}

function artifactMatches(name: string, pattern: string, mode: "exact" | "glob"): boolean {
  if (!pattern) {
    return true;
  }

  if (mode === "exact") {
    return name === pattern;
  }

  return globToRegExp(pattern).test(name);
}

function redactText(text: string, secrets: string[]): string {
  let out = text;
  for (const secret of secrets) {
    if (!secret) {
      continue;
    }
    out = out.split(secret).join("***");
  }
  return out;
}

export async function downloadAIBoMGen(): Promise<string> {
  const version = AIBOMGEN_VERSION;
  const assetName = getReleaseAssetName(version);
  const url = `https://github.com/idlab-discover/aibomgen-cli/releases/download/${version}/${assetName}`;

  core.info(`Downloading aibomgen-cli from ${url}`);

  const downloadPath = await cache.downloadTool(url);

  const expectedSha256 = core.getInput("aibomgen-sha256").trim().toLowerCase();
  if (expectedSha256) {
    verifySha256(downloadPath, expectedSha256);
  }

  let extractedDir: string;
  if (process.platform === "win32") {
    extractedDir = await cache.extractZip(downloadPath);
  } else {
    extractedDir = await cache.extractTar(downloadPath);
  }

  return path.join(extractedDir, `${AIBOMGEN_BINARY_NAME}${exeSuffix}`);
}

export async function getAIBoMGenCommand(): Promise<string> {
  const name = AIBOMGEN_BINARY_NAME + exeSuffix;
  const version = AIBOMGEN_VERSION;

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

function getArtifactName(command: AIBoMGenCommand): string {
  const fileName = core.getInput("artifact-name");
  if (fileName) {
    return fileName;
  }

  const {
    repo: { repo },
    job,
  } = github.context;

  return `${repo}-${job}-${command}-aibom`;
}

function buildCommonCommandArgs(
  getInput: InputGetter,
  setSecret: SecretSetter,
): {
  args: string[];
  format: AIBoMGenFormat;
  hfMode: AIBoMGenHFMode;
  hfTimeout: number;
  hfToken: string;
  logLevel: AIBoMGenLogLevel;
  noSecurityScan: boolean;
  outputFile: string;
  specVersion: string;
  configFile: string;
} {
  const format = parseEnumInput("format", FORMATS, "auto", getInput);
  const hfMode = parseEnumInput("hf-mode", HF_MODES, "online", getInput);
  const logLevel = parseEnumInput("log-level", LOG_LEVELS, "standard", getInput);
  const hfTimeout = parseIntegerInput("hf-timeout", 0, { min: 0 }, getInput);
  const specVersion = getInput("spec-version").trim();
  const outputFile = getInput("output-file").trim();
  const hfToken = getInput("hf-token").trim();
  const configFile = getInput("config").trim();
  const noSecurityScan = parseBooleanInput("no-security-scan", false, getInput);

  if (hfToken) {
    setSecret(hfToken);
  }

  const args: string[] = [];
  if (configFile) {
    args.push("--config", configFile);
  }

  return {
    args,
    configFile,
    format,
    hfMode,
    hfTimeout,
    hfToken,
    logLevel,
    noSecurityScan,
    outputFile,
    specVersion,
  };
}

function applyScanLikeFlags(
  args: string[],
  common: ReturnType<typeof buildCommonCommandArgs>,
  getInput: InputGetter,
  options?: { outputFormatInputName?: string },
): string[] {
  const formatInputName = options?.outputFormatInputName;

  if (common.outputFile) {
    args.push("--output", common.outputFile);
  }

  if (formatInputName) {
    const outputFormat = parseEnumInput(formatInputName, FORMATS, "auto", getInput);
    args.push("--output-format", outputFormat);
  } else {
    args.push("--format", common.format);
  }

  if (common.specVersion) {
    args.push("--spec", common.specVersion);
  }

  if (common.hfToken) {
    args.push("--hf-token", common.hfToken);
  }

  if (common.hfMode) {
    args.push("--hf-mode", common.hfMode);
  }

  if (common.hfTimeout > 0) {
    args.push("--hf-timeout", String(common.hfTimeout));
  }

  if (common.noSecurityScan) {
    args.push("--no-security-scan");
  }

  args.push("--log-level", common.logLevel);

  return args;
}

function buildCommandArgs(
  command: AIBoMGenCommand,
  getInput: InputGetter = (name: string) => core.getInput(name),
  setSecret: SecretSetter = (value: string) => core.setSecret(value),
): BuildCommandResult {
  const common = buildCommonCommandArgs(getInput, setSecret);
  const args = [...common.args];
  const sensitiveValues: string[] = [common.hfToken, common.configFile].filter((v) => Boolean(v));

  switch (command) {
    case "scan": {
      const inputPath = getInput("scan-input") || ".";
      const scanArgs = ["scan", "--input", inputPath.trim()];
      applyScanLikeFlags(scanArgs, common, getInput);
      args.push(...scanArgs);

      return {
        args,
        sensitiveValues,
        expectedOutputFiles: common.outputFile ? [common.outputFile] : [],
        outputDirectory: common.outputFile ? path.dirname(common.outputFile) : DEFAULT_OUTPUT_DIR,
        outputSuffix: common.format === "xml" ? "aibom.xml" : "aibom.json",
      };
    }

    case "generate": {
      const modelIds = parseListInput("generate-model-ids", getInput);
      if (modelIds.length === 0) {
        throw new Error("Input 'generate-model-ids' is required when command=generate.");
      }

      const generateArgs = ["generate"];
      for (const modelId of modelIds) {
        generateArgs.push("--model-id", modelId);
      }
      applyScanLikeFlags(generateArgs, common, getInput);
      args.push(...generateArgs);

      return {
        args,
        sensitiveValues,
        expectedOutputFiles: common.outputFile ? [common.outputFile] : [],
        outputDirectory: common.outputFile ? path.dirname(common.outputFile) : DEFAULT_OUTPUT_DIR,
        outputSuffix: common.format === "xml" ? "aibom.xml" : "aibom.json",
      };
    }

    case "validate": {
      const inputFile = getInput("validate-input").trim();
      if (!inputFile) {
        throw new Error("Input 'validate-input' is required when command=validate.");
      }

      const strict = parseBooleanInput("validate-strict", false, getInput);
      const checkModelCard = parseBooleanInput("validate-check-model-card", false, getInput);
      const minScore = parseNumberInput("validate-min-score", getInput);
      if (minScore !== undefined && (minScore < 0 || minScore > 1)) {
        throw new Error("Input 'validate-min-score' must be between 0 and 1.");
      }

      const validateArgs = ["validate", "--input", inputFile, "--format", common.format];
      if (strict) {
        validateArgs.push("--strict");
      }
      if (checkModelCard) {
        validateArgs.push("--check-model-card");
      }
      if (minScore !== undefined) {
        validateArgs.push("--min-score", String(minScore));
      }
      validateArgs.push("--log-level", common.logLevel);
      args.push(...validateArgs);

      return {
        args,
        sensitiveValues,
        expectedOutputFiles: [],
        outputDirectory: DEFAULT_OUTPUT_DIR,
        outputSuffix: "",
      };
    }

    case "completeness": {
      const inputFile = getInput("completeness-input").trim();
      if (!inputFile) {
        throw new Error("Input 'completeness-input' is required when command=completeness.");
      }

      const plainSummary = parseBooleanInput("completeness-plain-summary", false, getInput);
      const completenessArgs = ["completeness", "--input", inputFile, "--format", common.format];
      if (plainSummary) {
        completenessArgs.push("--plain-summary");
      }
      completenessArgs.push("--log-level", common.logLevel);
      args.push(...completenessArgs);

      return {
        args,
        sensitiveValues,
        expectedOutputFiles: [],
        outputDirectory: DEFAULT_OUTPUT_DIR,
        outputSuffix: "",
      };
    }

    case "vuln-scan": {
      const inputFile = getInput("vuln-scan-input").trim();
      if (!inputFile) {
        throw new Error("Input 'vuln-scan-input' is required when command=vuln-scan.");
      }

      const enrich = parseBooleanInput("vuln-scan-enrich", false, getInput);
      const noPreview = parseBooleanInput("vuln-scan-no-preview", false, getInput);
      const outputFormat = parseEnumInput("vuln-scan-output-format", FORMATS, "auto", getInput);

      const vulnArgs = ["vuln-scan", "--input", inputFile, "--format", common.format];
      if (enrich) {
        vulnArgs.push("--enrich", "--output-format", outputFormat);
        if (common.outputFile) {
          vulnArgs.push("--output", common.outputFile);
        }
        if (noPreview) {
          vulnArgs.push("--no-preview");
        }
      }
      if (common.specVersion) {
        vulnArgs.push("--spec", common.specVersion);
      }
      if (common.hfToken) {
        vulnArgs.push("--hf-token", common.hfToken);
      }
      if (common.hfTimeout > 0) {
        vulnArgs.push("--hf-timeout", String(common.hfTimeout));
      }
      vulnArgs.push("--log-level", common.logLevel);
      args.push(...vulnArgs);

      return {
        args,
        sensitiveValues,
        expectedOutputFiles: enrich ? [common.outputFile || inputFile] : [],
        outputDirectory: enrich
          ? common.outputFile
            ? path.dirname(common.outputFile)
            : path.dirname(inputFile)
          : DEFAULT_OUTPUT_DIR,
        outputSuffix: enrich
          ? common.outputFile
            ? path.basename(common.outputFile)
            : path.basename(inputFile)
          : "",
      };
    }

    case "merge": {
      const aibomFiles = parseListInput("merge-aibom-files", getInput);
      const sbomFile = getInput("merge-sbom-file").trim();
      const mergeOutputFile = getInput("merge-output-file").trim();
      const deduplicate = parseBooleanInput("merge-deduplicate", true, getInput);

      if (aibomFiles.length === 0) {
        throw new Error("Input 'merge-aibom-files' is required when command=merge.");
      }
      if (!sbomFile) {
        throw new Error("Input 'merge-sbom-file' is required when command=merge.");
      }
      if (!mergeOutputFile) {
        throw new Error("Input 'merge-output-file' is required when command=merge.");
      }

      const mergeArgs = ["merge"];
      for (const aibomFile of aibomFiles) {
        mergeArgs.push("--aibom", aibomFile);
      }
      mergeArgs.push("--sbom", sbomFile, "--output", mergeOutputFile, "--format", common.format);
      if (!deduplicate) {
        mergeArgs.push("--deduplicate=false");
      }
      mergeArgs.push("--log-level", common.logLevel);
      args.push(...mergeArgs);

      return {
        args,
        sensitiveValues,
        expectedOutputFiles: [mergeOutputFile],
        outputDirectory: path.dirname(mergeOutputFile),
        outputSuffix: path.basename(mergeOutputFile),
      };
    }

    case "download":
      return {
        args,
        sensitiveValues,
        expectedOutputFiles: [],
        outputDirectory: DEFAULT_OUTPUT_DIR,
        outputSuffix: "",
      };

    default:
      throw new Error(`Unsupported command '${command}'.`);
  }
}

export const __test = {
  artifactMatches,
  buildCommandArgs,
  globToRegExp,
  redactText,
};

async function runCliCommand(command: AIBoMGenCommand): Promise<string[]> {
  const cmd = await getAIBoMGenCommand();
  const build = buildCommandArgs(command);

  const redactedCommand = redactText(`${cmd} ${build.args.join(" ")}`.trim(), build.sensitiveValues);
  core.info(`[command] ${redactedCommand}`);

  const stderrChunks: string[] = [];

  const exitCode = await core.group(`Executing aibomgen-cli ${command}...`, async () =>
    execute(cmd, build.args, {
      listeners: {
        stdout(buffer) {
          core.info(redactText(buffer.toString(), build.sensitiveValues));
        },
        stderr(buffer) {
          const text = redactText(buffer.toString(), build.sensitiveValues);
          stderrChunks.push(text);
          core.info(text);
        },
        debug(message) {
          core.debug(redactText(message, build.sensitiveValues));
        },
      },
    }),
  );

  if (exitCode > 0) {
    const stderrTail = stderrChunks.join("\n").slice(-4000);
    throw new Error(
      `aibomgen-cli ${command} failed with exit code ${exitCode}.${stderrTail ? `\n${stderrTail}` : ""}`,
    );
  }

  if (build.expectedOutputFiles.length > 0) {
    return build.expectedOutputFiles.filter((f) => fs.existsSync(f));
  }

  if (!build.outputSuffix || !fs.existsSync(build.outputDirectory)) {
    return [];
  }

  return fs
    .readdirSync(build.outputDirectory)
    .filter((f) => f.endsWith(build.outputSuffix))
    .map((f) => path.join(build.outputDirectory, f));
}

async function uploadAIBomArtifact(filePaths: string[], artifactOptions: AIBoMGenActionArtifactOptions): Promise<void> {
  const { repo } = github.context;
  const token = core.getInput("github-token");
  const client = getClient(repo, token);

  const artifactName = artifactOptions.artifactName || path.basename(path.dirname(filePaths[0])) + "-aibom";

  core.info(dashWrap("Uploading workflow artifact"));
  for (const f of filePaths) {
    core.info(f);
  }

  await client.uploadWorkflowArtifact({
    files: filePaths,
    rootDir: path.dirname(filePaths[0]),
    name: artifactName,
    retention: artifactOptions.uploadArtifactRetention,
  });
}

export async function attachReleaseAssets(): Promise<void> {
  const artifactOptions = getArtifactOptions();
  if (!artifactOptions.uploadReleaseAssets) {
    return;
  }

  const { eventName, ref, payload, repo } = github.context;
  const client = getClient(repo, core.getInput("github-token"));

  let release: Release | undefined;

  if (eventName === "release") {
    release = (payload as ReleaseEvent).release;
    debugLog("Got release event", release);
  } else if (eventName === "push" && ref.startsWith(artifactOptions.releaseRefPrefix)) {
    const tag = ref.substring(artifactOptions.releaseRefPrefix.length);
    release = await client.findRelease({ tag });
    debugLog("Found release for ref push", release);
  }

  if (!release) {
    return;
  }

  const command = parseEnumInput(
    "command",
    COMMANDS,
    "scan",
    (name: string) => core.getInput(name),
  );
  const matchPattern = artifactOptions.artifactMatch || getArtifactName(command);

  const artifacts = await client.listCurrentWorkflowArtifacts();
  const matched = artifacts.filter((a) =>
    artifactMatches(a.name, matchPattern, artifactOptions.artifactMatchMode),
  );

  if (matched.length === 0) {
    core.warning(`No artifacts found for release upload with pattern '${matchPattern}'.`);
    return;
  }

  core.info(dashWrap(`Attaching AIBOMs to release '${release.tag_name}'`));

  for (const artifact of matched) {
    const dir = await client.downloadWorkflowArtifact(artifact);
    try {
      const files = fs.readdirSync(dir);
      for (const fileName of files) {
        const filePath = path.join(dir, fileName);
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
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }
}

export async function runAIBoMGenAction(): Promise<void> {
  core.info(dashWrap("Running aibomgen-cli Action"));
  debugLog("GitHub context", github.context);

  const start = Date.now();
  const command = getActionCommand();
  const artifacts = getArtifactOptions();

  if (command === "download") {
    const cmd = await getAIBoMGenCommand();
    core.setOutput("cmd", cmd);
    return;
  }

  const writtenFiles = await runCliCommand(command);

  core.info(`aibomgen-cli ${command} completed in ${(Date.now() - start) / 1000}s`);

  core.setOutput("executed-command", command);
  core.setOutput("written-files", writtenFiles.join("\n"));

  if (writtenFiles.length === 0) {
    core.info("No output files discovered for this command.");
    return;
  }

  core.info(`Found ${writtenFiles.length} output file(s).`);

  if (artifacts.uploadArtifact) {
    await uploadAIBomArtifact(writtenFiles, artifacts);
  }
}

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
