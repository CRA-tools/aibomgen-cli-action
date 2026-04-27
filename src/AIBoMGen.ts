export type AIBoMGenCommand =
  | "download"
  | "scan"
  | "generate"
  | "validate"
  | "completeness"
  | "vuln-scan"
  | "merge";

export type AIBoMGenFormat = "json" | "xml" | "auto";
export type AIBoMGenLogLevel = "quiet" | "standard" | "debug";
export type AIBoMGenHFMode = "online" | "dummy";

export interface AIBoMGenCommonCommandOptions {
  configFile: string;
  format: AIBoMGenFormat;
  hfMode: AIBoMGenHFMode;
  hfTimeout: number;
  hfToken: string;
  logLevel: AIBoMGenLogLevel;
  noSecurityScan: boolean;
  outputFile: string;
  specVersion: string;
}

export interface AIBoMGenScanCommandOptions extends AIBoMGenCommonCommandOptions {
  inputPath: string;
}

export interface AIBoMGenGenerateCommandOptions extends AIBoMGenCommonCommandOptions {
  modelIds: string[];
}

export interface AIBoMGenValidateCommandOptions {
  format: AIBoMGenFormat;
  inputFile: string;
  logLevel: AIBoMGenLogLevel;
  minScore?: number;
  strict: boolean;
  checkModelCard: boolean;
}

export interface AIBoMGenCompletenessCommandOptions {
  format: AIBoMGenFormat;
  inputFile: string;
  logLevel: AIBoMGenLogLevel;
  plainSummary: boolean;
}

export interface AIBoMGenVulnScanCommandOptions {
  enrich: boolean;
  format: AIBoMGenFormat;
  hfTimeout: number;
  hfToken: string;
  inputFile: string;
  logLevel: AIBoMGenLogLevel;
  noPreview: boolean;
  outputFile: string;
  outputFormat: AIBoMGenFormat;
  specVersion: string;
}

export interface AIBoMGenMergeCommandOptions {
  aibomFiles: string[];
  deduplicate: boolean;
  format: AIBoMGenFormat;
  logLevel: AIBoMGenLogLevel;
  outputFile: string;
  sbomFile: string;
}

export interface AIBoMGenActionArtifactOptions {
  artifactMatch: string;
  artifactMatchMode: "exact" | "glob";
  artifactName: string;
  releaseRefPrefix: string;
  uploadArtifact: boolean;
  uploadArtifactRetention: number;
  uploadReleaseAssets: boolean;
}
