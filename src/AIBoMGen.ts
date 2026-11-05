export type AIBoMGenCommand =
  | "download"
  | "scan"
  | "generate"
  | "validate"
  | "completeness"
  | "vuln-scan"
  | "merge";

export type AIBoMGenFormat = "json" | "xml";
export type AIBoMGenLogLevel = "quiet" | "standard" | "debug";
export type AIBoMGenHFMode = "online" | "dummy";
export type AIBoMGenSeverity = "critical" | "high" | "medium" | "low" | "info";
