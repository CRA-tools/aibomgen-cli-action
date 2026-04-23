/**
 * Used for filesystem directory input to the `scan` command.
 * aibomgen-cli scans the directory for Hugging Face model imports in source files.
 */
export interface AIBoMGenDirectoryInput {
  path: string;
}

/**
 * Options for the aibomgen-cli `scan` subcommand.
 *
 * The scan command scans a directory for AI-related imports (e.g. Hugging Face
 * model IDs referenced in Python files) and generates an AIBOM for each
 * discovered model by fetching metadata from the Hugging Face Hub.
 *
 * The generated AIBOM file(s) are written to disk (not stdout). The output
 * path is controlled by `outputFile`; the default when unset is `dist/aibom.json`.
 */
export interface AIBoMGenOptions {
  /** Directory to scan for AI imports. Defaults to "." */
  input: AIBoMGenDirectoryInput;

  /**
   * Output BOM format.
   *   json → CycloneDX JSON
   *   xml  → CycloneDX XML
   *   auto → inferred from the output file extension (default)
   */
  format: "json" | "xml" | "auto";

  /**
   * CycloneDX spec version for the output (e.g. "1.4", "1.5", "1.6").
   * Omit to use the tool's built-in default.
   */
  specVersion: string;

  /**
   * Full output file path on the runner (directory is derived from it).
   * When empty the tool writes to `dist/aibom.json` (or `dist/aibom.xml`).
   */
  outputFile: string;

  /**
   * Hugging Face Hub access token. Required for private models.
   * Set via the `hf-token` action input.
   */
  hfToken: string;

  /**
   * Hugging Face metadata mode.
   *   online → fetch live data from the HF Hub (default)
   *   dummy  → use built-in fixture data (useful for offline testing)
   */
  hfMode: "online" | "dummy";

  /**
   * Timeout in seconds for each Hugging Face API request.
   * 0 means use the CLI default (10 s).
   */
  hfTimeout: number;

  /**
   * Log verbosity passed as --log-level.
   *   quiet    → suppress all non-error output
   *   standard → normal progress output (default)
   *   debug    → verbose debug output
   */
  logLevel: "quiet" | "standard" | "debug";

  /** Path to an aibomgen-cli config file (--config persistent flag). */
  configFile: string;
}
