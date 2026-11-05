import assert from "node:assert";
import path from "node:path";
import { beforeEach, describe, it } from "node:test";
import { __test } from "../src/github/AIBoMGenGithubAction";

let inputMap: Record<string, string>;
const getInput = (name: string) => inputMap[name] ?? "";
const build = (command: Parameters<typeof __test.buildCommandArgs>[0]) =>
  __test.buildCommandArgs(command, getInput, () => {});

describe("AIBoMGen Action command argument builder", () => {
  beforeEach(() => {
    inputMap = {};
  });

  it("builds scan args with defaults", () => {
    inputMap["scan-input"] = "./repo";

    const result = build("scan");

    assert.deepEqual(result.argsList, [
      ["--no-input", "scan", "--input", "./repo", "--format", "json", "--hf-mode", "online"],
    ]);
    assert.equal(result.outputSuffix, ".aibom.cdx.json");
    assert.deepEqual(result.env, {});
  });

  it("rejects the removed auto format", () => {
    inputMap.format = "auto";
    assert.throws(() => build("scan"), /format.*json, xml/i);
  });

  it("passes the HF token as env, never as an argument, and masks it", () => {
    inputMap["hf-token"] = "hf_secret";
    const secrets: string[] = [];

    const result = __test.buildCommandArgs("scan", getInput, (s) => secrets.push(s));

    assert.deepEqual(result.env, { HF_TOKEN: "hf_secret" });
    assert.equal(result.argsList.flat().includes("hf_secret"), false);
    assert.deepEqual(secrets, ["hf_secret"]);
  });

  it("maps log-level to the v0.3.0 verbosity flags", () => {
    inputMap["log-level"] = "quiet";
    assert.deepEqual(build("scan").argsList[0].slice(0, 2), ["--no-input", "--quiet"]);
    inputMap["log-level"] = "debug";
    assert.deepEqual(build("scan").argsList[0].slice(0, 2), ["--no-input", "-vv"]);
  });

  it("requires model IDs for generate", () => {
    assert.throws(() => build("generate"), /generate-model-ids.*required.*command=generate/i);
  });

  it("builds generate args with multiple model IDs and options", () => {
    inputMap["generate-model-ids"] = "gpt2,google-bert/bert-base-uncased";
    inputMap["no-security-scan"] = "true";
    inputMap["spec-version"] = "1.6";
    inputMap["hf-timeout"] = "30";
    inputMap.format = "xml";

    const result = build("generate");

    assert.deepEqual(result.argsList[0], [
      "--no-input",
      "generate",
      "--model-id",
      "gpt2",
      "--model-id",
      "google-bert/bert-base-uncased",
      "--format",
      "xml",
      "--spec",
      "1.6",
      "--hf-mode",
      "online",
      "--hf-timeout",
      "30",
      "--no-security-scan",
    ]);
    assert.equal(result.outputSuffix, ".aibom.cdx.xml");
  });

  it("requires validate input and a min score between 0 and 1", () => {
    assert.throws(() => build("validate"), /validate-input.*required.*command=validate/i);
    inputMap["validate-input"] = "dist/a.json";
    inputMap["validate-min-score"] = "1.5";
    assert.throws(() => build("validate"), /validate-min-score.*between 0 and 1/i);
  });

  it("builds one validate invocation per file with strict options", () => {
    inputMap["validate-input"] = "dist/a1.json\ndist/a2.json";
    inputMap["validate-strict"] = "true";
    inputMap["validate-fail-severity"] = "high";
    inputMap["validate-min-score"] = "0.5";

    const flags = ["--strict", "--fail-severity", "high", "--min-score", "0.5"];
    assert.deepEqual(build("validate").argsList, [
      ["--no-input", "validate", "--input", "dist/a1.json", ...flags],
      ["--no-input", "validate", "--input", "dist/a2.json", ...flags],
    ]);
  });

  it("builds completeness args", () => {
    assert.throws(() => build("completeness"), /completeness-input.*required/i);
    inputMap["completeness-input"] = "dist/a.json";
    assert.deepEqual(build("completeness").argsList, [
      ["--no-input", "completeness", "--input", "dist/a.json"],
    ]);
  });

  it("builds vuln-scan report-only args without outputs", () => {
    assert.throws(() => build("vuln-scan"), /vuln-scan-input.*required/i);
    inputMap["vuln-scan-input"] = "dist/a.json";

    const result = build("vuln-scan");

    assert.deepEqual(result.argsList, [["--no-input", "vuln-scan", "--input", "dist/a.json"]]);
    assert.deepEqual(result.outputFiles, []);
  });

  it("enriches each vuln-scan input in place without prompting", () => {
    inputMap["vuln-scan-input"] = "dist/a1.json,dist/a2.json";
    inputMap["vuln-scan-enrich"] = "true";

    const result = build("vuln-scan");

    assert.deepEqual(result.argsList, [
      ["--no-input", "vuln-scan", "--input", "dist/a1.json", "--enrich", "--yes"],
      ["--no-input", "vuln-scan", "--input", "dist/a2.json", "--enrich", "--yes"],
    ]);
    assert.deepEqual(result.outputFiles, ["dist/a1.json", "dist/a2.json"]);
  });

  it("builds merge args with multiple AIBOM inputs", () => {
    inputMap["merge-aibom-files"] = "dist/a1.json,dist/a2.json";
    inputMap["merge-sbom-file"] = "sbom.json";
    assert.throws(() => build("merge"), /merge-output-file.*required/i);
    inputMap["merge-output-file"] = "dist/merged.json";
    inputMap["merge-deduplicate"] = "false";

    const result = build("merge");

    assert.deepEqual(result.argsList[0], [
      "--no-input",
      "merge",
      "--aibom",
      "dist/a1.json",
      "--aibom",
      "dist/a2.json",
      "--sbom",
      "sbom.json",
      "--output",
      "dist/merged.json",
      "--no-deduplicate",
    ]);
    assert.deepEqual(result.outputFiles, ["dist/merged.json"]);
  });
});

describe("AIBoMGen Action helpers", () => {
  it("uses default artifact names per command", () => {
    assert.equal(__test.getArtifactName("scan", getInput), "output-aiboms");
    assert.equal(__test.getArtifactName("generate", getInput), "output-aiboms");
    assert.equal(__test.getArtifactName("vuln-scan", getInput), "output-aiboms-vuln");
    assert.equal(__test.getArtifactName("merge", getInput), "merged");
  });

  it("finds a shared artifact root for files across directories", () => {
    assert.equal(
      __test.getArtifactRootDir(["dist/aibom/model-a.json", "dist/sbom/merged.xml"]),
      path.resolve("dist"),
    );
    assert.equal(__test.getArtifactRootDir(["dist/a.json"]), path.resolve("dist"));
  });

  it("names release assets like the aibomgen-cli releases", () => {
    assert.match(
      __test.getReleaseAssetName("v0.3.0"),
      /^aibomgen-cli_0\.3\.0_\w+_\w+\.(tar\.gz|zip)$/,
    );
  });
});
