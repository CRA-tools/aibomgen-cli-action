import assert from "node:assert";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { beforeEach, describe, it } from "node:test";
import { __test } from "../src/github/AIBoMGenGithubAction";

type InputMap = Record<string, string>;

let inputMap: InputMap;
let getInput: (name: string) => string;

describe("AIBoMGen Action command argument builder", () => {
  beforeEach(() => {
    inputMap = {
      format: "json",
      "hf-mode": "online",
      "hf-timeout": "0",
      "log-level": "standard",
      "no-security-scan": "false",
      "spec-version": "",
      "output-file": "",
      "hf-token": "",
      config: "",
    };

    getInput = (name: string) => inputMap[name] ?? "";
  });

  it("requires model IDs for generate", () => {
    assert.throws(
      () => __test.buildCommandArgs("generate", getInput, () => {}),
      /generate-model-ids.*required.*command=generate/i,
    );
  });

  it("builds scan args with input", () => {
    inputMap["scan-input"] = "./repo";

    const result = __test.buildCommandArgs("scan", getInput, () => {});

    assert.ok(result.args.includes("scan"));
    assert.ok(result.args.includes("--input"));
    assert.ok(result.args.includes("./repo"));
    assert.equal(result.args.includes("--output"), false);
    assert.deepEqual(result.expectedOutputFiles, []);
  });

  it("rejects output-file for scan", () => {
    inputMap["scan-input"] = "./repo";
    inputMap["output-file"] = "dist/out.json";

    assert.throws(
      () => __test.buildCommandArgs("scan", getInput, () => {}),
      /output-file.*not supported.*command=scan/i,
    );
  });

  it("builds generate args with multiple model IDs", () => {
    inputMap["generate-model-ids"] = "gpt2,google-bert/bert-base-uncased";
    inputMap["no-security-scan"] = "true";

    const result = __test.buildCommandArgs("generate", getInput, () => {});

    assert.ok(result.args.includes("generate"));
    assert.ok(result.args.includes("--model-id"));
    assert.ok(result.args.includes("gpt2"));
    assert.ok(result.args.includes("google-bert/bert-base-uncased"));
    assert.ok(result.args.includes("--no-security-scan"));
  });

  it("rejects output-file for generate", () => {
    inputMap["generate-model-ids"] = "gpt2,google-bert/bert-base-uncased";
    inputMap["output-file"] = "dist/generated_aibom.json";

    assert.throws(
      () => __test.buildCommandArgs("generate", getInput, () => {}),
      /output-file.*not supported.*command=generate/i,
    );
  });

  it("rejects validate min score outside range", () => {
    inputMap["validate-input"] = "dist/aibom.json";
    inputMap["validate-min-score"] = "1.5";

    assert.throws(
      () => __test.buildCommandArgs("validate", getInput, () => {}),
      /validate-min-score.*between 0 and 1/i,
    );
  });

  it("requires validate input", () => {
    assert.throws(
      () => __test.buildCommandArgs("validate", getInput, () => {}),
      /validate-input.*required.*command=validate/i,
    );
  });

  it("builds validate args with strict and min-score", () => {
    inputMap["validate-input"] = "dist/aibom.json";
    inputMap["validate-strict"] = "true";
    inputMap["validate-min-score"] = "0.7";
    inputMap["validate-check-model-card"] = "true";

    const result = __test.buildCommandArgs("validate", getInput, () => {});

    assert.ok(result.args.includes("validate"));
    assert.ok(result.args.includes("--strict"));
    assert.ok(result.args.includes("--check-model-card"));
    assert.ok(result.args.includes("--min-score"));
    assert.ok(result.args.includes("0.7"));
    assert.deepEqual(result.argsList, [result.args]);
  });

  it("builds validate args for multiple input files", () => {
    inputMap["validate-input"] = "dist/a1.json\ndist/a2.json";
    inputMap["validate-strict"] = "true";

    const result = __test.buildCommandArgs("validate", getInput, () => {});

    assert.equal(result.argsList.length, 2);
    assert.deepEqual(result.argsList[0], [
      "validate",
      "--input",
      "dist/a1.json",
      "--format",
      "json",
      "--strict",
      "--log-level",
      "standard",
    ]);
    assert.deepEqual(result.argsList[1], [
      "validate",
      "--input",
      "dist/a2.json",
      "--format",
      "json",
      "--strict",
      "--log-level",
      "standard",
    ]);
  });

  it("requires completeness input", () => {
    assert.throws(
      () => __test.buildCommandArgs("completeness", getInput, () => {}),
      /completeness-input.*required.*command=completeness/i,
    );
  });

  it("builds completeness args with plain summary", () => {
    inputMap["completeness-input"] = "dist/aibom.json";
    inputMap["completeness-plain-summary"] = "true";

    const result = __test.buildCommandArgs("completeness", getInput, () => {});

    assert.ok(result.args.includes("completeness"));
    assert.ok(result.args.includes("--plain-summary"));
  });

  it("requires vuln-scan input", () => {
    assert.throws(
      () => __test.buildCommandArgs("vuln-scan", getInput, () => {}),
      /vuln-scan-input.*required.*command=vuln-scan/i,
    );
  });

  it("builds vuln-scan args with enrich options", () => {
    inputMap["vuln-scan-input"] = "dist/aibom.json";
    inputMap["vuln-scan-enrich"] = "true";
    inputMap["vuln-scan-no-preview"] = "true";
    inputMap["vuln-scan-output-format"] = "xml";

    const result = __test.buildCommandArgs("vuln-scan", getInput, () => {});

    assert.ok(result.args.includes("vuln-scan"));
    assert.ok(result.args.includes("--enrich"));
    assert.ok(result.args.includes("--output-format"));
    assert.ok(result.args.includes("xml"));
    assert.ok(result.args.includes("--no-preview"));
    assert.equal(result.args.includes("--output"), false);
    assert.deepEqual(result.expectedOutputFiles, ["dist/aibom.json"]);
  });

  it("builds vuln-scan args for multiple input files", () => {
    inputMap["vuln-scan-input"] = "dist/a1.json\ndist/a2.json";
    inputMap["vuln-scan-enrich"] = "true";
    inputMap["vuln-scan-no-preview"] = "true";

    const result = __test.buildCommandArgs("vuln-scan", getInput, () => {});

    assert.equal(result.argsList.length, 2);
    assert.deepEqual(result.argsList[0], [
      "vuln-scan",
      "--input",
      "dist/a1.json",
      "--format",
      "json",
      "--enrich",
      "--output-format",
      "auto",
      "--no-preview",
      "--log-level",
      "standard",
    ]);
    assert.deepEqual(result.argsList[1], [
      "vuln-scan",
      "--input",
      "dist/a2.json",
      "--format",
      "json",
      "--enrich",
      "--output-format",
      "auto",
      "--no-preview",
      "--log-level",
      "standard",
    ]);
    assert.deepEqual(result.expectedOutputFiles, ["dist/a1.json", "dist/a2.json"]);
  });

  it("rejects output-file for vuln-scan", () => {
    inputMap["vuln-scan-input"] = "dist/a1.json\ndist/a2.json";
    inputMap["output-file"] = "dist/enriched.json";

    assert.throws(
      () => __test.buildCommandArgs("vuln-scan", getInput, () => {}),
      /output-file.*not supported.*command=vuln-scan/i,
    );
  });

  it("builds merge args with multiple AIBOM inputs", () => {
    inputMap["merge-aibom-files"] = "dist/a1.json,dist/a2.json";
    inputMap["merge-sbom-file"] = "dist/sbom.json";
    inputMap["merge-output-file"] = "dist/merged.json";
    inputMap["merge-deduplicate"] = "false";

    const result = __test.buildCommandArgs("merge", getInput, () => {});

    assert.deepEqual(result.expectedOutputFiles, ["dist/merged.json"]);
    assert.ok(result.args.includes("merge"));
    assert.ok(result.args.includes("--aibom"));
    assert.ok(result.args.includes("dist/a1.json"));
    assert.ok(result.args.includes("dist/a2.json"));
    assert.ok(result.args.includes("--sbom"));
    assert.ok(result.args.includes("dist/sbom.json"));
    assert.ok(result.args.includes("--deduplicate=false"));
  });

  it("builds download command without requiring extra inputs", () => {
    const result = __test.buildCommandArgs("download", getInput, () => {});

    assert.deepEqual(result.expectedOutputFiles, []);
    assert.equal(result.outputDirectory, "dist");
    assert.equal(result.outputSuffix, "");
  });
});

describe("AIBoMGen Action safety helpers", () => {
  it("uses requested default artifact names for scan generate and merge", () => {
    assert.equal(__test.getArtifactName("scan"), "output-aiboms");
    assert.equal(__test.getArtifactName("generate"), "output-aiboms");
    assert.equal(__test.getArtifactName("merge"), "merged");
  });

  it("supports exact and glob artifact matching", () => {
    assert.equal(
      __test.artifactMatches("repo-job-scan-aibom", "repo-job-scan-aibom", "exact"),
      true,
    );
    assert.equal(__test.artifactMatches("repo-job-scan-aibom", "repo-*-scan-*", "glob"), true);
    assert.equal(__test.artifactMatches("repo-job-scan-aibom", "other-*", "glob"), false);
  });

  it("redacts sensitive values in logs", () => {
    const text = "cmd --hf-token my-secret-token --config /tmp/config.yml";
    const redacted = __test.redactText(text, ["my-secret-token", "/tmp/config.yml"]);
    assert.equal(redacted.includes("my-secret-token"), false);
    assert.equal(redacted.includes("/tmp/config.yml"), false);
    assert.equal(redacted.includes("***"), true);
  });

  it("finds a shared artifact root for files across directories", () => {
    const rootDir = __test.getArtifactRootDir(["dist/aibom/model-a.json", "dist/sbom/merged.xml"]);

    assert.equal(rootDir, path.resolve("dist"));
  });

  it("filters missing current-run release files", () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "aibomgen-current-run-"));
    const existingFile = path.join(tmpDir, "aibom.json");
    fs.writeFileSync(existingFile, "{}");

    const releaseFiles = __test.getCurrentRunReleaseAssetFiles({
      command: "scan",
      writtenFiles: [existingFile, path.join(tmpDir, "missing.json")],
    });

    assert.deepEqual(releaseFiles, [path.resolve(existingFile)]);

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("recursively lists files from downloaded artifact contents", () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "aibomgen-artifact-files-"));
    const nestedDir = path.join(tmpDir, "nested");
    const topLevelFile = path.join(tmpDir, "aibom.json");
    const nestedFile = path.join(nestedDir, "merged.xml");

    fs.mkdirSync(nestedDir, { recursive: true });
    fs.writeFileSync(topLevelFile, "{}");
    fs.writeFileSync(nestedFile, "<bom />");

    const files = __test.listFilesRecursive(tmpDir).sort();

    assert.deepEqual(files, [nestedFile, topLevelFile].sort());

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });
});
