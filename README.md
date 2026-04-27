# AIBoMGen CLI: GitHub Action

A GitHub Action wrapper for [aibomgen-cli](https://github.com/idlab-discover/aibomgen-cli) that supports the non-interactive CI workflows for generating, validating, enriching, and merging AIBOM data.

## Usage

The action is command-based:

- `scan`
- `generate`
- `validate`
- `completeness`
- `vuln-scan`
- `merge`
- `download`

Interactive CLI flows are intentionally not first-class in CI-oriented action usage.

### 1) Scan source tree and upload artifacts

```yaml
- uses: idlab-discover/aibomgen-cli-action@main
  with:
    command: scan
    scan-input: .
    format: auto
    output-file: dist/aibom.json
    spec-version: "1.6"
    hf-mode: online
    hf-timeout: 0
    no-security-scan: "false"
    log-level: standard
    aibomgen-version: v0.2.1
    upload-artifact: "true"
    upload-release-assets: "false"
```

### 2) Generate from explicit model IDs

```yaml
- uses: idlab-discover/aibomgen-cli-action@main
  with:
    command: generate
    generate-model-ids: |
      google-bert/bert-base-uncased
      gpt2
    output-file: dist/generated_aibom.json
    format: json
```

### 3) Validate AIBOM and fail CI on strict checks

```yaml
- uses: idlab-discover/aibomgen-cli-action@main
  with:
    command: validate
    validate-input: dist/generated_aibom.json
    validate-strict: "true"
    validate-min-score: "0.6"
    validate-check-model-card: "true"
```

### 4) Merge one SBOM with multiple AIBOM files

```yaml
- uses: idlab-discover/aibomgen-cli-action@main
  with:
    command: merge
    merge-aibom-files: |
      dist/model1_aibom.json
      dist/model2_aibom.json
    merge-sbom-file: dist/sbom.json
    merge-output-file: dist/merged_bom.json
```

### 5) Download-only mode

```yaml
- id: aibomgen
  uses: idlab-discover/aibomgen-cli-action@main
  with:
    command: download
```

### Release upload permissions

If `upload-release-assets: "true"`, your workflow should grant:

```yaml
permissions:
  contents: write
  actions: read
```

### Input highlights

- Common: `command`, `aibomgen-version`, `aibomgen-sha256`, `format`, `output-file`, `config`, `log-level`
- Hugging Face: `hf-token`, `hf-mode`, `hf-timeout`, `no-security-scan`
- Validate: `validate-input`, `validate-strict`, `validate-min-score`, `validate-check-model-card`
- Completeness: `completeness-input`, `completeness-plain-summary`
- Vuln scan: `vuln-scan-input`, `vuln-scan-enrich`, `vuln-scan-no-preview`, `vuln-scan-output-format`
- Merge: `merge-aibom-files`, `merge-sbom-file`, `merge-output-file`, `merge-deduplicate`
- Artifact/release: `upload-artifact`, `artifact-name`, `upload-artifact-retention`, `upload-release-assets`, `aibom-artifact-match`, `aibom-artifact-match-mode`, `release-ref-prefix`

### Outputs

- `cmd`: resolved aibomgen-cli path (download command)
- `executed-command`: command run by action
- `written-files`: newline-separated discovered output files

### Local validation

Run the same core checks used by CI before opening a PR:

```bash
npm run build
npm run lint
npm test
npm run package
```

### Notes

- Default bundled CLI version is `v0.2.1`.
- `aibomgen-sha256` can be used to verify release archive integrity.
- Artifact pattern matching mode is constrained to `exact` or `glob` (no raw regex).
