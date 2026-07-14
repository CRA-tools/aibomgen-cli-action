# AIBoMGen CLI: GitHub Action

A GitHub Action wrapper for [aibomgen-cli](https://github.com/idlab-discover/aibomgen-cli) that supports the non-interactive CI workflows for generating, validating, enriching, and merging AIBOM data.

## AIBoMGen Ecosystem

This repository is part of the broader AIBoMGen ecosystem for generating, analyzing, and validating AI/ML Bills of Materials (AIBOMs).

| Repository | Purpose |
|---|---|
| [AIBoMGen CLI](https://github.com/idlab-discover/aibomgen-cli) | Command-line tool for generating AIBOMs from source code and ML artifacts |
| [AIBoMGen CLI Action](https://github.com/CRA-tools/AIBoMGen-cli-action) | GitHub Action for automated AIBOM generation in CI/CD pipelines |
| [AIBoMGen CLI Dashboard](https://github.com/CRA-tools/aibomgen-cli-dashboard) | Demo dashboard using [AIBoMGen CLI](https://github.com/idlab-discover/aibomgen-cli) |
| [AIBoMGen](https://github.com/idlab-discover/AIBoMGen) | Proof of concept research repository |
| [AIBoMGen Experiments](https://github.com/idlab-discover/AIBoMGen-experiments) | Experimental evaluations of [AIBoMGen](https://github.com/idlab-discover/AIBoMGen)|

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
    format: json
```

### 3) Validate AIBOM and fail CI on strict checks

```yaml
- uses: idlab-discover/aibomgen-cli-action@main
  with:
    command: validate
    validate-input: |
      dist/generated_aibom-1.json
      dist/generated_aibom-2.json
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

### Artifact and release naming

- For `scan`, `generate`, and `merge`, the action uploads the produced BOM files with their original filenames preserved.
- Workflow artifacts are uploaded as a single artifact bundle. If `artifact-name` is set, it changes only the bundle label shown in GitHub Actions, not the filenames inside the bundle.
- Release uploads use the current run's produced files directly when the workflow is running on a release event or a tag push that resolves to a release.
- If `generate` produces multiple AIBOM files, all discovered files are uploaded to the workflow artifact and attached to the release.
- `generate` does not support `output-file`; it writes per-model AIBOM files so they can be validated, merged, and uploaded individually.
- `aibom-artifact-match` remains available as a fallback for release attachment when current-run output files are not available.

### Input highlights

- Common: `command`, `aibomgen-version`, `aibomgen-sha256`, `format`, `output-file`, `config`, `log-level`
- Hugging Face: `hf-token`, `hf-mode`, `hf-timeout`, `no-security-scan`
- Validate: `validate-input` (single file or comma/newline-separated files), `validate-strict`, `validate-min-score`, `validate-check-model-card`
- Completeness: `completeness-input`, `completeness-plain-summary`
- Vuln scan: `vuln-scan-input`, `vuln-scan-enrich`, `vuln-scan-no-preview`, `vuln-scan-output-format`
- Merge: `merge-aibom-files`, `merge-sbom-file`, `merge-output-file`, `merge-deduplicate`
- Artifact/release: `upload-artifact`, `artifact-name` (bundle label only), `upload-artifact-retention`, `upload-release-assets`, `aibom-artifact-match` (fallback release lookup), `aibom-artifact-match-mode`, `release-ref-prefix`

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

## Contact

For inquiries, feel free to reach out

Maintained by:

Wiebe Vandendriessche  
[wiebe.vandendriessche@ugent.be](mailto:wiebe.vandendriessche@ugent.be)  
[LinkedIn](https://www.linkedin.com/in/wiebe-vandendriessche/?locale=en_US)  
[DISCOVER: IDLab, Ghent University – imec](https://idlab.ugent.be/research-teams/discover).

## License

This project is licensed under the terms described in the [LICENSE](./LICENSE) file.

## Acknowledgements

This work has been partially supported by the [CRACY project](https://cra-cy.eu/), funded by the European Union’s Digital Europe Programme under grant agreement No 101190492.
