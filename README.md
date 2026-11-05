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

The action is command-based. Each `command` runs one [aibomgen-cli](https://github.com/idlab-discover/aibomgen-cli) command, non-interactively:

- `scan`: detect the Hugging Face models a directory uses and write one AIBOM per model
- `generate`: write AIBOMs for explicit model IDs
- `validate`: check AIBOMs against the CycloneDX schema, completeness, and vulnerability findings
- `completeness`: print a completeness report for one AIBOM
- `vuln-scan`: fetch the Hub's security scan results again, and optionally write them into the AIBOMs
- `merge`: merge AIBOMs into an SBOM from any generator
- `download`: only install the CLI and output its path as `cmd`

All inputs and their defaults are listed in [action.yml](./action.yml). The examples use the `@v1` tag; for the strongest supply-chain guarantee, pin a full commit SHA instead.

### Reference pipeline

[.github/workflows/reference-pipeline.yml](.github/workflows/reference-pipeline.yml) is the DevSecOps pipeline from Fig. 1 of the AIBoMGen CLI paper. It runs on every push to this repository against the fake product in [examples/reference-product](examples/reference-product), so it also tests the action:

1. generate an SBOM with an SBOM generator of choice (Syft)
2. `scan` the product and write one AIBOM per model
3. `validate` the AIBOMs in strict mode (fails the build on invalid AIBOMs or findings rated `high` or above)
4. `merge` the AIBOMs into the SBOM
5. sign every AIBOM and the merged BOM with keyless Sigstore ([gh-action-sigstore-python](https://github.com/sigstore/gh-action-sigstore-python)), which also verifies the signatures
6. upload everything as the `reference-boms` workflow artifact
7. on a release of the product, attach the same files to that release

Releases of the fake product are tagged `reference-product-v*`, separate from the action's own `vX.Y.Z` releases, which the pipeline ignores. Create them as prereleases that are not marked latest, so the action release stays the repository's latest release:

```bash
gh release create reference-product-v1.0.0 --prerelease --latest=false \
  --title "Reference product v1.0.0" --notes "Release of the fake product in examples/reference-product"
```

[.github/workflows/reference-security-gate.yml](.github/workflows/reference-security-gate.yml) covers the failing branch. It scans [examples/reference-product-unsafe](examples/reference-product-unsafe), which uses [`ykilcher/totally-harmless-model`](https://huggingface.co/ykilcher/totally-harmless-model), a demo model whose `pytorch_model.bin` every Hub scanner rates critical. The workflow succeeds only when strict validation blocks the build. The AIBOM, with the finding in its `vulnerabilities`, is uploaded as `blocked-aiboms` for inspection.

[.github/workflows/reference-refresh.yml](.github/workflows/reference-refresh.yml) is the scheduled half. Every week, and after each successful pipeline run on `main`, it downloads the latest AIBOMs, refreshes their security findings with `vuln-scan` (`vuln-scan-enrich: "true"`), and validates them again.

Copy the workflows into your own repository, replacing `uses: ./` with `uses: CRA-tools/aibomgen-cli-action@v1` and `PRODUCT_DIR` with the directory to scan. To verify a signature from the artifact:

```bash
cosign verify-blob merged.cdx.json \
  --bundle merged.cdx.json.sigstore.json \
  --certificate-identity "https://github.com/CRA-tools/aibomgen-cli-action/.github/workflows/reference-pipeline.yml@refs/heads/main" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

For files from a product release, the identity ends in `@refs/tags/<tag>` instead of `@refs/heads/main`.

### Command examples

#### Scan a repository

```yaml
- id: scan
  uses: CRA-tools/aibomgen-cli-action@v1
  with:
    command: scan
    scan-input: .
    hf-token: ${{ secrets.HF_TOKEN }} # optional, for gated models and higher rate limits
```

#### Generate from explicit model IDs

```yaml
- uses: CRA-tools/aibomgen-cli-action@v1
  with:
    command: generate
    generate-model-ids: |
      google-bert/bert-base-uncased
      gpt2
    format: json
```

#### Validate AIBOM files

```yaml
- uses: CRA-tools/aibomgen-cli-action@v1
  with:
    command: validate
    validate-input: ${{ steps.scan.outputs.written-files }}
    validate-strict: "true"
    validate-fail-severity: high
    validate-min-score: "0.5"
```

#### Merge AIBOM files into an SBOM

```yaml
- uses: CRA-tools/aibomgen-cli-action@v1
  with:
    command: merge
    merge-aibom-files: ${{ steps.scan.outputs.written-files }}
    merge-sbom-file: sbom.cdx.json
    merge-output-file: dist/merged.cdx.json
```

The merged BOM is written as XML when `merge-output-file` ends in `.xml`, and as JSON otherwise.

#### Refresh vulnerability findings in existing AIBOMs

```yaml
- uses: CRA-tools/aibomgen-cli-action@v1
  with:
    command: vuln-scan
    vuln-scan-input: |
      dist/model1.aibom.cdx.json
      dist/model2.aibom.cdx.json
    vuln-scan-enrich: "true"
```

With `vuln-scan-enrich: "true"`, each AIBOM is updated in place. Without it, the findings are only reported.

#### Check completeness of an AIBOM

```yaml
- uses: CRA-tools/aibomgen-cli-action@v1
  with:
    command: completeness
    completeness-input: dist/model.aibom.cdx.json
```

#### Download-only mode

```yaml
- id: aibomgen
  uses: CRA-tools/aibomgen-cli-action@v1
  with:
    command: download
- run: ${{ steps.aibomgen.outputs.cmd }} --help
```

### Artifacts and releases

- `scan`, `generate`, `merge`, and an enriching `vuln-scan` upload the files they write as one workflow artifact, keeping the original filenames. The default artifact names are `output-aiboms` (`scan`, `generate`), `output-aiboms-vuln` (`vuln-scan`), and `merged` (`merge`); `artifact-name` overrides them. Set `upload-artifact: "false"` to skip the upload.
- On a `release` event or a tag push that has a release, the same files are attached to that release (`upload-release-assets`). This needs:

```yaml
permissions:
  contents: write
```

### Outputs

- `cmd`: path to the installed aibomgen-cli (`download` command)
- `executed-command`: the command the action ran
- `written-files`: newline-separated paths of the files the command wrote

### Local validation

Run the same checks as CI before opening a PR:

```bash
npm run all
```

### Notes

- The default CLI version is `v0.3.0` (`aibomgen-version`).
- `aibomgen-sha256` verifies the downloaded release archive.
- `hf-token` is passed to the CLI as the `HF_TOKEN` environment variable and masked in logs.

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
