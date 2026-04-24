# AIBoMGen CLI: Generate AIBOM Action

A GitHub Action that generates an **AI Bill of Materials (AIBOM)** for Hugging Face models referenced in your repository, using [aibomgen-cli](https://github.com/idlab-discover/aibomgen-cli).

## Usage

```yaml
- uses: idlab-discover/aibomgen-cli-action@main
  with:
    # Directory to scan for Hugging Face model references.
    # Default: "."
    path: .

    # Output format: json | xml | auto
    # "auto" infers the format from the output-file extension.
    # Default: "json"
    format: json

    # CycloneDX spec version to target: 1.4 | 1.5 | 1.6
    # Default: CLI default (latest)
    spec-version: ""

    # Path to write the AIBOM file to.
    # Default: dist/aibom.json (or dist/aibom.xml for xml format)
    output-file: ""

    # Hugging Face access token. Required for private or gated models.
    hf-token: ""

    # How to fetch HF model metadata: online | dummy
    # "dummy" uses built-in fixture data for offline testing.
    # Default: "online"
    hf-mode: online

    # Timeout in seconds per Hugging Face API request.
    # Default: 0 (uses CLI default of 10 s)
    hf-timeout: 0

    # Log verbosity: quiet | standard | debug
    # Default: "standard"
    log-level: standard

    # Path to an aibomgen-cli config file (passed as --config before the subcommand).
    config: ""

    # Version tag to download from GitHub Releases, or a GitHub archive URL to
    # build from source (requires Go on the runner).
    # Default: "v0.1.0"
    aibomgen-version: v0.1.0

    # GitHub token for uploading artifacts and attaching release assets.
    # Default: ${{ github.token }}
    github-token: ${{ github.token }}

    # Override the workflow artifact name.
    artifact-name: ""

    # Upload the AIBOM as a downloadable workflow artifact.
    # Default: "true"
    upload-artifact: "true"

    # Artifact retention in days. 0 = repository default (max 90).
    # Default: 0
    upload-artifact-retention: 0

    # Attach the AIBOM to a GitHub release when the event is a release or tag push.
    # Default: "true"
    # If you want to upload on release:
    # In the workflow file set:
    # permissions:
    #   contents: write  # needed to attach to releases
    #   actions: read    # needed to list artifacts for release upload
    upload-release-assets: "true"

    # Regex to filter which artifacts are attached to the release.
    aibom-artifact-match: ""

    # Ref prefix used to detect tag-based release pushes.
    # Default: "refs/tags/"
    release-ref-prefix: refs/tags/

    # Action mode: scan | download-aibomgen
    # "download-aibomgen" only downloads the CLI and sets the "cmd" output.
    # Default: "scan"
    run: scan
```
