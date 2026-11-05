import artifactClient, { UploadArtifactOptions } from "@actions/artifact";
import * as core from "@actions/core";
import * as github from "@actions/github";
import { GitHub } from "@actions/github/lib/utils";
import { Release } from "@octokit/webhooks-types";
import { stringify } from "./Util";

export type GithubRepo = { owner: string; repo: string };

export interface ReleaseAsset {
  id: number;
  name: string;
}

/**
 * Wraps a string in dashes to 80 chars width, used as a log section header.
 */
export function dashWrap(str: string): string {
  let out = ` ${str} `;
  while (out.length < 80) {
    out = `-${out}-`;
  }
  return out.substring(0, 80);
}

/**
 * Logs values under a labelled debug group when debug mode is active.
 */
export function debugLog(label: string, ...args: unknown[]): void {
  if (core.isDebug()) {
    core.startGroup(label);
    for (const arg of args) {
      core.debug(typeof arg === "string" ? arg : stringify(arg));
    }
    core.endGroup();
  }
}

/**
 * Returns a configured Octokit client.
 */
export function getClient(repo: GithubRepo, token: string): GithubClient {
  return new GithubClient(github.getOctokit(token), repo);
}

/**
 * Thin wrapper around the GitHub APIs this action needs.
 */
export class GithubClient {
  constructor(
    private octokit: InstanceType<typeof GitHub>,
    private repo: GithubRepo,
  ) {}

  async uploadWorkflowArtifact({
    files,
    rootDir,
    name,
    retention,
  }: {
    files: string[];
    rootDir: string;
    name: string;
    retention: number;
  }): Promise<void> {
    const options: UploadArtifactOptions = retention > 0 ? { retentionDays: retention } : {};
    await artifactClient.uploadArtifact(name, files, rootDir, options);
  }

  async findRelease({ tag }: { tag: string }): Promise<Release | undefined> {
    try {
      const res = await this.octokit.rest.repos.getReleaseByTag({ ...this.repo, tag });
      return res.data as unknown as Release;
    } catch {
      return undefined;
    }
  }

  async listReleaseAssets({ release }: { release: Release }): Promise<ReleaseAsset[]> {
    const assets = await this.octokit.paginate(this.octokit.rest.repos.listReleaseAssets, {
      ...this.repo,
      release_id: release.id,
      per_page: 100,
    });
    return assets.map((a) => ({ id: a.id, name: a.name }));
  }

  async deleteReleaseAsset({ asset }: { asset: ReleaseAsset }): Promise<void> {
    await this.octokit.rest.repos.deleteReleaseAsset({ ...this.repo, asset_id: asset.id });
  }

  async uploadReleaseAsset({
    release,
    assetName,
    contents,
    contentType,
  }: {
    release: Release;
    assetName: string;
    contents: string;
    contentType: string;
  }): Promise<void> {
    await this.octokit.rest.repos.uploadReleaseAsset({
      ...this.repo,
      release_id: release.id,
      name: assetName,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      data: contents as any,
      headers: { "content-type": contentType },
    });
  }
}
