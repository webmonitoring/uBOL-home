# Webmonitoring uBOL-home automation

This directory documents how we automate upgrades and publishing of the Chromium uBOL package.

## Branch model

1. `main`: mirror branch for upstream uBOL (`uBlockOrigin/uBOL-home`), no custom commits.
2. `wm/patches`: Webmonitoring customization branch, used as the default branch.
3. Upgrade PR direction: `main` -> `wm/patches`.

## Goal

Automate this loop:

1. Detect a new upstream uBOL release.
2. Sync `main` with upstream.
3. Open/update an upgrade PR into `wm/patches`.
4. When that PR is merged, publish the Chromium package with the same version as upstream.

## How it works

### 1) Upgrade detection and PR creation

Workflow: `/.github/workflows/upstream_upgrade_pr.yml`

This workflow:

1. Fetches upstream refs and tags.
2. Finds the latest upstream tag from `upstream/main`.
3. Classifies it as stable/beta.
4. Fast-forwards `origin/main` to match `upstream/main`.
5. Opens or updates PR `main` -> `wm/patches` with title `Upgrade UBOL to <tag>`.
6. Stores marker tag `ci/upstream-seen/<tag>` so the same release is not processed twice.

### 2) Publish when upgrade PR is merged

Workflow: `/.github/workflows/publish_chromium_package.yml`

This workflow runs when a PR is merged into `wm/patches` from `main` (and can also run manually).

Publish steps:

1. Sync `chromium/package.json` version from `chromium/manifest.json`.
2. Read the package version to publish.
3. Verify this version equals the latest tag on `origin/main`.
4. Check if `@webmonitoring/ublock-origin-lite-chromium@<version>` already exists on GitHub Packages.
5. Publish only if it does not already exist.
6. Open an issue in the monorepo asking for a renderer release using that published version.

The created monorepo issue requests:

1. Add a dependency alias in `screenshot-worker/package.json` like:
   - `"ubol-<version>": "npm:@webmonitoring/ublock-origin-lite-chromium@<version>"`
2. Run `npm install` in `screenshot-worker/` and commit lockfile changes if any.
3. Add a renderer version in `vp-common/src/Types/BaseTypes/JobRendererVersion.ts`.
4. Wire that version in `vp-common/src/Types/BaseTypes/JobRenderer.ts` as an experimental renderer setting.

Result:
the published npm package version stays aligned with the upstream uBOL release tag, and renderer follow-up is requested automatically.

## Triggering upgrade checks

The upgrade workflow supports:

1. `workflow_dispatch` (manual/API run).
2. `repository_dispatch` (`upstream_release`) for external automation (for example n8n).
