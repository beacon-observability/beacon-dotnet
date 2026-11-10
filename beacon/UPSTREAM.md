# Synchronizing OpenTelemetry .NET Automatic Instrumentation

Run all commands from the repository root. `main` is the Beacon downstream
branch. The official upstream `main` branch is used only to discover updates and
must not directly replace Beacon commits. The adopted release tag and commit are
recorded in [`upstream.lock.json`](upstream.lock.json).

## Remote Configuration

After the downstream repository has been created, `origin` must point to
`https://github.com/beacon-observability/beacon-dotnet.git`. Configure the
official repository only as `upstream`:

```bash
git remote add upstream https://github.com/open-telemetry/opentelemetry-dotnet-instrumentation.git
git remote set-url --push upstream DISABLED
git config remote.pushDefault origin
```

If a remote already exists, verify its URL before changing anything. Never push
to the official `upstream` remote.

## Pinning and Adopting an Official Baseline

1. Review the official Release. Verify the signed tag object, the full commit to
   which the tag resolves, and the Release artifacts. Do not infer a baseline
   only from the current upstream `main` branch.
2. Fetch the target tag locally and verify both the tag object and commit:

   ```bash
   git fetch --no-tags upstream refs/tags/v1.17.0:refs/tags/v1.17.0
   git rev-parse refs/tags/v1.17.0
   git rev-parse refs/tags/v1.17.0^{commit}
   ```

3. Create a synchronization branch from a clean `main`, merge the target commit,
   and preserve the merge commit. While resolving conflicts, retain Beacon
   product directories, artifact identity, and controlled CI. Do not replace the
   entire working tree with the new upstream directory.
4. Review the .NET SDK, OpenTelemetry Core, instrumentation packages, native
   toolchain, and NuGet dependencies. Base the dependency set on the adopted
   upstream release and real tests rather than blindly upgrading everything to
   the latest version.
5. Run Beacon checks, affected upstream tests, and target-platform builds.
   Complete archive, clean-environment startup, and DataKit-path validation for
   the intended release scope. Then update the baseline file and confirm that the
   target commit is part of the downstream branch:

   ```bash
   git merge-base --is-ancestor <upstream-commit-sha> HEAD
   ```

Fetching, merging, building, packaging, and releasing are distinct states.
Review newly introduced workflows after every synchronization. Inherited
upstream release workflows, bots, scheduled tasks, and third-party credential
flows must not automatically become Beacon entry points.

## Merging Synchronization Pull Requests

Merge synchronization pull requests with a merge commit. Squash and rebase
merges discard the original upstream commit ancestry even when the resulting
files are identical. The release validator requires the exact upstream commit
from `upstream.lock.json` to be an ancestor of the release commit.

The downstream branch protection policy must permit merge commits while retaining
required CI checks, conversation resolution, and force-push restrictions. A
linear-history requirement conflicts with this full-history synchronization
model. Do not bypass the ancestry check or rewrite published branch history.
