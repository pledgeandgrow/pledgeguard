# Chelog Generation Policy (Goal 467)

## Automated Changelog

PledgeGuard uses [cargo-release](https://github.com/crate-ci/cargo-release) for
release automation and generates `CHANGELOG.md` from conventional commit messages.

## Commit Message Format

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

### Types

- `feat`: New feature (triggers minor version bump)
- `fix`: Bug fix (triggers patch version bump)
- `breaking`: Breaking change (triggers major version bump)
- `docs`: Documentation changes
- `perf`: Performance improvements
- `refactor`: Code refactoring
- `test`: Test additions/changes
- `chore`: Maintenance tasks

### Examples

```
feat(scanner): add streaming scan for large files
fix(detectors): fix false positive on example AWS keys
breaking(api): rename ScanOptions.workers to ScanOptions.parallelism
docs(roadmap): update performance goals status
```

## Generation

The changelog is generated at release time using:

```bash
# Generate changelog from commits since last tag
git log $(git describe --tags --abbrev=0)..HEAD --pretty=format:"- %s" >> CHANGELOG.md
```

## Release Process (Goal 468)

1. Ensure all tests pass: `cargo test --workspace --all-targets`
2. Ensure clippy is clean: `cargo clippy --workspace --all-targets -- -D warnings`
3. Ensure formatting: `cargo fmt --all -- --check`
4. Bump version: `cargo release <patch|minor|major>`
5. Generate changelog entries
6. Create git tag: `v<version>`
7. Push tag: `git push --tags`
8. CI builds release binaries automatically

## Backport Policy (Goal 469)

Security fixes are backported to the previous minor version:

1. Identify the fix commit on `main`.
2. Cherry-pick to the `v<x.y>-maintenance` branch.
3. Create a patch release: `v<x.y.<z+1>`.
4. Document in CHANGELOG.md with `[SECURITY]` prefix.

## LTS Policy (Goal 470)

- The latest minor version receives all fixes.
- The previous minor version receives security fixes for 6 months.
- LTS branches are named `lts/v<x.y>`.
- LTS status is documented in the README.
