# API Stability Policy (Goal 466)

PledgeGuard follows [Semantic Versioning 2.0.0](https://semver.org/).

## Versioning

- **Major (0.x → 1.0)**: Breaking changes to public APIs.
- **Minor (1.0 → 1.1)**: New features, new public APIs, non-breaking changes.
- **Patch (1.0.0 → 1.0.1)**: Bug fixes, performance improvements, no new APIs.

## Stability Guarantees

### `pledgeguard-core` (library)

- All items exported in `lib.rs` are part of the public API.
- Struct fields that are `pub` are part of the public API.
- Enum variants are part of the public API.
- Functions marked `#[doc(hidden)]` are NOT part of the stable API.

### `pledgeguard-cli` (binary)

- CLI flags and subcommands follow deprecation cycles:
  - A deprecated flag emits a warning for one minor version before removal.
  - New subcommands are additive and don't break existing usage.

## Deprecation Policy

1. An API is marked `#[deprecated]` with a note explaining the replacement.
2. The API remains functional for at least one minor version.
3. The API is removed in the next major version.

## MSRV Policy (Goal 460)

- The Minimum Supported Rust Version is **1.85**.
- MSRV bumps require a minor version bump.
- MSRV is tested in CI against the exact pinned version.

## Compatibility

- `serde` serialization format is stable within a major version.
- JSON output format from `pledgeguard scan --format json` is stable within a major version.
- SARIF output follows the SARIF 2.1.0 specification.
