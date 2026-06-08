# Changelog

All notable changes to this project are documented here. The format is based on Keep a Changelog, and
the project aims to follow Semantic Versioning while in its 0.x line.

## [Unreleased]

### Added
- Community health files (CONTRIBUTING, SECURITY, CODE_OF_CONDUCT), issue and pull request templates,
  and a Dependabot configuration.
- A real-corpus coverage and false-positive sweep for the cross-version relocation anchors
  (`cross_version_relocation_coverage_and_false_positive_sweep`, run with `--ignored`).
- `cargo-deny` policy (`deny.toml`) gating advisories, licenses, bans, and sources, plus a forced-AVX2
  scanner test and a frontend render job in CI.
- `ARCHITECTURE.md` and a vendored-Monaco manifest with aggregated third-party license notes.

### Changed
- Hardened CI: least-privilege token, SHA-pinned actions, clippy `--all-features`, a doctest step, and
  dependency caching.
- Reframed the README cross-version efficacy figures around the measured sweep results.

### Fixed
- `module_arch` now rejects ARM and other non-x86/x64 machines instead of mapping them onto a bitness.
- The negative-corpus re-grade reads typed `packed`/`gated` flags instead of substring-matching reasons.
- Bounds and overflow hardening: checked `rel32` slicing, saturating region arithmetic, and the
  compiled-pattern anchor encoded as a non-optional field.
- The desktop workspace value cell is HTML-escaped consistently with every other field.

## [0.3.0] - 2026-06-08

### Added
- Cross-version function relocation: when a byte pattern no longer matches a recompiled build, the
  Signature Maker relocates the function by a recompile-stable handle (referenced string, imported-API
  set, string-anchored caller, C++ vtable structure with constructor grounding, or encoding
  fingerprint) and mints a fresh per-build AOB, reporting the version ranges each pattern covers.

## [0.2.0] - 2026-05-29

### Added
- Signature Maker scoring with independent sub-scores, cross-build validation, holdout, negative
  corpus, and string anchors; the desktop workspace and history; structured resolution traces.

## [0.1.3] - 2026-05-28
## [0.1.2] - 2026-05-27
## [0.1.1] - 2026-05-27

### Added
- Iterative hardening of the scanner, resolver, PE reader, CLI, and desktop app across the early
  releases.

## [0.1.0] - 2026-05-26

### Added
- Initial Rust implementation: AVX2 masked scanner, process reader, decode-driven resolver,
  module-relative RVA output, the CLI, and the desktop GUI.
