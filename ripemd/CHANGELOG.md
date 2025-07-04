# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.2.0 (UNRELEASED)
### Added
- `alloc` crate feature ([#678])

### Changed
- Edition changed to 2024 and MSRV bumped to 1.85 ([#652])
- Relax MSRV policy and allow MSRV bumps in patch releases
- Update to `digest` v0.11
- Replace type aliases with newtypes ([#678])

### Removed
- `std` crate feature ([#678])

[#652]: https://github.com/RustCrypto/hashes/pull/652
[#678]: https://github.com/RustCrypto/hashes/pull/678

## 0.1.3 (2022-09-23)
### Added
- Feature-gated OID support ([#415])

[#415]: https://github.com/RustCrypto/hashes/pull/415

## 0.1.2 (2022-09-16)
### Added
- RIPEMD-128 algorithm ([#406])

[#406]: https://github.com/RustCrypto/hashes/pull/406

## 0.1.1 (2022-02-17)
### Fixed
- Minimal versions build ([#363])

[#363]: https://github.com/RustCrypto/hashes/pull/363

## 0.1.0 (2021-12-07)
- Initial release of merged `ripemd160` and `ripemd320` crates updated
to `digest` v0.10. ([#217])

[#217]: https://github.com/RustCrypto/hashes/pull/217
