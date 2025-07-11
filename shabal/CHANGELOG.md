# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.5.0 (UNRELEASED)
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

## 0.4.1 (2022-02-17)
### Fixed
- Minimal versions build ([#363])

[#363]: https://github.com/RustCrypto/hashes/pull/363

## 0.4.0 (2021-12-07)
### Changed
- Update to `digest` v0.10 ([#217])

[#217]: https://github.com/RustCrypto/hashes/pull/217

## 0.3.0 (2020-06-12)
### Changed
- Bump `opaque-debug` to v0.3.0 ([#168])
- Bump `block-buffer` to v0.9 release ([#164])
- Bump `digest` to v0.9 release; MSRV 1.41 ([#155])
- Use new `*Dirty` traits from the `digest` crate ([#153])
- Rename `*result*` to `finalize` ([#148])
- Upgrade to Rust 2018 edition ([#135])

[#168]: https://github.com/RustCrypto/hashes/pull/168
[#164]: https://github.com/RustCrypto/hashes/pull/151
[#155]: https://github.com/RustCrypto/hashes/pull/155
[#153]: https://github.com/RustCrypto/hashes/pull/153
[#148]: https://github.com/RustCrypto/hashes/pull/148
[#135]: https://github.com/RustCrypto/hashes/pull/135

## 0.2.0 (2019-02-26)

## 0.1.0 (2019-02-25)
