# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Add null checks for upstream response body in NIP-11 handlers
- Use system Maven instead of wrapper in CI workflow

### Changed

- Update `actions/setup-java` to v5 in google-java-format workflow

### Security

- Upgrade Spring Boot 3.5.5 → 3.5.8 (fixes CVE-2025-41249, CVE-2025-41254, CVE-2025-55754, CVE-2025-11226)
- Upgrade commons-lang3 3.17.0 → 3.18.0 (fixes CVE-2025-48924)
- Upgrade commons-compress 1.24.0 → 1.27.1 (fixes CVE-2024-25710, CVE-2024-26308)

## [0.1.1] - 2026-01-06

### Fixed

- Enforce auth requirement for REQ messages when `require-auth=true`

## [0.1.0] - 2026-01-06

### Added

- Initial standalone nostr-auth-proxy project
- NIP-42 client authentication with BIP-340 signature verification
- WebSocket proxy to upstream Nostr relays (strfry)
- Session management with per-pubkey connection limits
- Access control modes: open, allowlist, blocklist
- Protection for privacy-sensitive event kinds (DMs, wallet data, etc.)
- Spring Boot Actuator health checks and Prometheus metrics
- Docker image support via Jib

[Unreleased]: https://github.com/tcheeric/nostr-auth-proxy/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/tcheeric/nostr-auth-proxy/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/tcheeric/nostr-auth-proxy/releases/tag/v0.1.0
