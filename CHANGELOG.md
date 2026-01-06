# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
