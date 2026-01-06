# GitHub Copilot Instructions

This repository implements a NIP-42 authentication proxy for Nostr relays. It adds client authentication support to upstream relays (like strfry) that don't natively support it.

## Guidelines

- Use Conventional Commits for titles and commit messages (e.g., `feat(scope): message`).
- Ensure pull requests include a clear description and test results.
- Reference related issues using `Closes #123` when applicable.
- Run `mvn -q verify` before committing code.
- Document new features in the README or related docs.
- Maintain Java 21 compatibility and update `pom.xml` for new dependencies.
- Remove unused imports.

## Relevant Nostr NIPs

When implementing features, consult the relevant NIP specifications:

- [NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md) - Basic protocol flow (events, subscriptions, messages)
- [NIP-42](https://github.com/nostr-protocol/nips/blob/master/42.md) - Client authentication (core to this proxy)
- [NIP-04](https://github.com/nostr-protocol/nips/blob/master/04.md) - Encrypted direct messages (protected kind)
- [NIP-17](https://github.com/nostr-protocol/nips/blob/master/17.md) - Private direct messages (protected kinds 14, 15)
- [NIP-46](https://github.com/nostr-protocol/nips/blob/master/46.md) - Nostr Connect / remote signing (protected kind 24133)
- [NIP-47](https://github.com/nostr-protocol/nips/blob/master/47.md) - Wallet Connect (protected kinds 23194-23197)
- [NIP-59](https://github.com/nostr-protocol/nips/blob/master/59.md) - Gift wraps (protected kinds 13, 1059)

## Architecture

```
Client (port 7777) ←→ NIP-42 Auth Proxy ←→ Upstream Relay (strfry @ 7778)
```

Key components:
- `auth/` - NIP-42 authentication and BIP-340 signature verification
- `session/` - WebSocket session management and state tracking
- `access/` - Access control (open, allowlist, blocklist modes)
- `handler/` - WebSocket message handling and upstream routing
- `upstream/` - Upstream relay client connections

These instructions help GitHub Copilot produce code that respects the repository's conventions and protocol requirements.