# NIP-42 Auth Proxy

A lightweight WebSocket proxy that adds [NIP-42](https://github.com/nostr-protocol/nips/blob/master/42.md) client authentication to Nostr relays that don't support it natively (like strfry).

## Overview

This proxy sits in front of strfry (or any Nostr relay) and:
1. Accepts client WebSocket connections
2. Challenges clients with NIP-42 AUTH
3. Verifies BIP-340 Schnorr signatures
4. Proxies authenticated connections to the upstream relay
5. Rejects unauthenticated connections

## Architecture

```
┌──────────┐    WebSocket    ┌─────────────────────────┐    WebSocket    ┌─────────────┐
│  Client  │◄───────────────►│   NIP-42 Auth Proxy     │◄───────────────►│   strfry    │
└──────────┘   (port 7777)   │     (public)            │   (port 7778)   │  (internal) │
                             └─────────────────────────┘                 └─────────────┘
```

## Configuration

Configure via environment variables or `application.yml`:

| Property | Environment Variable | Default | Description |
|----------|---------------------|---------|-------------|
| `nostr.auth-proxy.upstream-relay` | `NOSTR_AUTH_PROXY_UPSTREAM` | `ws://localhost:7778` | Upstream relay URL |
| `nostr.auth-proxy.public-relay-url` | `NOSTR_AUTH_PROXY_PUBLIC_URL` | - | Public URL for relay tag validation |
| `nostr.auth-proxy.require-auth` | `NOSTR_AUTH_PROXY_REQUIRE_AUTH` | `true` | Require authentication |
| `nostr.auth-proxy.auth-timeout` | `NOSTR_AUTH_PROXY_AUTH_TIMEOUT` | `30s` | Auth completion timeout |
| `nostr.auth-proxy.challenge-expiration` | `NOSTR_AUTH_PROXY_CHALLENGE_EXPIRATION` | `5m` | Challenge validity period |
| `nostr.auth-proxy.access-mode` | `NOSTR_AUTH_PROXY_ACCESS_MODE` | `OPEN` | `OPEN`, `ALLOWLIST`, or `BLOCKLIST` |
| `nostr.auth-proxy.allowed-pubkeys` | `NOSTR_AUTH_PROXY_ALLOWED_PUBKEYS` | - | Comma-separated pubkeys for allowlist |
| `nostr.auth-proxy.blocked-pubkeys` | `NOSTR_AUTH_PROXY_BLOCKED_PUBKEYS` | - | Comma-separated pubkeys for blocklist |
| `nostr.auth-proxy.max-connections-per-pubkey` | `NOSTR_AUTH_PROXY_MAX_CONNECTIONS` | `10` | Max connections per pubkey (0=unlimited) |

## Running

### With Docker

```bash
docker build -t nostr-auth-proxy .
docker run -p 7777:7777 \
  -e NOSTR_AUTH_PROXY_UPSTREAM=ws://strfry:7778 \
  -e NOSTR_AUTH_PROXY_PUBLIC_URL=wss://relay.example.com \
  nostr-auth-proxy
```

### With Docker Compose

```yaml
services:
  nostr-auth-proxy:
    image: nostr-auth-proxy:latest
    ports:
      - "7777:7777"
    environment:
      NOSTR_AUTH_PROXY_UPSTREAM: "ws://nostr-relay:7778"
      NOSTR_AUTH_PROXY_PUBLIC_URL: "wss://relay.example.com"
    depends_on:
      - nostr-relay

  nostr-relay:
    image: dockurr/strfry:latest
    expose:
      - "7778"
```

### Locally

```bash
mvn spring-boot:run
```

## NIP-42 Protocol Flow

1. Client connects to proxy
2. Proxy sends: `["AUTH", "<challenge>"]`
3. Client signs challenge and sends: `["AUTH", <signed-event>]`
4. Proxy verifies signature and kind (22242)
5. On success: `["OK", "<event-id>", true, "authenticated as <pubkey>..."]`
6. On failure: `["OK", "<event-id>", false, "<error>"]` and connection closes

## Message Authentication Requirements

The proxy enforces authentication based on message type and the `require-auth` setting:

| Message Type | `require-auth=true` | `require-auth=false` |
|--------------|---------------------|----------------------|
| **AUTH**     | Allowed (for authentication) | Allowed |
| **CLOSE**    | Allowed | Allowed |
| **REQ**      | Requires auth | Allowed, unless querying protected kinds |
| **EVENT**    | Requires auth | Requires auth |
| **Other**    | Requires auth | Requires auth |

### Protected Kinds

When `require-auth=false`, REQ messages are still rejected if they query privacy-sensitive event kinds:

- **NIP-04**: kind `4` (Legacy encrypted DMs)
- **NIP-17**: kinds `14`, `15` (Private direct messages)
- **NIP-29**: kind `39002` (Group members)
- **NIP-37**: kinds `10013`, `31234` (Draft events)
- **NIP-46**: kind `24133` (Nostr Remote Signing/Bunker)
- **NIP-47**: kinds `23194`, `23195`, `23196`, `23197` (Wallet Connect)
- **NIP-51**: kinds `10000`, `10050` (Mute list, DM relay preferences)
- **NIP-59**: kinds `13`, `1059` (Gift Wraps/Seals)
- **NIP-60**: kinds `7374`, `7375`, `7376`, `17375` (Cashu Wallet)
- **NIP-61**: kinds `9321`, `10019` (Nutzaps)

## Access Control

### OPEN Mode (default)
Any authenticated pubkey is allowed.

### ALLOWLIST Mode
Only pubkeys in the allowlist can connect:
```yaml
nostr:
  auth-proxy:
    access-mode: ALLOWLIST
    allowed-pubkeys: pubkey1,pubkey2,pubkey3
```

### BLOCKLIST Mode
All pubkeys except those in blocklist can connect:
```yaml
nostr:
  auth-proxy:
    access-mode: BLOCKLIST
    blocked-pubkeys: spammer1,spammer2
```

## Metrics

Prometheus metrics available at `/actuator/prometheus`:

- `nostr_auth_proxy_connections_total` - Total connection attempts
- `nostr_auth_proxy_auth_success_total` - Successful authentications
- `nostr_auth_proxy_auth_failure_total` - Failed authentications
- `nostr_auth_proxy_active_sessions` - Current active sessions
- `nostr_auth_proxy_messages_proxied_total` - Messages proxied to upstream

## Health Check

Health endpoint: `/actuator/health`

## Building

```bash
mvn clean package
```

## Testing

```bash
mvn test
```

## References

- [NIP-42: Authentication of clients to relays](https://github.com/nostr-protocol/nips/blob/master/42.md)
- [BIP-340: Schnorr Signatures](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)
- [strfry](https://github.com/hoytech/strfry)
