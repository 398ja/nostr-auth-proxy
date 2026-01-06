package xyz.tcheeric.nostr.authproxy.auth;

import java.time.Instant;

/**
 * Represents a NIP-42 authentication challenge.
 *
 * @param value     the random challenge string (64-character hex)
 * @param expiresAt the timestamp when this challenge expires
 */
public record Nip42Challenge(String value, Instant expiresAt) {

    /**
     * Checks if this challenge has expired.
     *
     * @return true if the challenge has expired
     */
    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }
}
