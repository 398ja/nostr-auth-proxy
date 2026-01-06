package xyz.tcheeric.nostr.authproxy.auth;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import xyz.tcheeric.nostr.authproxy.config.AuthProxyProperties;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for Nip42AuthVerifier.
 */
class Nip42AuthVerifierTest {

    private Nip42AuthVerifier verifier;
    private AuthProxyProperties properties;

    private static final String TEST_CHALLENGE = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private static final String TEST_PUBKEY = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
    private static final String TEST_RELAY_URL = "wss://relay.example.com";

    @BeforeEach
    void setUp() {
        properties = new AuthProxyProperties();
        properties.setPublicRelayUrl(TEST_RELAY_URL);
        verifier = new Nip42AuthVerifier(properties);
    }

    /**
     * Tests that events with wrong kind are rejected.
     */
    @Test
    void shouldRejectWrongKind() {
        // Given
        String eventJson = createEventJson(1, TEST_CHALLENGE, TEST_RELAY_URL);
        Nip42Challenge challenge = new Nip42Challenge(TEST_CHALLENGE, Instant.now().plusSeconds(300));

        // When
        AuthResult result = verifier.verify(eventJson, challenge);

        // Then
        assertThat(result.authenticated()).isFalse();
        assertThat(result.errorCode()).isEqualTo("invalid-kind");
    }

    /**
     * Tests that expired challenges are rejected.
     */
    @Test
    void shouldRejectExpiredChallenge() {
        // Given
        String eventJson = createEventJson(22242, TEST_CHALLENGE, TEST_RELAY_URL);
        Nip42Challenge expiredChallenge = new Nip42Challenge(TEST_CHALLENGE, Instant.now().minusSeconds(1));

        // When
        AuthResult result = verifier.verify(eventJson, expiredChallenge);

        // Then
        assertThat(result.authenticated()).isFalse();
        assertThat(result.errorCode()).isEqualTo("challenge-expired");
    }

    /**
     * Tests that mismatched challenges are rejected.
     */
    @Test
    void shouldRejectMismatchedChallenge() {
        // Given
        String differentChallenge = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
        String eventJson = createEventJson(22242, differentChallenge, TEST_RELAY_URL);
        Nip42Challenge challenge = new Nip42Challenge(TEST_CHALLENGE, Instant.now().plusSeconds(300));

        // When
        AuthResult result = verifier.verify(eventJson, challenge);

        // Then
        assertThat(result.authenticated()).isFalse();
        assertThat(result.errorCode()).isEqualTo("challenge-mismatch");
    }

    /**
     * Tests that mismatched relay URLs are rejected when public URL is configured.
     */
    @Test
    void shouldRejectMismatchedRelayUrl() {
        // Given
        String eventJson = createEventJson(22242, TEST_CHALLENGE, "wss://different.relay.com");
        Nip42Challenge challenge = new Nip42Challenge(TEST_CHALLENGE, Instant.now().plusSeconds(300));

        // When
        AuthResult result = verifier.verify(eventJson, challenge);

        // Then
        assertThat(result.authenticated()).isFalse();
        assertThat(result.errorCode()).isEqualTo("relay-mismatch");
    }

    /**
     * Tests that events with timestamps too old are rejected.
     */
    @Test
    void shouldRejectEventTooOld() {
        // Given
        long oldTimestamp = Instant.now().minusSeconds(15 * 60).getEpochSecond(); // 15 minutes ago
        String eventJson = createEventJsonWithTimestamp(22242, TEST_CHALLENGE, TEST_RELAY_URL, oldTimestamp);
        Nip42Challenge challenge = new Nip42Challenge(TEST_CHALLENGE, Instant.now().plusSeconds(300));

        // When
        AuthResult result = verifier.verify(eventJson, challenge);

        // Then
        assertThat(result.authenticated()).isFalse();
        assertThat(result.errorCode()).isEqualTo("event-too-old");
    }

    /**
     * Tests that events with timestamps in the future are rejected.
     */
    @Test
    void shouldRejectEventInFuture() {
        // Given
        long futureTimestamp = Instant.now().plusSeconds(15 * 60).getEpochSecond(); // 15 minutes in future
        String eventJson = createEventJsonWithTimestamp(22242, TEST_CHALLENGE, TEST_RELAY_URL, futureTimestamp);
        Nip42Challenge challenge = new Nip42Challenge(TEST_CHALLENGE, Instant.now().plusSeconds(300));

        // When
        AuthResult result = verifier.verify(eventJson, challenge);

        // Then
        assertThat(result.authenticated()).isFalse();
        assertThat(result.errorCode()).isEqualTo("event-in-future");
    }

    /**
     * Tests that invalid JSON is handled gracefully.
     */
    @Test
    void shouldHandleInvalidJson() {
        // Given
        String invalidJson = "not valid json";
        Nip42Challenge challenge = new Nip42Challenge(TEST_CHALLENGE, Instant.now().plusSeconds(300));

        // When
        AuthResult result = verifier.verify(invalidJson, challenge);

        // Then
        assertThat(result.authenticated()).isFalse();
        assertThat(result.errorCode()).isEqualTo("parse-error");
    }

    /**
     * Tests that relay URL matching ignores trailing slashes.
     */
    @Test
    void shouldNormalizeRelayUrlTrailingSlash() {
        // Given
        properties.setPublicRelayUrl("wss://relay.example.com/");
        verifier = new Nip42AuthVerifier(properties);

        String eventJson = createEventJson(22242, TEST_CHALLENGE, "wss://relay.example.com");
        Nip42Challenge challenge = new Nip42Challenge(TEST_CHALLENGE, Instant.now().plusSeconds(300));

        // When
        AuthResult result = verifier.verify(eventJson, challenge);

        // Then - should not fail on relay mismatch (will fail on signature instead)
        assertThat(result.errorCode()).isNotEqualTo("relay-mismatch");
    }

    /**
     * Tests that relay URL matching is case-insensitive.
     */
    @Test
    void shouldNormalizeRelayUrlCase() {
        // Given
        properties.setPublicRelayUrl("wss://RELAY.EXAMPLE.COM");
        verifier = new Nip42AuthVerifier(properties);

        String eventJson = createEventJson(22242, TEST_CHALLENGE, "wss://relay.example.com");
        Nip42Challenge challenge = new Nip42Challenge(TEST_CHALLENGE, Instant.now().plusSeconds(300));

        // When
        AuthResult result = verifier.verify(eventJson, challenge);

        // Then - should not fail on relay mismatch
        assertThat(result.errorCode()).isNotEqualTo("relay-mismatch");
    }

    /**
     * Tests that relay URL validation is skipped when not configured.
     */
    @Test
    void shouldSkipRelayValidationWhenNotConfigured() {
        // Given
        properties.setPublicRelayUrl(null);
        verifier = new Nip42AuthVerifier(properties);

        String eventJson = createEventJson(22242, TEST_CHALLENGE, "wss://any.relay.com");
        Nip42Challenge challenge = new Nip42Challenge(TEST_CHALLENGE, Instant.now().plusSeconds(300));

        // When
        AuthResult result = verifier.verify(eventJson, challenge);

        // Then - should not fail on relay mismatch (will fail on signature instead)
        assertThat(result.errorCode()).isNotEqualTo("relay-mismatch");
    }

    private String createEventJson(int kind, String challenge, String relayUrl) {
        return createEventJsonWithTimestamp(kind, challenge, relayUrl, Instant.now().getEpochSecond());
    }

    private String createEventJsonWithTimestamp(int kind, String challenge, String relayUrl, long createdAt) {
        return String.format("""
                {
                    "id": "abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
                    "pubkey": "%s",
                    "kind": %d,
                    "created_at": %d,
                    "tags": [
                        ["challenge", "%s"],
                        ["relay", "%s"]
                    ],
                    "content": "",
                    "sig": "invalid_signature_for_testing"
                }
                """, TEST_PUBKEY, kind, createdAt, challenge, relayUrl);
    }
}
