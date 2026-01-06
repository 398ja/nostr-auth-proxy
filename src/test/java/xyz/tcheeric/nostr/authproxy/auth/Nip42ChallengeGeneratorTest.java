package xyz.tcheeric.nostr.authproxy.auth;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import xyz.tcheeric.nostr.authproxy.config.AuthProxyProperties;

import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for Nip42ChallengeGenerator.
 */
class Nip42ChallengeGeneratorTest {

    private Nip42ChallengeGenerator generator;
    private AuthProxyProperties properties;

    @BeforeEach
    void setUp() {
        properties = new AuthProxyProperties();
        properties.setChallengeExpiration(Duration.ofMinutes(5));
        generator = new Nip42ChallengeGenerator(properties);
    }

    /**
     * Tests that generated challenges are 64 characters (32 bytes as hex).
     */
    @Test
    void shouldGenerateChallengeWith64HexCharacters() {
        // When
        Nip42Challenge challenge = generator.generate();

        // Then
        assertThat(challenge.value()).hasSize(64);
        assertThat(challenge.value()).matches("[0-9a-f]+");
    }

    /**
     * Tests that each generated challenge is unique.
     */
    @Test
    void shouldGenerateUniqueChallenges() {
        // Given
        int count = 100;
        Set<String> challenges = new HashSet<>();

        // When
        for (int i = 0; i < count; i++) {
            challenges.add(generator.generate().value());
        }

        // Then
        assertThat(challenges).hasSize(count);
    }

    /**
     * Tests that challenge expiration is set correctly based on properties.
     */
    @Test
    void shouldSetExpirationBasedOnProperties() {
        // Given
        Instant before = Instant.now().plus(properties.getChallengeExpiration()).minusSeconds(1);

        // When
        Nip42Challenge challenge = generator.generate();

        // Then
        Instant after = Instant.now().plus(properties.getChallengeExpiration()).plusSeconds(1);
        assertThat(challenge.expiresAt()).isAfter(before);
        assertThat(challenge.expiresAt()).isBefore(after);
    }

    /**
     * Tests that a newly generated challenge is not expired.
     */
    @Test
    void shouldNotBeExpiredWhenJustGenerated() {
        // When
        Nip42Challenge challenge = generator.generate();

        // Then
        assertThat(challenge.isExpired()).isFalse();
    }

    /**
     * Tests that isExpired returns true when the expiration time has passed.
     */
    @Test
    void shouldBeExpiredWhenExpirationTimePassed() {
        // Given
        Nip42Challenge expiredChallenge = new Nip42Challenge(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                Instant.now().minusSeconds(1)
        );

        // Then
        assertThat(expiredChallenge.isExpired()).isTrue();
    }
}
