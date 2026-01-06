package xyz.tcheeric.nostr.authproxy.auth;

import org.springframework.stereotype.Component;
import xyz.tcheeric.nostr.authproxy.config.AuthProxyProperties;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.HexFormat;

/**
 * Generates cryptographically secure NIP-42 challenges.
 */
@Component
public class Nip42ChallengeGenerator {

    private static final int CHALLENGE_LENGTH = 32;
    private final SecureRandom secureRandom = new SecureRandom();
    private final AuthProxyProperties properties;

    public Nip42ChallengeGenerator(AuthProxyProperties properties) {
        this.properties = properties;
    }

    /**
     * Generates a cryptographically secure random challenge.
     *
     * @return a new NIP-42 challenge with expiration time
     */
    public Nip42Challenge generate() {
        byte[] bytes = new byte[CHALLENGE_LENGTH];
        secureRandom.nextBytes(bytes);
        String challenge = HexFormat.of().formatHex(bytes);
        Instant expiresAt = Instant.now().plus(properties.getChallengeExpiration());
        return new Nip42Challenge(challenge, expiresAt);
    }
}
