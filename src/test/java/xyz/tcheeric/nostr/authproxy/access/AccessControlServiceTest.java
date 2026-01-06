package xyz.tcheeric.nostr.authproxy.access;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import xyz.tcheeric.nostr.authproxy.config.AuthProxyProperties;
import xyz.tcheeric.nostr.authproxy.config.AuthProxyProperties.AccessMode;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for AccessControlService.
 */
class AccessControlServiceTest {

    private static final String PUBKEY_1 = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
    private static final String PUBKEY_2 = "f1e2d3c4b5a6f1e2d3c4b5a6f1e2d3c4b5a6f1e2d3c4b5a6f1e2d3c4b5a6f1e2";
    private static final String PUBKEY_3 = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

    private AuthProxyProperties properties;
    private AccessControlService accessControl;

    @BeforeEach
    void setUp() {
        properties = new AuthProxyProperties();
    }

    /**
     * Tests that OPEN mode allows any pubkey.
     */
    @Test
    void shouldAllowAnyPubkeyInOpenMode() {
        // Given
        properties.setAccessMode(AccessMode.OPEN);
        accessControl = new AccessControlService(properties);

        // Then
        assertThat(accessControl.isAllowed(PUBKEY_1)).isTrue();
        assertThat(accessControl.isAllowed(PUBKEY_2)).isTrue();
        assertThat(accessControl.isAllowed(PUBKEY_3)).isTrue();
    }

    /**
     * Tests that ALLOWLIST mode only allows listed pubkeys.
     */
    @Test
    void shouldOnlyAllowListedPubkeysInAllowlistMode() {
        // Given
        properties.setAccessMode(AccessMode.ALLOWLIST);
        properties.setAllowedPubkeys(Set.of(PUBKEY_1, PUBKEY_2));
        accessControl = new AccessControlService(properties);

        // Then
        assertThat(accessControl.isAllowed(PUBKEY_1)).isTrue();
        assertThat(accessControl.isAllowed(PUBKEY_2)).isTrue();
        assertThat(accessControl.isAllowed(PUBKEY_3)).isFalse();
    }

    /**
     * Tests that BLOCKLIST mode blocks listed pubkeys.
     */
    @Test
    void shouldBlockListedPubkeysInBlocklistMode() {
        // Given
        properties.setAccessMode(AccessMode.BLOCKLIST);
        properties.setBlockedPubkeys(Set.of(PUBKEY_1));
        accessControl = new AccessControlService(properties);

        // Then
        assertThat(accessControl.isAllowed(PUBKEY_1)).isFalse();
        assertThat(accessControl.isAllowed(PUBKEY_2)).isTrue();
        assertThat(accessControl.isAllowed(PUBKEY_3)).isTrue();
    }

    /**
     * Tests that pubkey matching is case-insensitive.
     */
    @Test
    void shouldMatchPubkeysCaseInsensitively() {
        // Given
        properties.setAccessMode(AccessMode.ALLOWLIST);
        properties.setAllowedPubkeys(Set.of(PUBKEY_1.toUpperCase()));
        accessControl = new AccessControlService(properties);

        // Then
        assertThat(accessControl.isAllowed(PUBKEY_1.toLowerCase())).isTrue();
    }

    /**
     * Tests that null pubkeys are rejected.
     */
    @Test
    void shouldRejectNullPubkey() {
        // Given
        properties.setAccessMode(AccessMode.OPEN);
        accessControl = new AccessControlService(properties);

        // Then
        assertThat(accessControl.isAllowed(null)).isFalse();
    }

    /**
     * Tests that empty pubkeys are rejected.
     */
    @Test
    void shouldRejectEmptyPubkey() {
        // Given
        properties.setAccessMode(AccessMode.OPEN);
        accessControl = new AccessControlService(properties);

        // Then
        assertThat(accessControl.isAllowed("")).isFalse();
        assertThat(accessControl.isAllowed("  ")).isFalse();
    }

    /**
     * Tests that ALLOWLIST with empty list rejects all pubkeys.
     */
    @Test
    void shouldRejectAllWhenAllowlistIsEmpty() {
        // Given
        properties.setAccessMode(AccessMode.ALLOWLIST);
        properties.setAllowedPubkeys(Set.of());
        accessControl = new AccessControlService(properties);

        // Then
        assertThat(accessControl.isAllowed(PUBKEY_1)).isFalse();
        assertThat(accessControl.isAllowed(PUBKEY_2)).isFalse();
    }

    /**
     * Tests that BLOCKLIST with empty list allows all pubkeys.
     */
    @Test
    void shouldAllowAllWhenBlocklistIsEmpty() {
        // Given
        properties.setAccessMode(AccessMode.BLOCKLIST);
        properties.setBlockedPubkeys(Set.of());
        accessControl = new AccessControlService(properties);

        // Then
        assertThat(accessControl.isAllowed(PUBKEY_1)).isTrue();
        assertThat(accessControl.isAllowed(PUBKEY_2)).isTrue();
    }

    /**
     * Tests that getAccessMode returns the configured mode.
     */
    @Test
    void shouldReturnConfiguredAccessMode() {
        // Given
        properties.setAccessMode(AccessMode.BLOCKLIST);
        accessControl = new AccessControlService(properties);

        // Then
        assertThat(accessControl.getAccessMode()).isEqualTo(AccessMode.BLOCKLIST);
    }
}
