package xyz.tcheeric.nostr.authproxy.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.HashSet;
import java.util.Set;

/**
 * Configuration properties for the NIP-42 Auth Proxy.
 */
@ConfigurationProperties(prefix = "nostr.auth-proxy")
public class AuthProxyProperties {

    /**
     * Upstream strfry relay URL.
     */
    private String upstreamRelay = "ws://localhost:7778";

    /**
     * Relay URL to include in NIP-11 info and AUTH verification.
     * This should be the public-facing URL clients use.
     */
    private String publicRelayUrl;

    /**
     * Whether to require authentication for all connections.
     * If false, unauthenticated connections are proxied directly.
     */
    private boolean requireAuth = true;

    /**
     * Timeout for clients to complete AUTH after connecting.
     */
    private Duration authTimeout = Duration.ofSeconds(30);

    /**
     * Challenge expiration time.
     */
    private Duration challengeExpiration = Duration.ofMinutes(5);

    /**
     * Access control mode: ALLOWLIST, BLOCKLIST, or OPEN.
     */
    private AccessMode accessMode = AccessMode.OPEN;

    /**
     * List of allowed pubkeys (hex format) when accessMode is ALLOWLIST.
     */
    private Set<String> allowedPubkeys = new HashSet<>();

    /**
     * List of blocked pubkeys (hex format) when accessMode is BLOCKLIST.
     */
    private Set<String> blockedPubkeys = new HashSet<>();

    /**
     * Maximum concurrent connections per pubkey. 0 = unlimited.
     */
    private int maxConnectionsPerPubkey = 10;

    /**
     * Connection idle timeout.
     */
    private Duration idleTimeout = Duration.ofMinutes(30);

    /**
     * Access control mode enumeration.
     */
    public enum AccessMode {
        /**
         * Only pubkeys in allowedPubkeys can connect.
         */
        ALLOWLIST,

        /**
         * All pubkeys except those in blockedPubkeys can connect.
         */
        BLOCKLIST,

        /**
         * Any authenticated pubkey can connect.
         */
        OPEN
    }

    public String getUpstreamRelay() {
        return upstreamRelay;
    }

    public void setUpstreamRelay(String upstreamRelay) {
        this.upstreamRelay = upstreamRelay;
    }

    public String getPublicRelayUrl() {
        return publicRelayUrl;
    }

    public void setPublicRelayUrl(String publicRelayUrl) {
        this.publicRelayUrl = publicRelayUrl;
    }

    public boolean isRequireAuth() {
        return requireAuth;
    }

    public void setRequireAuth(boolean requireAuth) {
        this.requireAuth = requireAuth;
    }

    public Duration getAuthTimeout() {
        return authTimeout;
    }

    public void setAuthTimeout(Duration authTimeout) {
        this.authTimeout = authTimeout;
    }

    public Duration getChallengeExpiration() {
        return challengeExpiration;
    }

    public void setChallengeExpiration(Duration challengeExpiration) {
        this.challengeExpiration = challengeExpiration;
    }

    public AccessMode getAccessMode() {
        return accessMode;
    }

    public void setAccessMode(AccessMode accessMode) {
        this.accessMode = accessMode;
    }

    public Set<String> getAllowedPubkeys() {
        return allowedPubkeys;
    }

    public void setAllowedPubkeys(Set<String> allowedPubkeys) {
        this.allowedPubkeys = allowedPubkeys;
    }

    public Set<String> getBlockedPubkeys() {
        return blockedPubkeys;
    }

    public void setBlockedPubkeys(Set<String> blockedPubkeys) {
        this.blockedPubkeys = blockedPubkeys;
    }

    public int getMaxConnectionsPerPubkey() {
        return maxConnectionsPerPubkey;
    }

    public void setMaxConnectionsPerPubkey(int maxConnectionsPerPubkey) {
        this.maxConnectionsPerPubkey = maxConnectionsPerPubkey;
    }

    public Duration getIdleTimeout() {
        return idleTimeout;
    }

    public void setIdleTimeout(Duration idleTimeout) {
        this.idleTimeout = idleTimeout;
    }
}
