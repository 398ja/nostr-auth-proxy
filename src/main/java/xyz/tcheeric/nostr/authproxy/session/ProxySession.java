package xyz.tcheeric.nostr.authproxy.session;

import org.springframework.web.socket.WebSocketSession;
import xyz.tcheeric.nostr.authproxy.auth.Nip42Challenge;

import java.time.Instant;

/**
 * Represents a client session with the auth proxy.
 */
public class ProxySession {

    private final String sessionId;
    private final WebSocketSession clientSession;
    private final Nip42Challenge challenge;
    private final Instant connectedAt;

    private volatile SessionState state = SessionState.AWAITING_AUTH;
    private volatile String authenticatedPubkey;
    private volatile WebSocketSession upstreamSession;
    private volatile Instant authenticatedAt;

    /**
     * Creates a new proxy session.
     *
     * @param sessionId     unique session identifier
     * @param clientSession the client WebSocket session
     * @param challenge     the NIP-42 challenge for this session
     */
    public ProxySession(String sessionId, WebSocketSession clientSession, Nip42Challenge challenge) {
        this.sessionId = sessionId;
        this.clientSession = clientSession;
        this.challenge = challenge;
        this.connectedAt = Instant.now();
    }

    public String getSessionId() {
        return sessionId;
    }

    public WebSocketSession getClientSession() {
        return clientSession;
    }

    public Nip42Challenge getChallenge() {
        return challenge;
    }

    public Instant getConnectedAt() {
        return connectedAt;
    }

    public SessionState getState() {
        return state;
    }

    public void setState(SessionState state) {
        this.state = state;
    }

    public String getAuthenticatedPubkey() {
        return authenticatedPubkey;
    }

    public void setAuthenticatedPubkey(String authenticatedPubkey) {
        this.authenticatedPubkey = authenticatedPubkey;
        this.authenticatedAt = Instant.now();
    }

    public WebSocketSession getUpstreamSession() {
        return upstreamSession;
    }

    public void setUpstreamSession(WebSocketSession upstreamSession) {
        this.upstreamSession = upstreamSession;
    }

    public Instant getAuthenticatedAt() {
        return authenticatedAt;
    }

    /**
     * Checks if this session is authenticated.
     *
     * @return true if the session is authenticated
     */
    public boolean isAuthenticated() {
        return state == SessionState.AUTHENTICATED && authenticatedPubkey != null;
    }

    /**
     * Checks if the challenge has expired.
     *
     * @return true if the challenge has expired
     */
    public boolean isChallengeExpired() {
        return challenge.isExpired();
    }
}
