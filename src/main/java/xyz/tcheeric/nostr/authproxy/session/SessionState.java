package xyz.tcheeric.nostr.authproxy.session;

/**
 * Represents the state of a proxy session.
 */
public enum SessionState {

    /**
     * Connection established, waiting for AUTH.
     */
    AWAITING_AUTH,

    /**
     * AUTH received, verifying signature.
     */
    AUTHENTICATING,

    /**
     * Authenticated, proxying to upstream.
     */
    AUTHENTICATED,

    /**
     * Authentication failed, connection will close.
     */
    AUTH_FAILED,

    /**
     * Connection closed.
     */
    CLOSED
}
