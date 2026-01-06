package xyz.tcheeric.nostr.authproxy.auth;

/**
 * Result of NIP-42 authentication verification.
 *
 * @param authenticated true if authentication succeeded
 * @param pubkey        the authenticated pubkey (hex format) if successful
 * @param eventId       the AUTH event ID if successfully parsed
 * @param errorCode     error code if authentication failed
 * @param errorMessage  human-readable error message if authentication failed
 */
public record AuthResult(
        boolean authenticated,
        String pubkey,
        String eventId,
        String errorCode,
        String errorMessage
) {

    /**
     * Creates a successful authentication result.
     *
     * @param pubkey  the authenticated pubkey (hex format)
     * @param eventId the AUTH event ID
     * @return successful AuthResult
     */
    public static AuthResult success(String pubkey, String eventId) {
        return new AuthResult(true, pubkey, eventId, null, null);
    }

    /**
     * Creates a failed authentication result.
     *
     * @param code    error code for programmatic handling
     * @param message human-readable error message
     * @return failed AuthResult
     */
    public static AuthResult failure(String code, String message) {
        return new AuthResult(false, null, null, code, message);
    }

    /**
     * Creates a failed authentication result with event ID.
     *
     * @param code    error code for programmatic handling
     * @param message human-readable error message
     * @param eventId the AUTH event ID if it was successfully parsed
     * @return failed AuthResult
     */
    public static AuthResult failure(String code, String message, String eventId) {
        return new AuthResult(false, null, eventId, code, message);
    }
}
