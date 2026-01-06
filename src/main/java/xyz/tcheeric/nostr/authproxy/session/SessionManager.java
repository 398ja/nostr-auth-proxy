package xyz.tcheeric.nostr.authproxy.session;

import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import xyz.tcheeric.nostr.authproxy.config.AuthProxyProperties;

import java.util.Collections;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Manages proxy sessions and tracks connection counts per pubkey.
 */
@Component
public class SessionManager {

    private static final Logger log = LoggerFactory.getLogger(SessionManager.class);

    private final ConcurrentMap<String, ProxySession> sessions = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, Set<String>> sessionsByPubkey = new ConcurrentHashMap<>();
    private final AuthProxyProperties properties;

    public SessionManager(AuthProxyProperties properties, MeterRegistry meterRegistry) {
        this.properties = properties;

        Gauge.builder("nostr_auth_proxy_active_sessions", sessions, ConcurrentMap::size)
                .description("Number of active proxy sessions")
                .register(meterRegistry);
    }

    /**
     * Registers a new session.
     *
     * @param session the session to register
     */
    public void register(ProxySession session) {
        sessions.put(session.getSessionId(), session);
        log.debug("session_registered session_id={}", session.getSessionId());
    }

    /**
     * Gets a session by ID.
     *
     * @param sessionId the session ID
     * @return the session, or null if not found
     */
    public ProxySession get(String sessionId) {
        return sessions.get(sessionId);
    }

    /**
     * Marks a session as authenticated and tracks it by pubkey.
     *
     * @param sessionId the session ID
     * @param pubkey    the authenticated pubkey
     */
    public void authenticate(String sessionId, String pubkey) {
        ProxySession session = sessions.get(sessionId);
        if (session != null) {
            sessionsByPubkey.computeIfAbsent(pubkey, k -> ConcurrentHashMap.newKeySet())
                    .add(sessionId);
            log.info("session_authenticated session_id={} pubkey={}", sessionId, pubkey);
        }
    }

    /**
     * Unregisters a session.
     *
     * @param sessionId the session ID to unregister
     */
    public void unregister(String sessionId) {
        ProxySession session = sessions.remove(sessionId);
        if (session != null && session.getAuthenticatedPubkey() != null) {
            String pubkey = session.getAuthenticatedPubkey();
            Set<String> pubkeySessions = sessionsByPubkey.get(pubkey);
            if (pubkeySessions != null) {
                pubkeySessions.remove(sessionId);
                if (pubkeySessions.isEmpty()) {
                    sessionsByPubkey.remove(pubkey);
                }
            }
            log.debug("session_unregistered session_id={} pubkey={}", sessionId, pubkey);
        } else {
            log.debug("session_unregistered session_id={}", sessionId);
        }
    }

    /**
     * Gets the number of active connections for a pubkey.
     *
     * @param pubkey the pubkey
     * @return the number of active connections
     */
    public int getConnectionCount(String pubkey) {
        Set<String> pubkeySessions = sessionsByPubkey.get(pubkey);
        return pubkeySessions != null ? pubkeySessions.size() : 0;
    }

    /**
     * Checks if a new connection can be accepted for a pubkey.
     *
     * @param pubkey the pubkey
     * @return true if the connection can be accepted
     */
    public boolean canAcceptConnection(String pubkey) {
        int maxConnections = properties.getMaxConnectionsPerPubkey();
        if (maxConnections <= 0) {
            return true;
        }
        return getConnectionCount(pubkey) < maxConnections;
    }

    /**
     * Gets all session IDs for a pubkey.
     *
     * @param pubkey the pubkey
     * @return unmodifiable set of session IDs
     */
    public Set<String> getSessionsForPubkey(String pubkey) {
        Set<String> pubkeySessions = sessionsByPubkey.get(pubkey);
        return pubkeySessions != null ? Collections.unmodifiableSet(pubkeySessions) : Set.of();
    }

    /**
     * Gets the total number of active sessions.
     *
     * @return the number of active sessions
     */
    public int getActiveSessionCount() {
        return sessions.size();
    }
}
