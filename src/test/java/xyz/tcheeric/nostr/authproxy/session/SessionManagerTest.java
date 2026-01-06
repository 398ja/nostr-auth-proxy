package xyz.tcheeric.nostr.authproxy.session;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.web.socket.WebSocketSession;
import xyz.tcheeric.nostr.authproxy.auth.Nip42Challenge;
import xyz.tcheeric.nostr.authproxy.config.AuthProxyProperties;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 * Unit tests for SessionManager.
 */
@ExtendWith(MockitoExtension.class)
@org.mockito.junit.jupiter.MockitoSettings(strictness = org.mockito.quality.Strictness.LENIENT)
class SessionManagerTest {

    @Mock
    private WebSocketSession clientSession;

    private AuthProxyProperties properties;
    private SessionManager sessionManager;
    private SimpleMeterRegistry meterRegistry;

    private static final String SESSION_ID_1 = "session-1";
    private static final String SESSION_ID_2 = "session-2";
    private static final String PUBKEY_1 = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
    private static final String PUBKEY_2 = "f1e2d3c4b5a6f1e2d3c4b5a6f1e2d3c4b5a6f1e2d3c4b5a6f1e2d3c4b5a6f1e2";
    private static final String TEST_CHALLENGE = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    @BeforeEach
    void setUp() {
        properties = new AuthProxyProperties();
        properties.setMaxConnectionsPerPubkey(2);
        meterRegistry = new SimpleMeterRegistry();
        sessionManager = new SessionManager(properties, meterRegistry);
    }

    /**
     * Tests that sessions can be registered and retrieved.
     */
    @Test
    void shouldRegisterAndRetrieveSession() {
        // Given
        when(clientSession.getId()).thenReturn(SESSION_ID_1);
        Nip42Challenge challenge = new Nip42Challenge(TEST_CHALLENGE, Instant.now().plusSeconds(300));
        ProxySession session = new ProxySession(SESSION_ID_1, clientSession, challenge);

        // When
        sessionManager.register(session);

        // Then
        assertThat(sessionManager.get(SESSION_ID_1)).isSameAs(session);
    }

    /**
     * Tests that sessions can be unregistered.
     */
    @Test
    void shouldUnregisterSession() {
        // Given
        when(clientSession.getId()).thenReturn(SESSION_ID_1);
        Nip42Challenge challenge = new Nip42Challenge(TEST_CHALLENGE, Instant.now().plusSeconds(300));
        ProxySession session = new ProxySession(SESSION_ID_1, clientSession, challenge);
        sessionManager.register(session);

        // When
        sessionManager.unregister(SESSION_ID_1);

        // Then
        assertThat(sessionManager.get(SESSION_ID_1)).isNull();
    }

    /**
     * Tests that authenticated sessions are tracked by pubkey.
     */
    @Test
    void shouldTrackSessionsByPubkey() {
        // Given
        when(clientSession.getId()).thenReturn(SESSION_ID_1);
        Nip42Challenge challenge = new Nip42Challenge(TEST_CHALLENGE, Instant.now().plusSeconds(300));
        ProxySession session = new ProxySession(SESSION_ID_1, clientSession, challenge);
        session.setAuthenticatedPubkey(PUBKEY_1);
        sessionManager.register(session);

        // When
        sessionManager.authenticate(SESSION_ID_1, PUBKEY_1);

        // Then
        assertThat(sessionManager.getConnectionCount(PUBKEY_1)).isEqualTo(1);
        assertThat(sessionManager.getSessionsForPubkey(PUBKEY_1)).contains(SESSION_ID_1);
    }

    /**
     * Tests that connection count increases with multiple sessions per pubkey.
     */
    @Test
    void shouldCountMultipleConnectionsPerPubkey() {
        // Given
        Nip42Challenge challenge = new Nip42Challenge(TEST_CHALLENGE, Instant.now().plusSeconds(300));

        ProxySession session1 = new ProxySession(SESSION_ID_1, clientSession, challenge);
        session1.setAuthenticatedPubkey(PUBKEY_1);
        sessionManager.register(session1);
        sessionManager.authenticate(SESSION_ID_1, PUBKEY_1);

        ProxySession session2 = new ProxySession(SESSION_ID_2, clientSession, challenge);
        session2.setAuthenticatedPubkey(PUBKEY_1);
        sessionManager.register(session2);
        sessionManager.authenticate(SESSION_ID_2, PUBKEY_1);

        // Then
        assertThat(sessionManager.getConnectionCount(PUBKEY_1)).isEqualTo(2);
    }

    /**
     * Tests that unregistering decrements connection count.
     */
    @Test
    void shouldDecrementConnectionCountOnUnregister() {
        // Given
        Nip42Challenge challenge = new Nip42Challenge(TEST_CHALLENGE, Instant.now().plusSeconds(300));

        ProxySession session1 = new ProxySession(SESSION_ID_1, clientSession, challenge);
        session1.setAuthenticatedPubkey(PUBKEY_1);
        sessionManager.register(session1);
        sessionManager.authenticate(SESSION_ID_1, PUBKEY_1);

        ProxySession session2 = new ProxySession(SESSION_ID_2, clientSession, challenge);
        session2.setAuthenticatedPubkey(PUBKEY_1);
        sessionManager.register(session2);
        sessionManager.authenticate(SESSION_ID_2, PUBKEY_1);

        // When
        sessionManager.unregister(SESSION_ID_1);

        // Then
        assertThat(sessionManager.getConnectionCount(PUBKEY_1)).isEqualTo(1);
    }

    /**
     * Tests that canAcceptConnection respects max connections limit.
     */
    @Test
    void shouldRespectMaxConnectionsLimit() {
        // Given
        Nip42Challenge challenge = new Nip42Challenge(TEST_CHALLENGE, Instant.now().plusSeconds(300));

        ProxySession session1 = new ProxySession(SESSION_ID_1, clientSession, challenge);
        session1.setAuthenticatedPubkey(PUBKEY_1);
        sessionManager.register(session1);
        sessionManager.authenticate(SESSION_ID_1, PUBKEY_1);

        ProxySession session2 = new ProxySession(SESSION_ID_2, clientSession, challenge);
        session2.setAuthenticatedPubkey(PUBKEY_1);
        sessionManager.register(session2);
        sessionManager.authenticate(SESSION_ID_2, PUBKEY_1);

        // Then
        assertThat(sessionManager.canAcceptConnection(PUBKEY_1)).isFalse();
        assertThat(sessionManager.canAcceptConnection(PUBKEY_2)).isTrue();
    }

    /**
     * Tests that unlimited connections are allowed when max is 0.
     */
    @Test
    void shouldAllowUnlimitedConnectionsWhenMaxIsZero() {
        // Given
        properties.setMaxConnectionsPerPubkey(0);
        sessionManager = new SessionManager(properties, meterRegistry);

        Nip42Challenge challenge = new Nip42Challenge(TEST_CHALLENGE, Instant.now().plusSeconds(300));
        for (int i = 0; i < 100; i++) {
            String sessionId = "session-" + i;
            ProxySession session = new ProxySession(sessionId, clientSession, challenge);
            session.setAuthenticatedPubkey(PUBKEY_1);
            sessionManager.register(session);
            sessionManager.authenticate(sessionId, PUBKEY_1);
        }

        // Then
        assertThat(sessionManager.canAcceptConnection(PUBKEY_1)).isTrue();
    }

    /**
     * Tests that active session count is tracked correctly.
     */
    @Test
    void shouldTrackActiveSessionCount() {
        // Given
        Nip42Challenge challenge = new Nip42Challenge(TEST_CHALLENGE, Instant.now().plusSeconds(300));

        // When
        ProxySession session1 = new ProxySession(SESSION_ID_1, clientSession, challenge);
        sessionManager.register(session1);
        assertThat(sessionManager.getActiveSessionCount()).isEqualTo(1);

        ProxySession session2 = new ProxySession(SESSION_ID_2, clientSession, challenge);
        sessionManager.register(session2);
        assertThat(sessionManager.getActiveSessionCount()).isEqualTo(2);

        sessionManager.unregister(SESSION_ID_1);
        assertThat(sessionManager.getActiveSessionCount()).isEqualTo(1);
    }

    /**
     * Tests that metrics gauge reflects active sessions.
     */
    @Test
    void shouldExposeActiveSessionsAsMetric() {
        // Given
        Nip42Challenge challenge = new Nip42Challenge(TEST_CHALLENGE, Instant.now().plusSeconds(300));
        ProxySession session = new ProxySession(SESSION_ID_1, clientSession, challenge);

        // When
        sessionManager.register(session);

        // Then
        double gaugeValue = meterRegistry.get("nostr_auth_proxy_active_sessions").gauge().value();
        assertThat(gaugeValue).isEqualTo(1.0);
    }

    /**
     * Tests that getSessionsForPubkey returns empty set for unknown pubkey.
     */
    @Test
    void shouldReturnEmptySetForUnknownPubkey() {
        // When/Then
        assertThat(sessionManager.getSessionsForPubkey("unknown")).isEmpty();
    }
}
