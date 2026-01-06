package xyz.tcheeric.nostr.authproxy.handler;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;
import xyz.tcheeric.nostr.authproxy.access.AccessControlService;
import xyz.tcheeric.nostr.authproxy.auth.AuthResult;
import xyz.tcheeric.nostr.authproxy.auth.Nip42AuthVerifier;
import xyz.tcheeric.nostr.authproxy.auth.Nip42Challenge;
import xyz.tcheeric.nostr.authproxy.auth.Nip42ChallengeGenerator;
import xyz.tcheeric.nostr.authproxy.config.AuthProxyProperties;
import xyz.tcheeric.nostr.authproxy.session.ProxySession;
import xyz.tcheeric.nostr.authproxy.session.SessionManager;
import xyz.tcheeric.nostr.authproxy.session.SessionState;
import xyz.tcheeric.nostr.authproxy.upstream.UpstreamRelayClientFactory;

import java.net.InetSocketAddress;
import java.time.Duration;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for AuthProxyWebSocketHandler.
 */
@ExtendWith(MockitoExtension.class)
@org.mockito.junit.jupiter.MockitoSettings(strictness = org.mockito.quality.Strictness.LENIENT)
class AuthProxyWebSocketHandlerTest {

    @Mock
    private Nip42ChallengeGenerator challengeGenerator;
    @Mock
    private Nip42AuthVerifier authVerifier;
    @Mock
    private AccessControlService accessControl;
    @Mock
    private SessionManager sessionManager;
    @Mock
    private UpstreamRelayClientFactory upstreamFactory;
    @Mock
    private WebSocketSession clientSession;

    private AuthProxyProperties properties;
    private AuthProxyWebSocketHandler handler;
    private ThreadPoolTaskScheduler taskScheduler;
    private SimpleMeterRegistry meterRegistry;

    private static final String SESSION_ID = "test-session-123";
    private static final String TEST_CHALLENGE = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private static final String TEST_PUBKEY = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";

    @BeforeEach
    void setUp() {
        properties = new AuthProxyProperties();
        properties.setAuthTimeout(Duration.ofSeconds(30));

        taskScheduler = new ThreadPoolTaskScheduler();
        taskScheduler.initialize();

        meterRegistry = new SimpleMeterRegistry();

        handler = new AuthProxyWebSocketHandler(
                challengeGenerator,
                authVerifier,
                accessControl,
                sessionManager,
                upstreamFactory,
                properties,
                taskScheduler,
                meterRegistry
        );

        when(clientSession.getId()).thenReturn(SESSION_ID);
        when(clientSession.getRemoteAddress()).thenReturn(new InetSocketAddress("127.0.0.1", 12345));
    }

    /**
     * Tests that connection established sends AUTH challenge.
     */
    @Test
    void shouldSendAuthChallengeOnConnection() throws Exception {
        // Given
        Nip42Challenge challenge = new Nip42Challenge(TEST_CHALLENGE, Instant.now().plusSeconds(300));
        when(challengeGenerator.generate()).thenReturn(challenge);

        // When
        handler.afterConnectionEstablished(clientSession);

        // Then
        verify(sessionManager).register(any(ProxySession.class));
        verify(clientSession).sendMessage(argThat(msg ->
                msg.getPayload().equals("[\"AUTH\",\"" + TEST_CHALLENGE + "\"]")
        ));
    }

    /**
     * Tests that valid AUTH message results in successful authentication.
     */
    @Test
    void shouldAuthenticateValidAuthMessage() throws Exception {
        // Given
        Nip42Challenge challenge = new Nip42Challenge(TEST_CHALLENGE, Instant.now().plusSeconds(300));
        ProxySession proxySession = new ProxySession(SESSION_ID, clientSession, challenge);

        WebSocketSession upstreamSession = mock(WebSocketSession.class);

        when(sessionManager.get(SESSION_ID)).thenReturn(proxySession);
        when(authVerifier.verify(anyString(), any())).thenReturn(
                AuthResult.success(TEST_PUBKEY, "event123"));
        when(accessControl.isAllowed(TEST_PUBKEY)).thenReturn(true);
        when(sessionManager.canAcceptConnection(TEST_PUBKEY)).thenReturn(true);
        when(upstreamFactory.connect(any())).thenReturn(upstreamSession);

        String authMessage = "[\"AUTH\",{\"kind\":22242,\"pubkey\":\"" + TEST_PUBKEY + "\"}]";

        // When
        handler.handleTextMessage(clientSession, new TextMessage(authMessage));

        // Then
        verify(sessionManager).authenticate(SESSION_ID, TEST_PUBKEY);
        assertThat(proxySession.getState()).isEqualTo(SessionState.AUTHENTICATED);
        assertThat(proxySession.getAuthenticatedPubkey()).isEqualTo(TEST_PUBKEY);
    }

    /**
     * Tests that failed AUTH verification closes connection.
     */
    @Test
    void shouldCloseConnectionOnAuthFailure() throws Exception {
        // Given
        Nip42Challenge challenge = new Nip42Challenge(TEST_CHALLENGE, Instant.now().plusSeconds(300));
        ProxySession proxySession = new ProxySession(SESSION_ID, clientSession, challenge);

        when(sessionManager.get(SESSION_ID)).thenReturn(proxySession);
        when(authVerifier.verify(anyString(), any())).thenReturn(
                AuthResult.failure("invalid-signature", "Signature verification failed", "event123"));

        String authMessage = "[\"AUTH\",{\"kind\":22242}]";

        // When
        handler.handleTextMessage(clientSession, new TextMessage(authMessage));

        // Then
        verify(clientSession).close(CloseStatus.POLICY_VIOLATION);
        assertThat(proxySession.getState()).isEqualTo(SessionState.AUTH_FAILED);
    }

    /**
     * Tests that access control denial closes connection.
     */
    @Test
    void shouldCloseConnectionWhenAccessDenied() throws Exception {
        // Given
        Nip42Challenge challenge = new Nip42Challenge(TEST_CHALLENGE, Instant.now().plusSeconds(300));
        ProxySession proxySession = new ProxySession(SESSION_ID, clientSession, challenge);

        when(sessionManager.get(SESSION_ID)).thenReturn(proxySession);
        when(authVerifier.verify(anyString(), any())).thenReturn(
                AuthResult.success(TEST_PUBKEY, "event123"));
        when(accessControl.isAllowed(TEST_PUBKEY)).thenReturn(false);

        String authMessage = "[\"AUTH\",{\"kind\":22242}]";

        // When
        handler.handleTextMessage(clientSession, new TextMessage(authMessage));

        // Then
        verify(clientSession).close(CloseStatus.POLICY_VIOLATION);
        verify(upstreamFactory, never()).connect(any());
    }

    /**
     * Tests that connection limit denial closes connection.
     */
    @Test
    void shouldCloseConnectionWhenConnectionLimitReached() throws Exception {
        // Given
        Nip42Challenge challenge = new Nip42Challenge(TEST_CHALLENGE, Instant.now().plusSeconds(300));
        ProxySession proxySession = new ProxySession(SESSION_ID, clientSession, challenge);

        when(sessionManager.get(SESSION_ID)).thenReturn(proxySession);
        when(authVerifier.verify(anyString(), any())).thenReturn(
                AuthResult.success(TEST_PUBKEY, "event123"));
        when(accessControl.isAllowed(TEST_PUBKEY)).thenReturn(true);
        when(sessionManager.canAcceptConnection(TEST_PUBKEY)).thenReturn(false);

        String authMessage = "[\"AUTH\",{\"kind\":22242}]";

        // When
        handler.handleTextMessage(clientSession, new TextMessage(authMessage));

        // Then
        verify(clientSession).close(CloseStatus.POLICY_VIOLATION);
        verify(upstreamFactory, never()).connect(any());
    }

    /**
     * Tests that EVENT (write) messages require authentication.
     * REQ and CLOSE are allowed without auth since they are read-only.
     */
    @Test
    void shouldRejectEventMessageBeforeAuth() throws Exception {
        // Given
        Nip42Challenge challenge = new Nip42Challenge(TEST_CHALLENGE, Instant.now().plusSeconds(300));
        ProxySession proxySession = new ProxySession(SESSION_ID, clientSession, challenge);

        when(sessionManager.get(SESSION_ID)).thenReturn(proxySession);

        String eventMessage = "[\"EVENT\",{\"id\":\"abc\",\"kind\":1,\"content\":\"test\"}]";

        // When
        handler.handleTextMessage(clientSession, new TextMessage(eventMessage));

        // Then - should receive auth-required notice for EVENT
        verify(clientSession).sendMessage(argThat((TextMessage msg) ->
                msg.getPayload().contains("auth-required") && msg.getPayload().contains("EVENT")
        ));
    }

    /**
     * Tests that REQ (read) messages are allowed without authentication.
     */
    @Test
    void shouldAllowReqMessageWithoutAuth() throws Exception {
        // Given
        Nip42Challenge challenge = new Nip42Challenge(TEST_CHALLENGE, Instant.now().plusSeconds(300));
        ProxySession proxySession = new ProxySession(SESSION_ID, clientSession, challenge);
        WebSocketSession upstreamSession = mock(WebSocketSession.class);

        when(sessionManager.get(SESSION_ID)).thenReturn(proxySession);
        when(upstreamFactory.connect(proxySession)).thenReturn(upstreamSession);
        when(upstreamSession.isOpen()).thenReturn(true);

        String reqMessage = "[\"REQ\",\"sub1\",{}]";

        // When
        handler.handleTextMessage(clientSession, new TextMessage(reqMessage));

        // Then - should connect to upstream and forward REQ
        verify(upstreamFactory).connect(proxySession);
        verify(upstreamSession).sendMessage(argThat((TextMessage msg) ->
                msg.getPayload().equals(reqMessage)
        ));
    }

    /**
     * Tests that authenticated messages are proxied to upstream.
     */
    @Test
    void shouldProxyMessagesToUpstreamWhenAuthenticated() throws Exception {
        // Given
        Nip42Challenge challenge = new Nip42Challenge(TEST_CHALLENGE, Instant.now().plusSeconds(300));
        ProxySession proxySession = new ProxySession(SESSION_ID, clientSession, challenge);
        WebSocketSession upstreamSession = mock(WebSocketSession.class);

        proxySession.setState(SessionState.AUTHENTICATED);
        proxySession.setUpstreamSession(upstreamSession);
        when(upstreamSession.isOpen()).thenReturn(true);
        when(sessionManager.get(SESSION_ID)).thenReturn(proxySession);

        String reqMessage = "[\"REQ\",\"sub1\",{}]";
        TextMessage textMessage = new TextMessage(reqMessage);

        // When
        handler.handleTextMessage(clientSession, textMessage);

        // Then
        verify(upstreamSession).sendMessage(textMessage);
    }

    /**
     * Tests that connection closed cleans up session.
     */
    @Test
    void shouldCleanupSessionOnConnectionClose() throws Exception {
        // Given
        Nip42Challenge challenge = new Nip42Challenge(TEST_CHALLENGE, Instant.now().plusSeconds(300));
        ProxySession proxySession = new ProxySession(SESSION_ID, clientSession, challenge);
        WebSocketSession upstreamSession = mock(WebSocketSession.class);

        proxySession.setUpstreamSession(upstreamSession);
        when(upstreamSession.isOpen()).thenReturn(true);
        when(sessionManager.get(SESSION_ID)).thenReturn(proxySession);

        // When
        handler.afterConnectionClosed(clientSession, CloseStatus.NORMAL);

        // Then
        verify(upstreamSession).close(CloseStatus.NORMAL);
        verify(sessionManager).unregister(SESSION_ID);
        assertThat(proxySession.getState()).isEqualTo(SessionState.CLOSED);
    }

    /**
     * Tests that unknown session messages are rejected.
     */
    @Test
    void shouldRejectMessageFromUnknownSession() throws Exception {
        // Given
        when(sessionManager.get(SESSION_ID)).thenReturn(null);

        // When
        handler.handleTextMessage(clientSession, new TextMessage("[\"REQ\",\"sub1\",{}]"));

        // Then
        verify(clientSession).close(CloseStatus.POLICY_VIOLATION);
    }

    /**
     * Tests that metrics are incremented on connection.
     */
    @Test
    void shouldIncrementConnectionMetricsOnConnect() throws Exception {
        // Given
        Nip42Challenge challenge = new Nip42Challenge(TEST_CHALLENGE, Instant.now().plusSeconds(300));
        when(challengeGenerator.generate()).thenReturn(challenge);

        // When
        handler.afterConnectionEstablished(clientSession);

        // Then
        double count = meterRegistry.get("nostr_auth_proxy_connections_total").counter().count();
        assertThat(count).isEqualTo(1.0);
    }
}
