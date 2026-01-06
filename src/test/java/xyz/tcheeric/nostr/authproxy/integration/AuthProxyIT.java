package xyz.tcheeric.nostr.authproxy.integration;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.client.standard.StandardWebSocketClient;
import org.springframework.web.socket.handler.TextWebSocketHandler;
import xyz.tcheeric.nostr.authproxy.config.AuthProxyProperties;
import xyz.tcheeric.nostr.authproxy.session.SessionManager;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests for NIP-42 Auth Proxy.
 */
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "nostr.auth-proxy.upstream-relay=ws://localhost:7778",
                "nostr.auth-proxy.require-auth=true"
        }
)
@Tag("integration")
class AuthProxyIT {

    @LocalServerPort
    private int port;

    @Autowired
    private AuthProxyProperties properties;

    @Autowired
    private SessionManager sessionManager;

    /**
     * Tests that connecting to the proxy receives an AUTH challenge.
     */
    @Test
    void shouldReceiveAuthChallengeOnConnect() throws Exception {
        // Given
        BlockingQueue<String> messages = new LinkedBlockingQueue<>();
        StandardWebSocketClient client = new StandardWebSocketClient();

        TextWebSocketHandler handler = new TextWebSocketHandler() {
            @Override
            protected void handleTextMessage(WebSocketSession session, TextMessage message) {
                messages.add(message.getPayload());
            }
        };

        // When
        WebSocketSession session = client
                .execute(handler, "ws://localhost:" + port + "/")
                .get(5, TimeUnit.SECONDS);

        try {
            // Then
            String authChallenge = messages.poll(5, TimeUnit.SECONDS);
            assertThat(authChallenge).isNotNull();
            assertThat(authChallenge).startsWith("[\"AUTH\",\"");
            assertThat(authChallenge).endsWith("\"]");

            // Extract challenge value and verify format
            // Format is ["AUTH","<64-hex-chars>"]
            String challenge = authChallenge.substring(9, authChallenge.length() - 2);
            assertThat(challenge).hasSize(64);
            assertThat(challenge).matches("[0-9a-f]+");
        } finally {
            session.close();
        }
    }

    /**
     * Tests that session is registered on connect.
     */
    @Test
    void shouldRegisterSessionOnConnect() throws Exception {
        // Given
        StandardWebSocketClient client = new StandardWebSocketClient();
        int initialCount = sessionManager.getActiveSessionCount();

        // When
        WebSocketSession session = client
                .execute(new TextWebSocketHandler() {}, "ws://localhost:" + port + "/")
                .get(5, TimeUnit.SECONDS);

        try {
            // Then
            Thread.sleep(100); // Allow time for session registration
            assertThat(sessionManager.getActiveSessionCount()).isGreaterThan(initialCount);
        } finally {
            session.close();
        }
    }

    /**
     * Tests that non-AUTH message before authentication returns error.
     */
    @Test
    void shouldRejectNonAuthMessageBeforeAuthentication() throws Exception {
        // Given
        BlockingQueue<String> messages = new LinkedBlockingQueue<>();
        StandardWebSocketClient client = new StandardWebSocketClient();

        TextWebSocketHandler handler = new TextWebSocketHandler() {
            @Override
            protected void handleTextMessage(WebSocketSession session, TextMessage message) {
                messages.add(message.getPayload());
            }
        };

        // When
        WebSocketSession session = client
                .execute(handler, "ws://localhost:" + port + "/")
                .get(5, TimeUnit.SECONDS);

        try {
            // Wait for AUTH challenge
            String authChallenge = messages.poll(5, TimeUnit.SECONDS);
            assertThat(authChallenge).isNotNull();

            // Send REQ before authenticating
            session.sendMessage(new TextMessage("[\"REQ\",\"sub1\",{}]"));

            // Then - should receive NOTICE about auth requirement
            String response = messages.poll(5, TimeUnit.SECONDS);
            assertThat(response).isNotNull();
            assertThat(response).contains("NOTICE").contains("AUTH");
        } finally {
            session.close();
        }
    }

    /**
     * Tests that session is unregistered on disconnect.
     */
    @Test
    void shouldUnregisterSessionOnDisconnect() throws Exception {
        // Given
        StandardWebSocketClient client = new StandardWebSocketClient();

        WebSocketSession session = client
                .execute(new TextWebSocketHandler() {}, "ws://localhost:" + port + "/")
                .get(5, TimeUnit.SECONDS);

        Thread.sleep(100); // Allow time for session registration
        int countBeforeClose = sessionManager.getActiveSessionCount();

        // When
        session.close();
        Thread.sleep(100); // Allow time for session cleanup

        // Then
        assertThat(sessionManager.getActiveSessionCount()).isLessThan(countBeforeClose);
    }

    /**
     * Tests that configuration is loaded correctly.
     */
    @Test
    void shouldLoadConfiguration() {
        // Then
        assertThat(properties.isRequireAuth()).isTrue();
        assertThat(properties.getUpstreamRelay()).isEqualTo("ws://localhost:7778");
    }
}
