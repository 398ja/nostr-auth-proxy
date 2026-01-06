package xyz.tcheeric.nostr.authproxy.upstream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.client.standard.StandardWebSocketClient;
import org.springframework.web.socket.handler.TextWebSocketHandler;
import xyz.tcheeric.nostr.authproxy.config.AuthProxyProperties;
import xyz.tcheeric.nostr.authproxy.session.ProxySession;

import java.net.URI;
import java.util.concurrent.TimeUnit;

/**
 * Factory for creating upstream relay connections.
 */
@Component
public class UpstreamRelayClientFactory {

    private static final Logger log = LoggerFactory.getLogger(UpstreamRelayClientFactory.class);
    private static final int CONNECT_TIMEOUT_SECONDS = 10;

    private final AuthProxyProperties properties;
    private final StandardWebSocketClient webSocketClient;

    public UpstreamRelayClientFactory(AuthProxyProperties properties) {
        this.properties = properties;
        this.webSocketClient = new StandardWebSocketClient();
    }

    /**
     * Creates a connection to the upstream strfry relay.
     * Messages from upstream are forwarded to the client session.
     *
     * @param proxySession the proxy session to connect to upstream
     * @return the upstream WebSocket session
     * @throws Exception if connection fails
     */
    public WebSocketSession connect(ProxySession proxySession) throws Exception {
        URI upstreamUri = URI.create(properties.getUpstreamRelay());
        String sessionId = proxySession.getSessionId();

        log.debug("connecting_to_upstream session_id={} upstream={}", sessionId, upstreamUri);

        TextWebSocketHandler handler = new TextWebSocketHandler() {
            @Override
            protected void handleTextMessage(WebSocketSession session, TextMessage message) {
                try {
                    WebSocketSession client = proxySession.getClientSession();
                    if (client.isOpen()) {
                        client.sendMessage(message);
                    }
                } catch (Exception e) {
                    log.error("error_forwarding_to_client session_id={} error={}",
                            sessionId, e.getMessage(), e);
                }
            }

            @Override
            public void afterConnectionClosed(WebSocketSession session, CloseStatus status) {
                log.debug("upstream_connection_closed session_id={} status={}", sessionId, status);
                try {
                    WebSocketSession client = proxySession.getClientSession();
                    if (client.isOpen()) {
                        client.close(status);
                    }
                } catch (Exception e) {
                    log.debug("error_closing_client session_id={}", sessionId, e);
                }
            }

            @Override
            public void handleTransportError(WebSocketSession session, Throwable exception) {
                log.error("upstream_transport_error session_id={} error={}",
                        sessionId, exception.getMessage(), exception);
            }
        };

        WebSocketSession upstreamSession = webSocketClient
                .execute(handler, upstreamUri.toString())
                .get(CONNECT_TIMEOUT_SECONDS, TimeUnit.SECONDS);

        log.info("upstream_connected session_id={} upstream={}", sessionId, upstreamUri);
        return upstreamSession;
    }
}
