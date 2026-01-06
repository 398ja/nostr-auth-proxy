package xyz.tcheeric.nostr.authproxy.handler;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.socket.WebSocketHandler;
import org.springframework.web.socket.server.HandshakeInterceptor;
import xyz.tcheeric.nostr.authproxy.config.AuthProxyProperties;

import java.io.IOException;
import java.util.Map;

/**
 * Handshake interceptor that handles NIP-11 relay info requests.
 *
 * <p>If the request has Accept: application/nostr+json header but no
 * WebSocket upgrade header, it's a NIP-11 info request. We handle it
 * directly and reject the WebSocket handshake.</p>
 */
@Component
public class Nip11HandshakeInterceptor implements HandshakeInterceptor {

    private static final Logger log = LoggerFactory.getLogger(Nip11HandshakeInterceptor.class);

    private final AuthProxyProperties properties;
    private final RestTemplate restTemplate;

    public Nip11HandshakeInterceptor(AuthProxyProperties properties) {
        this.properties = properties;
        this.restTemplate = new RestTemplate();
    }

    @Override
    public boolean beforeHandshake(ServerHttpRequest request, ServerHttpResponse response,
            WebSocketHandler wsHandler, Map<String, Object> attributes) throws Exception {

        String accept = request.getHeaders().getFirst("Accept");
        String upgrade = request.getHeaders().getFirst("Upgrade");

        // If it's a NIP-11 request (has nostr+json Accept but no WebSocket upgrade)
        if (accept != null && accept.contains("application/nostr+json") &&
                (upgrade == null || !upgrade.equalsIgnoreCase("websocket"))) {

            log.info("nip11_request_intercepted path={}", request.getURI().getPath());
            handleNip11Request(response);
            return false; // Reject WebSocket handshake
        }

        return true; // Proceed with WebSocket handshake
    }

    @Override
    public void afterHandshake(ServerHttpRequest request, ServerHttpResponse response,
            WebSocketHandler wsHandler, Exception exception) {
        // Nothing to do
    }

    private void handleNip11Request(ServerHttpResponse response) throws IOException {
        try {
            // Convert ws:// to http:// for the upstream URL
            String upstreamUrl = properties.getUpstreamRelay()
                    .replace("ws://", "http://")
                    .replace("wss://", "https://");

            log.info("proxying_nip11_request upstream={}", upstreamUrl);

            HttpHeaders headers = new HttpHeaders();
            headers.set("Accept", "application/nostr+json");
            HttpEntity<Void> request = new HttpEntity<>(headers);

            ResponseEntity<String> upstreamResponse = restTemplate.exchange(
                    upstreamUrl,
                    HttpMethod.GET,
                    request,
                    String.class);

            response.getHeaders().set("Content-Type", "application/nostr+json");
            response.getBody().write(upstreamResponse.getBody().getBytes());
            response.getBody().flush();

            log.info("nip11_response_sent");

        } catch (Exception e) {
            log.error("nip11_proxy_error error={}", e.getMessage(), e);
            response.getHeaders().set("Content-Type", "application/nostr+json");
            response.getBody().write("{\"error\":\"Failed to fetch relay info\"}".getBytes());
            response.getBody().flush();
        }
    }
}
