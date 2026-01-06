package xyz.tcheeric.nostr.authproxy.config;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.socket.config.annotation.EnableWebSocket;
import org.springframework.web.socket.config.annotation.WebSocketConfigurer;
import org.springframework.web.socket.config.annotation.WebSocketHandlerRegistry;
import xyz.tcheeric.nostr.authproxy.handler.AuthProxyWebSocketHandler;
import xyz.tcheeric.nostr.authproxy.handler.Nip11HandshakeInterceptor;

/**
 * WebSocket configuration for the NIP-42 Auth Proxy.
 */
@Configuration
@EnableWebSocket
public class WebSocketConfig implements WebSocketConfigurer {

    private static final Logger log = LoggerFactory.getLogger(WebSocketConfig.class);

    private final AuthProxyWebSocketHandler authProxyWebSocketHandler;
    private final Nip11HandshakeInterceptor nip11HandshakeInterceptor;

    public WebSocketConfig(AuthProxyWebSocketHandler authProxyWebSocketHandler,
            Nip11HandshakeInterceptor nip11HandshakeInterceptor) {
        this.authProxyWebSocketHandler = authProxyWebSocketHandler;
        this.nip11HandshakeInterceptor = nip11HandshakeInterceptor;
    }

    @PostConstruct
    public void init() {
        log.info("websocket_config_initialized handler={}", authProxyWebSocketHandler.getClass().getSimpleName());
    }

    @Override
    public void registerWebSocketHandlers(WebSocketHandlerRegistry registry) {
        log.info("websocket_handlers_registering path=/");
        registry.addHandler(authProxyWebSocketHandler, "/")
                .addInterceptors(nip11HandshakeInterceptor)
                .setAllowedOrigins("*");
        log.info("websocket_handlers_registered");
    }
}
