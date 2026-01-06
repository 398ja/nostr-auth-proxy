package xyz.tcheeric.nostr.authproxy;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import xyz.tcheeric.nostr.authproxy.config.AuthProxyProperties;

/**
 * NIP-42 Authentication Proxy for Nostr relays.
 *
 * <p>This application provides a WebSocket proxy that authenticates clients using
 * the NIP-42 protocol before forwarding connections to an upstream relay (strfry).</p>
 */
@SpringBootApplication
@EnableConfigurationProperties(AuthProxyProperties.class)
public class AuthProxyApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthProxyApplication.class, args);
    }
}
