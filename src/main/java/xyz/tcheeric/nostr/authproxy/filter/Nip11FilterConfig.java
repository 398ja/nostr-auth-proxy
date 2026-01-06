package xyz.tcheeric.nostr.authproxy.filter;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;
import xyz.tcheeric.nostr.authproxy.config.AuthProxyProperties;

import java.io.IOException;

/**
 * Configuration for NIP-11 filter.
 * Registers a high-priority filter to handle NIP-11 relay info requests.
 */
@Configuration
public class Nip11FilterConfig {

    private static final Logger log = LoggerFactory.getLogger(Nip11FilterConfig.class);

    @Bean
    public FilterRegistrationBean<Nip11RequestFilter> nip11Filter(AuthProxyProperties properties) {
        FilterRegistrationBean<Nip11RequestFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(new Nip11RequestFilter(properties));
        registration.addUrlPatterns("/*");
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE);
        registration.setName("nip11Filter");
        return registration;
    }

    /**
     * Filter that handles NIP-11 relay info requests.
     */
    public static class Nip11RequestFilter implements Filter {

        private final AuthProxyProperties properties;
        private final RestTemplate restTemplate;

        public Nip11RequestFilter(AuthProxyProperties properties) {
            this.properties = properties;
            this.restTemplate = new RestTemplate();
        }

        @Override
        public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
                throws IOException, ServletException {

            HttpServletRequest httpRequest = (HttpServletRequest) request;
            HttpServletResponse httpResponse = (HttpServletResponse) response;

            String accept = httpRequest.getHeader("Accept");
            String upgrade = httpRequest.getHeader("Upgrade");
            String path = httpRequest.getRequestURI();
            String method = httpRequest.getMethod();

            log.debug("nip11_filter accept={} upgrade={} path={} method={}", accept, upgrade, path, method);

            // Handle NIP-11 requests: GET to / with nostr+json Accept and no WebSocket upgrade
            if ("GET".equals(method) && "/".equals(path) &&
                    accept != null && accept.contains("application/nostr+json") &&
                    (upgrade == null || !upgrade.equalsIgnoreCase("websocket"))) {

                log.info("nip11_request_detected path={}", path);
                handleNip11Request(httpResponse);
                return;
            }

            // Handle fallback for non-WebSocket, non-NIP-11 requests to root path
            if ("GET".equals(method) && "/".equals(path) &&
                    (upgrade == null || !upgrade.equalsIgnoreCase("websocket"))) {

                log.info("fallback_response path={}", path);
                httpResponse.setContentType("text/html");
                httpResponse.setStatus(HttpServletResponse.SC_OK);
                httpResponse.getWriter().write("Please use a Nostr client to connect. [v2]");
                httpResponse.getWriter().flush();
                return;
            }

            chain.doFilter(request, response);
        }

        private void handleNip11Request(HttpServletResponse response) throws IOException {
            try {
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

                response.setContentType("application/nostr+json");
                response.setStatus(HttpServletResponse.SC_OK);
                response.getWriter().write(upstreamResponse.getBody());
                response.getWriter().flush();

                log.info("nip11_response_sent");

            } catch (Exception e) {
                log.error("nip11_proxy_error error={}", e.getMessage(), e);
                response.setContentType("application/nostr+json");
                response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                response.getWriter().write("{\"error\":\"Failed to fetch relay info\"}");
                response.getWriter().flush();
            }
        }
    }
}
