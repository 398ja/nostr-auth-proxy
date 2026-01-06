package xyz.tcheeric.nostr.authproxy.handler;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.TaskScheduler;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.handler.TextWebSocketHandler;
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

import java.time.Instant;
import java.util.Set;

/**
 * WebSocket handler for NIP-42 authentication proxy.
 *
 * <p>Handles the NIP-42 authentication flow and proxies authenticated connections
 * to the upstream relay.</p>
 */
@Component
public class AuthProxyWebSocketHandler extends TextWebSocketHandler {

    private static final Logger log = LoggerFactory.getLogger(AuthProxyWebSocketHandler.class);
    private static final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Kinds that require authentication to read (privacy-sensitive data).
     * Based on comprehensive review of all NIPs at github.com/nostr-protocol/nips
     *
     * NIP-04 (Legacy DMs - unrecommended, superseded by NIP-17):
     * - 4: Encrypted DMs
     *
     * NIP-17 (Private Direct Messages):
     * - 14: Chat messages
     * - 15: File messages
     *
     * NIP-29 (Groups - private membership):
     * - 39002: Group members
     *
     * NIP-37 (Draft Events):
     * - 10013: Draft relay preferences
     * - 31234: Draft wraps (encrypted unsigned events)
     *
     * NIP-46 (Nostr Remote Signing / Bunker):
     * - 24133: Bunker requests/responses (encrypted)
     *
     * NIP-47 (Nostr Wallet Connect):
     * - 23194: NWC requests
     * - 23195: NWC responses
     * - 23196: NWC notifications (legacy NIP-04)
     * - 23197: NWC notifications
     *
     * NIP-51 (Lists - may contain encrypted private items):
     * - 10000: Mute list
     * - 10050: DM relay preferences
     *
     * NIP-59 (Gift Wraps):
     * - 13: Seals
     * - 1059: Gift wraps
     *
     * NIP-60 (Cashu Wallet):
     * - 7374: Quote state
     * - 7375: Token event (unspent proofs)
     * - 7376: Spending history
     * - 17375: Wallet event
     *
     * NIP-61 (Nutzaps):
     * - 9321: Nutzap event
     * - 10019: Nutzap/relay config
     */
    private static final Set<Integer> PROTECTED_KINDS = Set.of(
            // NIP-04: Legacy DMs
            4,
            // NIP-17: Private Direct Messages
            14, 15,
            // NIP-29: Groups (private membership)
            39002,
            // NIP-37: Draft Events
            10013, 31234,
            // NIP-46: Nostr Remote Signing (Bunker)
            24133,
            // NIP-47: Nostr Wallet Connect
            23194, 23195, 23196, 23197,
            // NIP-51: Lists (with private items)
            10000, 10050,
            // NIP-59: Gift Wraps
            13, 1059,
            // NIP-60: Cashu Wallet
            7374, 7375, 7376, 17375,
            // NIP-61: Nutzaps
            9321, 10019
    );

    private final Nip42ChallengeGenerator challengeGenerator;
    private final Nip42AuthVerifier authVerifier;
    private final AccessControlService accessControl;
    private final SessionManager sessionManager;
    private final UpstreamRelayClientFactory upstreamFactory;
    private final AuthProxyProperties properties;
    private final TaskScheduler taskScheduler;

    private final Counter connectionsTotal;
    private final Counter authSuccessTotal;
    private final Counter authFailureTotal;
    private final Counter messagesProxiedTotal;

    public AuthProxyWebSocketHandler(
            Nip42ChallengeGenerator challengeGenerator,
            Nip42AuthVerifier authVerifier,
            AccessControlService accessControl,
            SessionManager sessionManager,
            UpstreamRelayClientFactory upstreamFactory,
            AuthProxyProperties properties,
            TaskScheduler taskScheduler,
            MeterRegistry meterRegistry) {
        this.challengeGenerator = challengeGenerator;
        this.authVerifier = authVerifier;
        this.accessControl = accessControl;
        this.sessionManager = sessionManager;
        this.upstreamFactory = upstreamFactory;
        this.properties = properties;
        this.taskScheduler = taskScheduler;

        this.connectionsTotal = Counter.builder("nostr_auth_proxy_connections_total")
                .description("Total connection attempts")
                .register(meterRegistry);
        this.authSuccessTotal = Counter.builder("nostr_auth_proxy_auth_success_total")
                .description("Successful authentications")
                .register(meterRegistry);
        this.authFailureTotal = Counter.builder("nostr_auth_proxy_auth_failure_total")
                .description("Failed authentications")
                .register(meterRegistry);
        this.messagesProxiedTotal = Counter.builder("nostr_auth_proxy_messages_proxied_total")
                .description("Messages proxied to upstream")
                .register(meterRegistry);
    }

    @Override
    public void afterConnectionEstablished(WebSocketSession session) throws Exception {
        connectionsTotal.increment();
        String sessionId = session.getId();
        log.info("client_connected session_id={} remote={}", sessionId, session.getRemoteAddress());

        Nip42Challenge challenge = challengeGenerator.generate();
        ProxySession proxySession = new ProxySession(sessionId, session, challenge);
        sessionManager.register(proxySession);

        // If auth not required, connect to upstream immediately and mark as authenticated
        if (!properties.isRequireAuth()) {
            log.debug("auth_not_required session_id={}", sessionId);
            WebSocketSession upstream = upstreamFactory.connect(proxySession);
            proxySession.setUpstreamSession(upstream);
            proxySession.setState(SessionState.AUTHENTICATED);
            return;
        }

        String authMessage = "[\"AUTH\",\"" + challenge.value() + "\"]";
        session.sendMessage(new TextMessage(authMessage));

        log.debug("auth_challenge_sent session_id={}", sessionId);

        scheduleAuthTimeout(sessionId);
    }

    @Override
    protected void handleTextMessage(WebSocketSession session, TextMessage message) throws Exception {
        String sessionId = session.getId();
        ProxySession proxySession = sessionManager.get(sessionId);

        if (proxySession == null) {
            log.warn("message_for_unknown_session session_id={}", sessionId);
            session.close(CloseStatus.POLICY_VIOLATION);
            return;
        }

        // Check message type and determine if auth is required
        String payload = message.getPayload();
        String messageType = extractMessageType(payload);

        log.info("message_received session_id={} type={} state={} payload_length={}",
                sessionId, messageType, proxySession.getState(), payload.length());

        switch (proxySession.getState()) {
            case AWAITING_AUTH -> {
                if ("AUTH".equals(messageType)) {
                    handleAuthMessage(proxySession, message);
                } else if ("CLOSE".equals(messageType)) {
                    // CLOSE never requires auth
                    ensureUpstreamConnected(proxySession);
                    proxyToUpstream(proxySession, message);
                } else if ("REQ".equals(messageType)) {
                    // REQ requires auth if require-auth is enabled or if querying protected kinds
                    if (properties.isRequireAuth()) {
                        sendAuthError(proxySession, "auth-required",
                                "AUTH required for REQ messages");
                    } else if (reqContainsProtectedKinds(payload)) {
                        sendAuthError(proxySession, "auth-required",
                                "Authentication required to query protected kinds (DMs, wallet data)");
                    } else {
                        ensureUpstreamConnected(proxySession);
                        proxyToUpstream(proxySession, message);
                    }
                } else {
                    // EVENT and other write operations require auth
                    sendAuthError(proxySession, "auth-required",
                            "Authentication required for " + messageType + " messages");
                }
            }
            case AUTHENTICATED -> proxyToUpstream(proxySession, message);
            default -> log.warn("message_in_invalid_state session_id={} state={}",
                    sessionId, proxySession.getState());
        }
    }

    private String extractMessageType(String payload) {
        try {
            JsonNode root = objectMapper.readTree(payload);
            if (root.isArray() && !root.isEmpty()) {
                return root.get(0).asText();
            }
        } catch (Exception e) {
            log.debug("failed_to_extract_message_type error={}", e.getMessage());
        }
        return null;
    }

    private void ensureUpstreamConnected(ProxySession session) throws Exception {
        if (session.getUpstreamSession() == null || !session.getUpstreamSession().isOpen()) {
            WebSocketSession upstream = upstreamFactory.connect(session);
            session.setUpstreamSession(upstream);
            log.debug("upstream_connected_for_readonly session_id={}", session.getSessionId());
        }
    }

    /**
     * Checks if a REQ message contains any protected kinds that require authentication.
     * REQ format: ["REQ", subscription_id, filter1, filter2, ...]
     * Filter may contain: {"kinds": [0, 1, 4, ...], ...}
     */
    private boolean reqContainsProtectedKinds(String payload) {
        try {
            JsonNode root = objectMapper.readTree(payload);
            if (!root.isArray() || root.size() < 3) {
                return false; // Invalid REQ or no filters
            }

            // Iterate over filters (starting at index 2)
            for (int i = 2; i < root.size(); i++) {
                JsonNode filter = root.get(i);
                if (filter.has("kinds")) {
                    JsonNode kinds = filter.get("kinds");
                    if (kinds.isArray()) {
                        for (JsonNode kind : kinds) {
                            if (kind.isInt() && PROTECTED_KINDS.contains(kind.asInt())) {
                                log.debug("protected_kind_requested kind={}", kind.asInt());
                                return true;
                            }
                        }
                    }
                }
            }
            return false;
        } catch (Exception e) {
            log.debug("failed_to_parse_req_kinds error={}", e.getMessage());
            return false; // Allow if we can't parse
        }
    }

    private void handleAuthMessage(ProxySession session, TextMessage message) throws Exception {
        String payload = message.getPayload();
        String sessionId = session.getSessionId();

        try {
            JsonNode root = objectMapper.readTree(payload);

            if (!root.isArray() || root.size() < 2) {
                sendAuthError(session, "auth-required",
                        "AUTH message missing event payload");
                return;
            }

            String eventJson = root.get(1).toString();
            session.setState(SessionState.AUTHENTICATING);

            AuthResult result = authVerifier.verify(eventJson, session.getChallenge());

            if (!result.authenticated()) {
                authFailureTotal.increment();
                log.info("auth_failed session_id={} error={}", sessionId, result.errorCode());
                sendAuthError(session, result.errorCode(), result.errorMessage(), result.eventId());
                session.setState(SessionState.AUTH_FAILED);
                session.getClientSession().close(CloseStatus.POLICY_VIOLATION);
                return;
            }

            String pubkey = result.pubkey();

            if (!accessControl.isAllowed(pubkey)) {
                authFailureTotal.increment();
                log.info("auth_denied_by_acl session_id={} pubkey={}", sessionId, pubkey);
                sendAuthError(session, "restricted", "Access denied for this pubkey", result.eventId());
                session.getClientSession().close(CloseStatus.POLICY_VIOLATION);
                return;
            }

            if (!sessionManager.canAcceptConnection(pubkey)) {
                authFailureTotal.increment();
                log.info("auth_denied_connection_limit session_id={} pubkey={}", sessionId, pubkey);
                sendAuthError(session, "rate-limited",
                        "Too many connections for this pubkey", result.eventId());
                session.getClientSession().close(CloseStatus.POLICY_VIOLATION);
                return;
            }

            WebSocketSession upstream = upstreamFactory.connect(session);
            session.setUpstreamSession(upstream);
            session.setAuthenticatedPubkey(pubkey);
            session.setState(SessionState.AUTHENTICATED);
            sessionManager.authenticate(sessionId, pubkey);
            authSuccessTotal.increment();

            String okMessage = String.format(
                    "[\"OK\",\"%s\",true,\"authenticated as %s\"]",
                    result.eventId(), pubkey.substring(0, 8) + "...");
            session.getClientSession().sendMessage(new TextMessage(okMessage));

            log.info("auth_success session_id={} pubkey={}", sessionId, pubkey);

        } catch (Exception e) {
            authFailureTotal.increment();
            log.error("auth_processing_error session_id={} error={}", sessionId, e.getMessage(), e);
            sendAuthError(session, "error", "Failed to process AUTH: " + e.getMessage());
            session.getClientSession().close(CloseStatus.SERVER_ERROR);
        }
    }

    private void proxyToUpstream(ProxySession session, TextMessage message) {
        try {
            WebSocketSession upstream = session.getUpstreamSession();
            if (upstream != null && upstream.isOpen()) {
                log.info("proxying_to_upstream session_id={} payload_length={}",
                        session.getSessionId(), message.getPayload().length());
                upstream.sendMessage(message);
                messagesProxiedTotal.increment();
                log.info("proxied_to_upstream session_id={}", session.getSessionId());
            } else {
                log.warn("upstream_not_available session_id={} upstream_null={} upstream_open={}",
                        session.getSessionId(), upstream == null, upstream != null && upstream.isOpen());
            }
        } catch (Exception e) {
            log.error("upstream_send_error session_id={} error={}",
                    session.getSessionId(), e.getMessage(), e);
        }
    }

    private void sendAuthError(ProxySession session, String code, String message) throws Exception {
        sendAuthError(session, code, message, null);
    }

    private void sendAuthError(ProxySession session, String code, String message, String eventId)
            throws Exception {
        if (eventId != null) {
            String okMessage = String.format("[\"OK\",\"%s\",false,\"%s: %s\"]", eventId, code, message);
            session.getClientSession().sendMessage(new TextMessage(okMessage));
        } else {
            String prefix = code.startsWith("auth-") ? code : "auth-required:" + code;
            String notice = String.format("[\"NOTICE\",\"%s: %s\"]", prefix, message);
            session.getClientSession().sendMessage(new TextMessage(notice));
        }
    }

    @Override
    public void afterConnectionClosed(WebSocketSession session, CloseStatus status) {
        String sessionId = session.getId();
        ProxySession proxySession = sessionManager.get(sessionId);

        if (proxySession != null) {
            WebSocketSession upstream = proxySession.getUpstreamSession();
            if (upstream != null && upstream.isOpen()) {
                try {
                    upstream.close(status);
                } catch (Exception e) {
                    log.debug("error_closing_upstream session_id={}", sessionId, e);
                }
            }
            proxySession.setState(SessionState.CLOSED);
            sessionManager.unregister(sessionId);
        }

        log.info("client_disconnected session_id={} status={}", sessionId, status);
    }

    @Override
    public void handleTransportError(WebSocketSession session, Throwable exception) {
        log.error("transport_error session_id={} error={}",
                session.getId(), exception.getMessage(), exception);
    }

    private void scheduleAuthTimeout(String sessionId) {
        Instant timeoutAt = Instant.now().plus(properties.getAuthTimeout());
        taskScheduler.schedule(() -> {
            ProxySession session = sessionManager.get(sessionId);
            if (session != null && session.getState() == SessionState.AWAITING_AUTH) {
                log.info("auth_timeout session_id={}", sessionId);
                try {
                    sendAuthError(session, "auth-timeout", "Authentication timeout");
                    session.getClientSession().close(CloseStatus.POLICY_VIOLATION);
                } catch (Exception e) {
                    log.debug("error_closing_timed_out_session session_id={}", sessionId, e);
                }
            }
        }, timeoutAt);
    }
}
