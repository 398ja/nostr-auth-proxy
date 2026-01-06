package xyz.tcheeric.nostr.authproxy.access;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import xyz.tcheeric.nostr.authproxy.config.AuthProxyProperties;
import xyz.tcheeric.nostr.authproxy.config.AuthProxyProperties.AccessMode;

/**
 * Service for controlling access based on pubkey allowlist/blocklist.
 */
@Service
public class AccessControlService {

    private static final Logger log = LoggerFactory.getLogger(AccessControlService.class);

    private final AuthProxyProperties properties;

    public AccessControlService(AuthProxyProperties properties) {
        this.properties = properties;
    }

    /**
     * Checks if a pubkey is allowed to connect.
     *
     * @param pubkey the pubkey to check (hex format)
     * @return true if the pubkey is allowed
     */
    public boolean isAllowed(String pubkey) {
        if (pubkey == null || pubkey.isBlank()) {
            log.debug("access_denied reason=empty_pubkey");
            return false;
        }

        String normalizedPubkey = pubkey.toLowerCase();
        AccessMode mode = properties.getAccessMode();

        boolean allowed = switch (mode) {
            case ALLOWLIST -> {
                boolean inList = properties.getAllowedPubkeys().stream()
                        .map(String::toLowerCase)
                        .anyMatch(p -> p.equals(normalizedPubkey));
                if (!inList) {
                    log.debug("access_denied reason=not_in_allowlist pubkey={}", normalizedPubkey);
                }
                yield inList;
            }
            case BLOCKLIST -> {
                boolean blocked = properties.getBlockedPubkeys().stream()
                        .map(String::toLowerCase)
                        .anyMatch(p -> p.equals(normalizedPubkey));
                if (blocked) {
                    log.debug("access_denied reason=in_blocklist pubkey={}", normalizedPubkey);
                }
                yield !blocked;
            }
            case OPEN -> true;
        };

        if (allowed) {
            log.trace("access_granted pubkey={} mode={}", normalizedPubkey, mode);
        }

        return allowed;
    }

    /**
     * Gets the current access mode.
     *
     * @return the access mode
     */
    public AccessMode getAccessMode() {
        return properties.getAccessMode();
    }
}
