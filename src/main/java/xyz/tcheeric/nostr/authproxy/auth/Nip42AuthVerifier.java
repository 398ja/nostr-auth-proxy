package xyz.tcheeric.nostr.authproxy.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import xyz.tcheeric.nostr.authproxy.config.AuthProxyProperties;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;

/**
 * Verifies NIP-42 AUTH events according to the NIP-42 specification.
 */
@Component
public class Nip42AuthVerifier {

    private static final int AUTH_EVENT_KIND = 22242;
    private static final Duration EVENT_TIME_TOLERANCE = Duration.ofMinutes(10);
    private static final Logger log = LoggerFactory.getLogger(Nip42AuthVerifier.class);
    private static final HexFormat HEX = HexFormat.of();

    // BIP-340 cryptographic constants
    private static final X9ECParameters CURVE_PARAMS = SECNamedCurves.getByName("secp256k1");
    private static final ECCurve CURVE = CURVE_PARAMS.getCurve();
    private static final ECDomainParameters DOMAIN = new ECDomainParameters(
            CURVE_PARAMS.getCurve(),
            CURVE_PARAMS.getG(),
            CURVE_PARAMS.getN(),
            CURVE_PARAMS.getH()
    );
    private static final BigInteger FIELD_MODULUS = CURVE.getField().getCharacteristic();
    private static final BigInteger GROUP_ORDER = CURVE_PARAMS.getN();
    private static final byte[] TAG_CHALLENGE = hashTag("BIP0340/challenge");

    private final AuthProxyProperties properties;
    private final ObjectMapper objectMapper;

    public Nip42AuthVerifier(AuthProxyProperties properties) {
        this.properties = properties;
        this.objectMapper = new ObjectMapper();
    }

    /**
     * Verifies a NIP-42 AUTH event.
     *
     * @param authEventJson     the raw JSON of the AUTH event
     * @param expectedChallenge the challenge that was sent to the client
     * @return AuthResult with pubkey if valid, or error details if invalid
     */
    public AuthResult verify(String authEventJson, Nip42Challenge expectedChallenge) {
        try {
            JsonNode eventNode = objectMapper.readTree(authEventJson);

            String eventId = getTextField(eventNode, "id");
            int kind = eventNode.has("kind") ? eventNode.get("kind").asInt() : -1;
            String pubkey = getTextField(eventNode, "pubkey");
            long createdAt = eventNode.has("created_at") ? eventNode.get("created_at").asLong() : 0;
            String content = getTextField(eventNode, "content");
            String sig = getTextField(eventNode, "sig");
            JsonNode tagsNode = eventNode.get("tags");

            if (kind != AUTH_EVENT_KIND) {
                log.debug("auth_verification_failed reason=invalid_kind expected={} actual={}", AUTH_EVENT_KIND, kind);
                return AuthResult.failure("invalid-kind",
                        "Expected kind " + AUTH_EVENT_KIND + ", got " + kind, eventId);
            }

            if (expectedChallenge.isExpired()) {
                log.debug("auth_verification_failed reason=challenge_expired challenge={}", expectedChallenge.value());
                return AuthResult.failure("challenge-expired",
                        "Challenge has expired, reconnect to get a new challenge", eventId);
            }

            String challengeTag = extractTagValue(tagsNode, "challenge");
            if (!expectedChallenge.value().equals(challengeTag)) {
                log.debug("auth_verification_failed reason=challenge_mismatch expected={} actual={}",
                        expectedChallenge.value(), challengeTag);
                return AuthResult.failure("challenge-mismatch",
                        "Challenge in event does not match expected challenge", eventId);
            }

            if (properties.getPublicRelayUrl() != null && !properties.getPublicRelayUrl().isBlank()) {
                String relayTag = extractTagValue(tagsNode, "relay");
                if (!normalizeUrl(properties.getPublicRelayUrl()).equals(normalizeUrl(relayTag))) {
                    log.debug("auth_verification_failed reason=relay_mismatch expected={} actual={}",
                            properties.getPublicRelayUrl(), relayTag);
                    return AuthResult.failure("relay-mismatch",
                            "Relay URL in event does not match this relay", eventId);
                }
            }

            Instant eventTime = Instant.ofEpochSecond(createdAt);
            Instant now = Instant.now();
            if (eventTime.isBefore(now.minus(EVENT_TIME_TOLERANCE))) {
                log.debug("auth_verification_failed reason=event_too_old created_at={}", eventTime);
                return AuthResult.failure("event-too-old",
                        "AUTH event created_at is too old", eventId);
            }
            if (eventTime.isAfter(now.plus(EVENT_TIME_TOLERANCE))) {
                log.debug("auth_verification_failed reason=event_in_future created_at={}", eventTime);
                return AuthResult.failure("event-in-future",
                        "AUTH event created_at is in the future", eventId);
            }

            // Parse tags for canonical serialization
            List<List<String>> tags = parseTags(tagsNode);

            // Verify event ID matches canonical serialization
            String canonicalId = generateEventId(pubkey, createdAt, kind, tags, content != null ? content : "");
            if (!canonicalId.equalsIgnoreCase(eventId)) {
                log.debug("auth_verification_failed reason=id_mismatch expected={} actual={}", canonicalId, eventId);
                return AuthResult.failure("id-mismatch",
                        "Event ID does not match canonical serialization", eventId);
            }

            if (!verifySignature(pubkey, canonicalId, sig)) {
                log.debug("auth_verification_failed reason=invalid_signature pubkey={}", pubkey);
                return AuthResult.failure("invalid-signature",
                        "BIP-340 signature verification failed", eventId);
            }

            log.info("auth_verification_success pubkey={} event_id={}", pubkey, eventId);
            return AuthResult.success(pubkey, eventId);

        } catch (Exception e) {
            log.error("auth_verification_failed reason=parse_error error={}", e.getMessage(), e);
            return AuthResult.failure("parse-error",
                    "Failed to parse AUTH event: " + e.getMessage());
        }
    }

    private String generateEventId(String pubkey, long createdAt, int kind,
                                   List<List<String>> tags, String content) {
        try {
            StringBuilder tagsJson = new StringBuilder("[");
            for (int i = 0; i < tags.size(); i++) {
                if (i > 0) tagsJson.append(",");
                tagsJson.append("[");
                List<String> tag = tags.get(i);
                for (int j = 0; j < tag.size(); j++) {
                    if (j > 0) tagsJson.append(",");
                    tagsJson.append("\"").append(escapeJson(tag.get(j))).append("\"");
                }
                tagsJson.append("]");
            }
            tagsJson.append("]");

            String serialized = String.format("[0,\"%s\",%d,%d,%s,\"%s\"]",
                    pubkey.toLowerCase(Locale.ROOT),
                    createdAt,
                    kind,
                    tagsJson,
                    escapeJson(content));

            byte[] hash = sha256(serialized.getBytes(StandardCharsets.UTF_8));
            return HEX.formatHex(hash);
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate event ID", e);
        }
    }

    private String escapeJson(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 32) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.toString();
    }

    private boolean verifySignature(String pubkeyHex, String messageHex, String signatureHex) {
        try {
            if (signatureHex == null || signatureHex.isBlank()) {
                return false;
            }

            byte[] pubkey = HEX.parseHex(pubkeyHex);
            byte[] message = HEX.parseHex(messageHex.toLowerCase(Locale.ROOT));
            byte[] signature = HEX.parseHex(signatureHex);

            if (pubkey.length != 32 || signature.length != 64) {
                return false;
            }

            BigInteger r = new BigInteger(1, slice(signature, 0, 32));
            BigInteger s = new BigInteger(1, slice(signature, 32, 64));

            if (r.signum() == 0 || r.compareTo(FIELD_MODULUS) >= 0) {
                return false;
            }
            if (s.signum() == 0 || s.compareTo(GROUP_ORDER) >= 0) {
                return false;
            }

            ECPoint P = liftX(pubkey);
            if (P == null) {
                return false;
            }

            byte[] eBytes = taggedHash(TAG_CHALLENGE, toFixedLength(r, 32), pubkey, message);
            BigInteger e = new BigInteger(1, eBytes).mod(GROUP_ORDER);

            ECPoint sG = DOMAIN.getG().multiply(s);
            ECPoint eP = P.multiply(e);
            ECPoint R = sG.subtract(eP).normalize();

            if (R.isInfinity()) {
                return false;
            }

            BigInteger xCoord = R.getAffineXCoord().toBigInteger();
            if (R.getAffineYCoord().toBigInteger().testBit(0)) {
                return false;
            }
            return xCoord.equals(r);
        } catch (Exception e) {
            log.warn("signature_verification_error error={}", e.getMessage(), e);
            return false;
        }
    }

    private static ECPoint liftX(byte[] publicKey) {
        BigInteger x = new BigInteger(1, publicKey);
        if (x.signum() < 0 || x.compareTo(FIELD_MODULUS) >= 0) {
            return null;
        }

        ECFieldElement xField = CURVE.fromBigInteger(x);
        ECFieldElement alpha = xField.multiply(xField.square()).add(CURVE.getB());
        ECFieldElement beta = alpha.sqrt();
        if (beta == null) {
            return null;
        }
        BigInteger y = beta.toBigInteger();
        if (y.testBit(0)) {
            y = FIELD_MODULUS.subtract(y);
        }
        return CURVE.validatePoint(x, y);
    }

    private static byte[] taggedHash(byte[] tagHash, byte[]... data) {
        MessageDigest digest = newDigest();
        digest.update(tagHash);
        digest.update(tagHash);
        for (byte[] part : data) {
            digest.update(part);
        }
        return digest.digest();
    }

    private static byte[] toFixedLength(BigInteger value, int length) {
        byte[] bytes = value.toByteArray();
        if (bytes.length == length) {
            return bytes;
        }
        byte[] result = new byte[length];
        int srcPos = Math.max(0, bytes.length - length);
        int destPos = Math.max(0, length - bytes.length);
        int copyLength = Math.min(length, bytes.length);
        System.arraycopy(bytes, srcPos, result, destPos, copyLength);
        return result;
    }

    private static byte[] slice(byte[] input, int from, int to) {
        byte[] slice = new byte[to - from];
        System.arraycopy(input, from, slice, 0, slice.length);
        return slice;
    }

    private static byte[] hashTag(String tag) {
        return sha256(tag.getBytes(StandardCharsets.US_ASCII));
    }

    private static byte[] sha256(byte[] input) {
        return newDigest().digest(input);
    }

    private static MessageDigest newDigest() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 digest not available", e);
        }
    }

    private List<List<String>> parseTags(JsonNode tagsNode) {
        List<List<String>> tags = new ArrayList<>();
        if (tagsNode != null && tagsNode.isArray()) {
            for (JsonNode tagNode : tagsNode) {
                if (tagNode.isArray()) {
                    List<String> tag = new ArrayList<>();
                    for (JsonNode element : tagNode) {
                        tag.add(element.asText());
                    }
                    tags.add(tag);
                }
            }
        }
        return tags;
    }

    private String extractTagValue(JsonNode tagsNode, String tagName) {
        if (tagsNode == null || !tagsNode.isArray()) {
            return null;
        }
        for (JsonNode tagNode : tagsNode) {
            if (tagNode.isArray() && tagNode.size() >= 2) {
                if (tagName.equals(tagNode.get(0).asText())) {
                    return tagNode.get(1).asText();
                }
            }
        }
        return null;
    }

    private String getTextField(JsonNode node, String field) {
        if (node.has(field) && !node.get(field).isNull()) {
            return node.get(field).asText();
        }
        return null;
    }

    private String normalizeUrl(String url) {
        if (url == null) {
            return null;
        }
        return url.replaceAll("/$", "").toLowerCase();
    }
}
