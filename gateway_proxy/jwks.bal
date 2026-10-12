// JWKS fetching, caching, and RSA key resolution for the jwt-auth policy.
//
// Keys are cached as plain hex strings per JWKS URI with a TTL refresh, one
// forced refetch on an unknown `kid` (RFC 8725), and last-known-good fallback
// when a refresh fails, so a JWKS outage does not take authentication down
// with it.
//
// NOTE: `crypto:PublicKey` values built by Nutcracker's crypto externals
// cannot be stored in typed maps/arrays (their Go-side atomic type is
// `map<string>`, which never satisfies the closed `crypto:PublicKey` record
// in a member-store check, and rebuilding the record orphans the weak-pointer
// key material). The cache therefore holds only modulus/exponent hex strings
// and materializes a fresh key per verification via `materializePublicKey`.

import ballerina/crypto;
import ballerina/http;
import ballerina/log;
import ballerina/time;

# One cached JWK: hex-encoded RSA modulus and exponent, safe to store.
public type JwksCachedKey record {|
    # Key ID, or "" for entries that shipped without a `kid`
    string keyId;
    # Hex-encoded RSA modulus (from base64url `n`)
    string modulusHex;
    # Hex-encoded RSA exponent (from base64url `e`)
    string exponentHex;
|};

# Cached JWKS document for one URI.
type JwksCache record {|
    # Key ID → cached key, for tokens that carry a `kid`
    map<JwksCachedKey> keysByKeyId;
    # Every usable RSA signature key, for tokens without a `kid`
    JwksCachedKey[] keys;
    # Epoch seconds of the fetch that populated this cache
    int fetchedAt;
|};

map<JwksCache> jwksCaches = {};
map<http:Client> jwksClients = {};

# Resolves signing keys from a JWKS document.
#
# Returns the key matching `keyId` when given, otherwise every usable key.
# The document is cached for `cacheTtlSeconds`; an unknown `kid` triggers one
# immediate refetch before failing; a failed refresh keeps the cached keys.
#
# + jwksUri - Full URL of the JWKS document
# + keyId - JOSE `kid` to select, or `()` for all usable keys
# + cacheTtlSeconds - How long before the cached document is refreshed
# + return - Usable cached keys, or an error when none resolve
public function resolveSigningKeys(string jwksUri, string? keyId = (),
        int cacheTtlSeconds = 300) returns JwksCachedKey[]|error {
    JwksCache currentCache;
    JwksCache? cached = jwksCaches[jwksUri];
    if cached is () {
        JwksCache|error fetchedResult = fetchJwksCache(jwksUri = jwksUri);
        if fetchedResult is error {
            // Prefix lets jwt-auth tell infrastructure failures from auth
            // failures (unknown kid): this one must fail the chain closed.
            return error("JWKS unavailable: " + fetchedResult.message());
        }
        jwksCaches[jwksUri] = fetchedResult;
        currentCache = fetchedResult;
    } else {
        currentCache = cached;
    }

    if currentEpochSeconds() - currentCache.fetchedAt >= cacheTtlSeconds {
        JwksCache|error refreshed = fetchJwksCache(jwksUri = jwksUri);
        if refreshed is JwksCache {
            jwksCaches[jwksUri] = refreshed;
            currentCache = refreshed;
        } else {
            log:printWarn("JWKS refresh failed; using cached keys",
                    jwksUri = jwksUri, reason = refreshed.message());
        }
    }

    if keyId is string {
        JwksCachedKey? key = currentCache.keysByKeyId[keyId];
        if key is JwksCachedKey {
            return [key];
        }
        // Unknown kid: the issuer may have just rotated — refetch once.
        JwksCache|error refetched = fetchJwksCache(jwksUri = jwksUri);
        if refetched is JwksCache {
            jwksCaches[jwksUri] = refetched;
            JwksCachedKey? refetchedKey = refetched.keysByKeyId[keyId];
            if refetchedKey is JwksCachedKey {
                return [refetchedKey];
            }
        } else {
            log:printWarn("JWKS refetch failed; using cached keys",
                    jwksUri = jwksUri, reason = refetched.message());
        }
        return error("no JWKS key matches kid: " + keyId);
    }
    if currentCache.keys.length() == 0 {
        return error("JWKS contains no usable keys");
    }
    return currentCache.keys;
}

# Builds a fresh `crypto:PublicKey` from a cached key.
#
# Call this per verification: built keys must not be stored in typed
# containers (see file header), so materialize, use, and drop.
#
# + cachedKey - The cached modulus/exponent pair
# + return - A verifiable RSA public key, or an error when hex/base64 is invalid
public function materializePublicKey(JwksCachedKey cachedKey) returns crypto:PublicKey|error {
    return check crypto:buildRsaPublicKey(
            modulus = cachedKey.modulusHex,
            exponent = cachedKey.exponentHex);
}

# Drops cached JWKS documents and clients (used by tests and config reloads).
public function clearJwksCache() {
    foreach string key in jwksCaches.keys() {
        _ = jwksCaches.remove(key);
    }
    foreach string key in jwksClients.keys() {
        _ = jwksClients.remove(key);
    }
}

# Fetches and parses the JWKS document at `jwksUri`.
function fetchJwksCache(string jwksUri) returns JwksCache|error {
    http:Client jwksHttp = check jwksClientFor(jwksUri = jwksUri);
    http:Response response = check jwksHttp->get(path = "", targetType = http:Response);
    if response.statusCode != 200 {
        return error("JWKS fetch failed with status " + response.statusCode.toString());
    }
    json payload = check response.getJsonPayload();
    map<json>|error payloadMapResult = payload.cloneWithType();
    if payloadMapResult is error {
        return error("JWKS response is not a JSON object");
    }
    map<json> payloadMap = payloadMapResult;
    if !payloadMap.hasKey("keys") {
        return error("JWKS response is missing keys");
    }
    json keysValue = payloadMap.get("keys");
    json[]|error keysArray = keysValue.cloneWithType();
    if keysArray is error {
        return error("JWKS keys is not an array");
    }
    return parseJwksKeys(keysArray = keysArray);
}

# Parses usable RSA signature keys out of a JWKS `keys` array.
# Entries that are malformed or unusable (non-RSA, wrong use/alg, bad
# base64url) are skipped; a document with zero usable keys is an error.
function parseJwksKeys(json[] keysArray) returns JwksCache|error {
    map<JwksCachedKey> keysByKeyId = {};
    JwksCachedKey[] keys = [];
    foreach json keyJson in keysArray {
        map<json>|error keyMapResult = keyJson.cloneWithType();
        if keyMapResult is map<json> {
            JwksCachedKey? parsed = parseSingleJwk(keyMap = keyMapResult);
            if parsed is JwksCachedKey {
                if parsed.keyId.length() > 0 {
                    keysByKeyId[parsed.keyId] = parsed;
                }
                keys.push(parsed);
            }
        }
    }
    if keys.length() == 0 {
        return error("JWKS contains no usable RSA signature keys");
    }
    return {
        keysByKeyId: keysByKeyId,
        keys: keys,
        fetchedAt: currentEpochSeconds()
    };
}

# Parses one JWK entry into cached hex form; `()` when the entry is not a
# usable RS256 key. The base64url fields are validated here so a bad entry
# is skipped instead of failing every later verification.
function parseSingleJwk(map<json> keyMap) returns JwksCachedKey? {
    string? kty = claimString(claims = keyMap, key = "kty");
    if kty is () || kty != "RSA" {
        return ();
    }
    string? use = claimString(claims = keyMap, key = "use");
    if use is string && use != "sig" {
        return ();
    }
    string? algorithm = claimString(claims = keyMap, key = "alg");
    if algorithm is string && algorithm != "RS256" {
        return ();
    }
    string? modulus = claimString(claims = keyMap, key = "n");
    string? exponent = claimString(claims = keyMap, key = "e");
    if modulus is () || exponent is () {
        return ();
    }
    byte[]|error modulusBytes = base64urlDecode(encoded = modulus);
    byte[]|error exponentBytes = base64urlDecode(encoded = exponent);
    if modulusBytes is error || exponentBytes is error {
        return ();
    }
    string? keyId = claimString(claims = keyMap, key = "kid");
    string cachedKeyId = "";
    if keyId is string {
        cachedKeyId = keyId;
    }
    return {
        keyId: cachedKeyId,
        modulusHex: hexEncode(modulusBytes),
        exponentHex: hexEncode(exponentBytes)
    };
}

# Returns a cached HTTP client for `jwksUri`, creating it on first use.
function jwksClientFor(string jwksUri) returns http:Client|error {
    http:Client? existing = jwksClients[jwksUri];
    if existing is http:Client {
        return existing;
    }
    http:Client created = check new (jwksUri, {
        timeout: 10,
        httpVersion: http:HTTP_1_1
    });
    jwksClients[jwksUri] = created;
    return created;
}

# Current time as integer seconds since the UNIX epoch.
function currentEpochSeconds() returns int {
    time:Utc now = time:utcNow();
    return now[0];
}
