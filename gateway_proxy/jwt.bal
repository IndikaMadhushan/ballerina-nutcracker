// Compact-JWT parsing and RS256 verification for the jwt-auth policy.
//
// Claims are kept as `map<json>` (JWT claims are dynamic by nature) and read
// through the typed accessors below, so callers never manipulate raw json.
// All helpers are pure; key selection/JWKS fetching lives in jwks.bal and the
// policy orchestration in jwt_auth.bal.

import ballerina/crypto;
import ballerina/io;
import ballerina/time;

# The three segments of a compact JWS serialization plus the signed input.
public type JwtParts record {|
    # `base64url(header).base64url(payload)` — the exact bytes that were signed
    string signingInput;
    string headerSegment;
    string payloadSegment;
    string signatureSegment;
|};

# Splits a compact JWT into its segments; rejects anything that is not
# exactly three dot-separated parts.
#
# + token - The compact serialization (`header.payload.signature`)
# + return - The segments, or an error when the token is malformed
public function splitJwt(string token) returns JwtParts|error {
    string[] segments = check splitOn(subject = token, delim = ".");
    if segments.length() != 3 {
        return error("malformed JWT: expected 3 segments, got " + segments.length().toString());
    }
    return {
        signingInput: segments[0] + "." + segments[1],
        headerSegment: segments[0],
        payloadSegment: segments[1],
        signatureSegment: segments[2]
    };
}

# Decodes a base64url JWT segment (header or claims set) into a map.
#
# + segment - The base64url-encoded segment
# + return - The decoded object, or an error when decoding/decoding-shape fails
public function parseJwtSegment(string segment) returns map<json>|error {
    byte[] decoded = check base64urlDecode(encoded = segment);
    // Nutcracker has no string→json parser; route the bytes through the
    // io reader channels, which do expose readJson().
    io:ReadableByteChannel byteChannel = check io:createReadableChannel(content = decoded);
    io:ReadableCharacterChannel charChannel = new (byteChannel, "UTF-8");
    json parsed = check charChannel.readJson();
    map<json>|error parsedMap = parsed.cloneWithType();
    if parsedMap is map<json> {
        return parsedMap;
    }
    return error("JWT segment is not a JSON object");
}

# Returns the string claim `key`, or `()` when absent or not a string.
public function claimString(map<json> claims, string key) returns string? {
    if !claims.hasKey(key) {
        return ();
    }
    json claimValue = claims.get(key);
    string|error converted = claimValue.cloneWithType();
    if converted is string {
        return converted;
    }
    return ();
}

# Returns the integer claim `key`, or `()` when absent or not a number.
public function claimInt(map<json> claims, string key) returns int? {
    if !claims.hasKey(key) {
        return ();
    }
    json claimValue = claims.get(key);
    int|error converted = claimValue.cloneWithType();
    if converted is int {
        return converted;
    }
    return ();
}

# Collects scopes from `scope` (space-delimited string) and/or `scp` (array),
# merging both shapes like the api-platform reference does.
#
# + claims - The decoded claims set
# + return - All scopes found, in claim order, without empty entries
public function tokenScopes(map<json> claims) returns string[] {
    string[] scopes = [];
    string? scopeValue = claimString(claims = claims, key = "scope");
    if scopeValue is string {
        string[]|error parts = splitOn(subject = scopeValue, delim = " ");
        if parts is string[] {
            foreach string part in parts {
                if part.length() > 0 {
                    scopes.push(part);
                }
            }
        }
    }
    if claims.hasKey("scp") {
        json scpValue = claims.get("scp");
        json[]|error items = scpValue.cloneWithType();
        if items is json[] {
            foreach json item in items {
                string|error scopeItem = item.cloneWithType();
                if scopeItem is string {
                    scopes.push(scopeItem);
                }
            }
        }
    }
    return scopes;
}

# Validates `exp`/`nbf` against the current time, allowing `leewaySeconds`
# of clock skew. Claims that are absent are not enforced.
#
# + claims - The decoded claims set
# + leewaySeconds - Clock-skew tolerance in seconds
# + return - An error when the token is expired or not yet valid
public function validateTemporalClaims(map<json> claims, int leewaySeconds) returns error? {
    time:Utc now = time:utcNow();
    int nowSeconds = now[0];
    int? expValue = claimInt(claims = claims, key = "exp");
    if expValue is int {
        if nowSeconds > expValue + leewaySeconds {
            return error("token expired");
        }
    }
    int? nbfValue = claimInt(claims = claims, key = "nbf");
    if nbfValue is int {
        if nowSeconds < nbfValue - leewaySeconds {
            return error("token not yet valid");
        }
    }
}

# Rejects any header `alg` other than RS256 (blocks alg-confusion attacks).
#
# + header - The decoded JOSE header
# + return - An error when `alg` is missing or not RS256
public function requireRs256Algorithm(map<json> header) returns error? {
    string? algorithm = claimString(claims = header, key = "alg");
    if algorithm is () {
        return error("JWT header is missing alg");
    }
    if algorithm != "RS256" {
        return error("unsupported JWT algorithm: " + algorithm);
    }
}

# Returns the JOSE header `kid`, or `()` when absent.
public function jwtKeyId(map<json> header) returns string? {
    return claimString(claims = header, key = "kid");
}

# Verifies the RS256 signature over `signingInput` (`header.payload`)
# against `publicKey`.
#
# + signingInput - The exact signed bytes as a string
# + signatureSegment - The base64url signature segment
# + publicKey - The verifier's RSA public key
# + return - `true` when valid, `false` when mismatched, or an error when
#   the signature cannot be decoded
public function verifyRsa256(string signingInput, string signatureSegment,
        crypto:PublicKey publicKey) returns boolean|error {
    byte[] signature = check base64urlDecode(encoded = signatureSegment);
    return crypto:verifyRsaSha256Signature(
            data = signingInput.toBytes(),
            signature = signature,
            publicKey = publicKey);
}
