// The jwt-auth policy: RS256 JWT verification against a JWKS plus
// issuer/audience/scope/claim enforcement, mirroring api-platform's
// jwt-auth parameters.
//
// Authentication failures (missing/malformed/expired token, bad signature,
// issuer/audience/scope/claim mismatch) produce a configured deny response.
// Infrastructure failures (JWKS unreachable with a cold cache) propagate as
// `error` so the chain fails closed with a 403.

import ballerina/crypto;
import ballerina/http;

# allOf/anyOf scope rules (both default to empty = no requirement).
public type ScopeRules record {|
    # Every scope here must be present in the token.
    string[] allOf = [];
    # At least one scope here must be present in the token.
    string[] anyOf = [];
|};

# Tunables for the jwt-auth policy. All fields are optional in
# policies.json; unknown fields in `parameters` are rejected at load time.
public type JwtAuthParameters record {|
    # JWKS document holding the issuer's RS256 public keys (required).
    string jwksUri = "";
    # Accepted `iss` values; empty accepts any issuer.
    string[] issuers = [];
    # Accepted `aud` values (string or array claim); empty accepts any.
    string[] audiences = [];
    # Scope requirements against `scope`/`scp` claims.
    ScopeRules scopeRules = {};
    # Claim name → acceptable values; an empty list only requires presence.
    map<string[]> claims = {};
    # Request header carrying the token.
    string headerName = "Authorization";
    # Scheme prefix before the token, matched case-insensitively.
    string scheme = "Bearer";
    # Status code used for every authentication/authorization failure.
    int onFailureStatusCode = 401;
    # Fixed response body; `()` sends {"error": ..., "message": ...} JSON.
    string? errorMessage = ();
    # When true, copies the raw JWT payload segment to X-JWT-Payload upstream.
    boolean forwardToken = false;
    # Claim name → upstream request header injected on success (string claims only).
    map<string> claimMappings = {};
    # Clock-skew tolerance for exp/nbf, in seconds.
    int leeway = 60;
|};

# Builds a jwt-auth policy instance from its config spec.
#
# + spec - The policy attachment from policies.json
# + return - The policy, or a config error (missing jwksUri, bad shape)
public function createJwtAuthPolicy(PolicySpec spec) returns Policy|error {
    JwtAuthParameters params = check coerceJwtAuthParameters(rawParameters = spec.parameters);
    if params.jwksUri == "" {
        return error("jwt-auth: parameters.jwksUri is required");
    }
    return new JwtAuthPolicy(policyId = spec.name + ":" + spec.version, params = params);
}

# Verifies and authorizes bearer JWTs on the request path.
public class JwtAuthPolicy {
    private final string policyId;
    private final JwtAuthParameters params;

    public function init(string policyId, JwtAuthParameters params) {
        self.policyId = policyId;
        self.params = params;
    }

    private function name() returns string {
        return self.policyId;
    }

    private function onRequest(http:Request req, PolicyContext ctx) returns PolicyVerdict|error {
        JwtAuthParameters policyParams = self.params;

        if !req.hasHeader(headerName = policyParams.headerName) {
            return deny(authDenyResponse(params = policyParams, message = "missing authorization header"));
        }
        string|error headerValue = req.getHeader(headerName = policyParams.headerName);
        if headerValue is error {
            return deny(authDenyResponse(params = policyParams, message = "unreadable authorization header"));
        }
        string|error token = extractBearerToken(headerValue = headerValue, scheme = policyParams.scheme);
        if token is error {
            return deny(authDenyResponse(params = policyParams, message = token.message()));
        }

        JwtParts|error partsResult = splitJwt(token = token);
        if partsResult is error {
            return deny(authDenyResponse(params = policyParams, message = partsResult.message()));
        }
        JwtParts parts = partsResult;

        map<json>|error tokenHeaderResult = parseJwtSegment(segment = parts.headerSegment);
        if tokenHeaderResult is error {
            return deny(authDenyResponse(params = policyParams, message = "malformed token header"));
        }
        map<json> tokenHeader = tokenHeaderResult;
        error? algorithmResult = requireRs256Algorithm(header = tokenHeader);
        if algorithmResult is error {
            return deny(authDenyResponse(params = policyParams, message = algorithmResult.message()));
        }

        map<json>|error claimsResult = parseJwtSegment(segment = parts.payloadSegment);
        if claimsResult is error {
            return deny(authDenyResponse(params = policyParams, message = "malformed token claims"));
        }
        map<json> claims = claimsResult;

        error? temporalResult = validateTemporalClaims(claims = claims, leewaySeconds = policyParams.leeway);
        if temporalResult is error {
            return deny(authDenyResponse(params = policyParams, message = temporalResult.message()));
        }

        string? keyId = jwtKeyId(header = tokenHeader);
        JwksCachedKey[]|error candidatesResult = resolveSigningKeys(
                jwksUri = policyParams.jwksUri, keyId = keyId);
        if candidatesResult is error {
            string resolveMessage = candidatesResult.message();
            if hasPrefix(subject = resolveMessage, prefix = "JWKS unavailable") {
                // Infrastructure failure (cold cache, JWKS down) — fail closed.
                return candidatesResult;
            }
            return deny(authDenyResponse(params = policyParams, message = resolveMessage));
        }

        boolean signatureValid = false;
        foreach JwksCachedKey candidate in candidatesResult {
            boolean|error candidateValid = verifyCandidate(candidate = candidate, parts = parts);
            if candidateValid is boolean {
                if candidateValid {
                    signatureValid = true;
                    break;
                }
            }
        }
        if !signatureValid {
            return deny(authDenyResponse(params = policyParams, message = "invalid token signature"));
        }

        if policyParams.issuers.length() > 0 {
            string? issuer = claimString(claims = claims, key = "iss");
            boolean issuerAllowed = false;
            if issuer is string {
                issuerAllowed = valueAllowed(value = issuer, allowed = policyParams.issuers);
            }
            if !issuerAllowed {
                return deny(authDenyResponse(params = policyParams, message = "token issuer not allowed"));
            }
        }

        if policyParams.audiences.length() > 0 {
            if !audienceSatisfied(claims = claims, allowed = policyParams.audiences) {
                return deny(authDenyResponse(params = policyParams, message = "token audience not allowed"));
            }
        }

        string[] tokenScopeList = tokenScopes(claims = claims);
        foreach string requiredScope in policyParams.scopeRules.allOf {
            if !valueAllowed(value = requiredScope, allowed = tokenScopeList) {
                return deny(authDenyResponse(params = policyParams,
                        message = "missing required scope: " + requiredScope));
            }
        }
        if policyParams.scopeRules.anyOf.length() > 0 {
            boolean anyScopeMatched = false;
            foreach string candidateScope in policyParams.scopeRules.anyOf {
                if valueAllowed(value = candidateScope, allowed = tokenScopeList) {
                    anyScopeMatched = true;
                    break;
                }
            }
            if !anyScopeMatched {
                return deny(authDenyResponse(params = policyParams, message = "missing required scope"));
            }
        }

        foreach string claimName in policyParams.claims.keys() {
            string? claimValue = claimString(claims = claims, key = claimName);
            if claimValue is () {
                return deny(authDenyResponse(params = policyParams, message = "missing claim: " + claimName));
            }
            string[] allowedValues = policyParams.claims.get(claimName);
            if allowedValues.length() > 0 {
                if !valueAllowed(value = claimValue, allowed = allowedValues) {
                    return deny(authDenyResponse(params = policyParams,
                            message = "claim not allowed: " + claimName));
                }
            }
        }

        if policyParams.forwardToken {
            req.setHeader(headerName = "X-JWT-Payload", headerValue = parts.payloadSegment);
        }
        foreach string claimName in policyParams.claimMappings.keys() {
            string? claimValue = claimString(claims = claims, key = claimName);
            if claimValue is string {
                string targetHeader = policyParams.claimMappings.get(claimName);
                if targetHeader.length() > 0 {
                    req.setHeader(headerName = targetHeader, headerValue = claimValue);
                }
            }
        }

        string? subject = claimString(claims = claims, key = "sub");
        if subject is string {
            ctx.attributes["sub"] = subject;
        }
        string? issuerClaim = claimString(claims = claims, key = "iss");
        if issuerClaim is string {
            ctx.attributes["iss"] = issuerClaim;
        }
        ctx.attributes["scope"] = joinWithSpace(values = tokenScopeList);
        return pass();
    }
}

# Fills defaults for omitted jwt-auth parameters, deep-merging `scopeRules`,
# then converts under the strict Nutcracker rules (unknown fields rejected).
function coerceJwtAuthParameters(json rawParameters) returns JwtAuthParameters|error {
    JwtAuthParameters defaultParams = {};
    map<json> paramMap = check defaultParams.cloneWithType();
    map<json> userParams = check rawParameters.cloneWithType();

    if userParams.hasKey("scopeRules") {
        ScopeRules defaultScopes = {};
        map<json> scopeMap = check defaultScopes.cloneWithType();
        map<json> userScopesResult = check userParams.get("scopeRules").cloneWithType();
        foreach string scopeKey in userScopesResult.keys() {
            scopeMap[scopeKey] = userScopesResult.get(scopeKey);
        }
        paramMap["scopeRules"] = scopeMap;
        _ = userParams.remove("scopeRules");
    }

    foreach string paramKey in userParams.keys() {
        paramMap[paramKey] = userParams.get(paramKey);
    }
    return paramMap.fromJsonWithType();
}

# Builds the deny response: configured status, fixed or JSON body.
function authDenyResponse(JwtAuthParameters params, string message) returns http:Response {
    http:Response response = new;
    response.statusCode = params.onFailureStatusCode;
    string? customMessage = params.errorMessage;
    if customMessage is string {
        response.setTextPayload(payload = customMessage);
    } else {
        json body = {"error": "Unauthorized", "message": message};
        response.setJsonPayload(payload = body);
    }
    if params.onFailureStatusCode == 401 {
        response.setHeader(headerName = "WWW-Authenticate", headerValue = "Bearer realm=\"gateway\"");
    }
    return response;
}

# Verifies one JWKS candidate key against the token.
# Uses early-return narrowing: `is crypto:PublicKey` cannot be used because the
# runtime-produced key record fails the structural check (missing certificate field).
function verifyCandidate(JwksCachedKey candidate, JwtParts parts) returns boolean|error {
    crypto:PublicKey|error materializedKey = materializePublicKey(cachedKey = candidate);
    if materializedKey is error {
        return materializedKey;
    }
    return verifyRsa256(
            signingInput = parts.signingInput,
            signatureSegment = parts.signatureSegment,
            publicKey = materializedKey);
}

# Extracts the token after the (case-insensitive) scheme prefix.
# Errors when the prefix is absent or the token is empty.
function extractBearerToken(string headerValue, string scheme) returns string|error {
    string expectedPrefix = (scheme + " ").toLowerAscii();
    if !hasPrefix(subject = headerValue.toLowerAscii(), prefix = expectedPrefix) {
        return error("expected " + scheme + " token in " + scheme + " header");
    }
    byte[] headerBytes = headerValue.toBytes();
    int prefixLength = expectedPrefix.length();
    if headerBytes.length() <= prefixLength {
        return error("empty bearer token");
    }
    string tokenValue = check string:fromBytes(sliceBytes(
            data = headerBytes,
            startOffset = prefixLength,
            endOffset = headerBytes.length()));
    if tokenValue.length() == 0 {
        return error("empty bearer token");
    }
    return tokenValue;
}

# True when `value` appears in `allowed`.
function valueAllowed(string value, string[] allowed) returns boolean {
    foreach string candidate in allowed {
        if candidate == value {
            return true;
        }
    }
    return false;
}

# True when the `aud` claim (string or array) intersects `allowed`.
function audienceSatisfied(map<json> claims, string[] allowed) returns boolean {
    if !claims.hasKey("aud") {
        return false;
    }
    json audienceValue = claims.get("aud");
    string|error singleAudience = audienceValue.cloneWithType();
    if singleAudience is string {
        return valueAllowed(value = singleAudience, allowed = allowed);
    }
    json[]|error multipleAudiences = audienceValue.cloneWithType();
    if multipleAudiences is json[] {
        foreach json item in multipleAudiences {
            string|error audienceItem = item.cloneWithType();
            if audienceItem is string {
                if valueAllowed(value = audienceItem, allowed = allowed) {
                    return true;
                }
            }
        }
    }
    return false;
}

# Joins values with a single space (scope claim shape).
function joinWithSpace(string[] values) returns string {
    string joined = "";
    foreach int index in 0 ..< values.length() {
        if index > 0 {
            joined = joined + " ";
        }
        joined = joined + values[index];
    }
    return joined;
}
