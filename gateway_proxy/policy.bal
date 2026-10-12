import ballerina/http;

# Context passed to every policy while processing a single request.
public type PolicyContext record {|
    # Route key that selected this chain (e.g. "GET /api/v1/users" or "*").
    string routeKey;
    # Values shared between policies for this request
    # (e.g. parsed JWT claims for downstream policies).
    map<string> attributes;
|};

# Verdict returned by a policy's onRequest hook.
public type PolicyVerdict record {|
    # true → continue to the next policy; false → stop the chain
    # and return `response` to the client.
    boolean allowed;
    # Response returned to the client when `allowed` is false.
    http:Response? response = ();
|};

# Creates an empty request context for the given route key.
public isolated function newPolicyContext(string routeKey) returns PolicyContext {
    return {routeKey: routeKey, attributes: {}};
}

# Verdict that lets the request continue to the next policy / upstream.
public isolated function pass() returns PolicyVerdict {
    return {allowed: true};
}

# Verdict that stops the chain and returns the given response to the client.
public isolated function deny(http:Response response) returns PolicyVerdict {
    return {allowed: false, response: response};
}

# Contract implemented by every gateway policy.
#
# Any object with these two methods conforms structurally — policies do not
# need to explicitly extend this type.
public type Policy object {
    # Stable identity of the policy implementation (e.g. "jwt-auth").
    function name() returns string;

    # Runs before the request is proxied upstream.
    #
    # + return - `pass()` to continue, `deny(response)` to short-circuit,
    #            or an `error` for unexpected failures (chain aborts).
    function onRequest(http:Request req, PolicyContext ctx) returns PolicyVerdict|error;
};
