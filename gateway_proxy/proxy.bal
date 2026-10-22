import ballerina/http;
import ballerina/os;

// Resolves the upstream base URL: the UPSTREAM_URL env var when set,
// otherwise the docker-compose service name.
function resolveUpstreamUrl() returns string {
    string configuredUrl = os:getEnv(name = "UPSTREAM_URL");
    if configuredUrl == "" {
        return "http://mock-backend-service:8688";
    }
    return configuredUrl;
}

// target upstream URL
final string UPSTREAM_URL = resolveUpstreamUrl();

// Initialize the HTTP Client
final http:Client backendClient = check new (UPSTREAM_URL, {
    httpVersion: http:HTTP_1_1,
    poolConfig: {
        maxActiveConnections: 1000,
        maxIdleConnections: 2000,
        waitTime: 90
    }
});

# Runs the policy chain for `routeKey`, then forwards the request upstream.
#
# Returns the policy deny response as-is when the chain stops, otherwise the
# upstream response. Config errors (bad policies.json, unknown policy) surface
# as an `error` — the resource turns them into a 500.
#
# + routeKey - Policy route key, e.g. "GET /api/v1/users"
# + upstreamPath - Path to forward to, e.g. "/users"
# + request - The inbound request, forwarded unchanged after policies run
public function proxy(string routeKey, string upstreamPath, http:Request request)
        returns http:Response|error {
    check ensureConfigLoaded();
    PolicyContext context = newPolicyContext(routeKey = routeKey);
    CompiledChain? chain = findChain(routeKey = routeKey);
    if chain is CompiledChain {
        http:Response? denyResponse = check executeChain(
                policies = chain.policies,
                request = request,
                context = context);
        if denyResponse is http:Response {
            return denyResponse;
        }
    }
    return backendClient->forward(path = upstreamPath, request = request);
}
