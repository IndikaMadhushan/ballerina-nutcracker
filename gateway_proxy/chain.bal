import ballerina/http;
import ballerina/io;
import ballerina/log;
import ballerina/os;

# One route's attachment list in policies.json, e.g.
# `{"routeKey": "GET /api/v1/users", "policies": [...]}`.
# `policies` is mandatory — write `[]` for a public route.
public type RoutePolicyConfig record {|
    string routeKey;
    PolicySpec[] policies;
|};

# Root shape of policies.json.
public type GatewayPolicyConfig record {|
    RoutePolicyConfig[] routes;
    json systemParameters;
|};

# A route with its fully constructed policy instances.
public type CompiledChain record {|
    string routeKey;
    Policy[] policies;
|};

# Compiled chains for exact route keys ("GET /api/v1/users").
map<CompiledChain> exactChains = {};
# The wildcard ("*") chain, if configured.
CompiledChain? wildcardChain = ();
# True once policies.json has been loaded successfully.
boolean configLoaded = false;
# System-wide parameters passed to policies (keyManagers, leeway, ...).
# Opaque to the framework — each policy converts it to its own record.
json systemParameters = {};

# Fills defaults for omitted top-level fields, then converts with the
# strict Nutcracker rules (every declared field present, unknown rejected).
function coerceConfig(json rawConfig) returns GatewayPolicyConfig|error {
    map<json> configMap = check rawConfig.cloneWithType();
    if !configMap.hasKey("routes") {
        configMap["routes"] = [];
    }
    if !configMap.hasKey("systemParameters") {
        configMap["systemParameters"] = {};
    }
    return configMap.fromJsonWithType();
}

# Loads, validates and compiles policies.json. Fails on the first bad entry:
# unknown policy name, invalid parameters, duplicate route key.
public function loadPolicyConfig(string configPath) returns error? {
    json rawConfig = check io:fileReadJson(path = configPath);
    GatewayPolicyConfig config = check coerceConfig(rawConfig);
    registerBuiltinPolicies();

    map<CompiledChain> nextExactChains = {};
    CompiledChain? nextWildcardChain = ();
    foreach RoutePolicyConfig routeConfig in config.routes {
        Policy[] policies = [];
        foreach PolicySpec spec in routeConfig.policies {
            Policy policy = check createPolicy(spec);
            policies.push(policy);
        }
        CompiledChain compiledChain = {routeKey: routeConfig.routeKey, policies: policies};
        if routeConfig.routeKey == "*" {
            nextWildcardChain = compiledChain;
        } else {
            if nextExactChains.hasKey(routeConfig.routeKey) {
                return error("duplicate routeKey in policy config: " + routeConfig.routeKey);
            }
            nextExactChains[routeConfig.routeKey] = compiledChain;
        }
    }

    exactChains = nextExactChains;
    wildcardChain = nextWildcardChain;
    systemParameters = config.systemParameters;
    configLoaded = true;
    log:printInfo("Policy config loaded",
        configPath = configPath,
        routeCount = nextExactChains.length());
}

# Loads the config on first use. Path comes from the POLICY_CONFIG
# environment variable, defaulting to policies.json next to the binary.
public function ensureConfigLoaded() returns error? {
    if configLoaded {
        return;
    }
    string configPath = os:getEnv(name = "POLICY_CONFIG");
    if configPath == "" {
        configPath = "policies.json";
    }
    check loadPolicyConfig(configPath);
}

# Returns the chain for this route key: exact "METHOD /path" match first,
# then the "*" wildcard. `()` when neither exists (callers proxy without policies).
public function findChain(string routeKey) returns CompiledChain? {
    if exactChains.hasKey(routeKey) {
        CompiledChain exactChain = exactChains.get(routeKey);
        return exactChain;
    }
    return wildcardChain;
}

# Returns the loaded system parameters (for policies that need them).
public function getSystemParameters() returns json {
    return systemParameters;
}

# Runs every policy's onRequest hook in order.
# Returns the deny response (execution stopped) or `()` to proceed upstream.
# Fails closed: a policy that denies without supplying a response gets a 403.
public function executeChain(Policy[] policies, http:Request request, PolicyContext context)
        returns http:Response?|error {
    foreach Policy policy in policies {
        PolicyVerdict verdict = check policy.onRequest(request, context);
        if !verdict.allowed {
            http:Response? denyResponse = verdict.response;
            if denyResponse is http:Response {
                return denyResponse;
            }
            http:Response fallbackResponse = new;
            fallbackResponse.statusCode = 403;
            fallbackResponse.setTextPayload(payload = "Forbidden");
            return fallbackResponse;
        }
    }
    return ();
}
