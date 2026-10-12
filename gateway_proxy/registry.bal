# Policy registry: named factories that build policy instances from specs.

# One policy attachment from the config, e.g.
# `{"name": "jwt-auth", "version": "v1", "parameters": {...}}`.
#
# `parameters` is an opaque pass-through — the framework never inspects it.
# Each policy converts it to its own typed record with `fromJsonWithType`
# as the first thing its factory does.
public type PolicySpec record {|
    string name;
    string version = "v1";
    json parameters = {};
|};

# Builds a policy instance from its spec. Factories validate their own
# `parameters` and fail fast with a descriptive error on bad config.
public type PolicyFactory function(PolicySpec spec) returns Policy|error;

# Factories keyed by "name:version" (e.g. "jwt-auth:v1").
map<PolicyFactory> policyFactories = {};

# Registers a factory under "name:version". Overwrites an existing entry.
public function registerPolicy(string name, string version, PolicyFactory factory) {
    policyFactories[name + ":" + version] = factory;
}

# Looks up the factory and builds the policy described by `spec`.
public function createPolicy(PolicySpec spec) returns Policy|error {
    string policyKey = spec.name + ":" + spec.version;
    if !policyFactories.hasKey(policyKey) {
        return error("unknown policy: " + policyKey);
    }
    PolicyFactory factory = policyFactories.get(policyKey);
    return factory(spec);
}

# Registers the policies compiled into this gateway build.
# Called once when the policy config loads.
public function registerBuiltinPolicies() {
    registerPolicy(name = "jwt-auth", version = "v1", factory = createJwtAuthPolicy);
}
