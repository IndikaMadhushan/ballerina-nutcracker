import ballerina/http;
// import ballerina/log;

// base context path
service /api/v1 on new http:Listener(8080) {

    // GET /users
    resource function get users(http:Request req) returns http:Response|error {
        // log:printInfo("Received request for get /users");
        return proxy(routeKey = "GET /api/v1/users", upstreamPath = "/users", request = req);
    }

    // POST /users
    resource function post users(http:Request req) returns http:Response|error {
        // log:printInfo("Received request for post /users");
        return proxy(routeKey = "POST /api/v1/users", upstreamPath = "/users", request = req);
    }

    // GET /products
    resource function get products(http:Request req) returns http:Response|error {
        // log:printInfo("Received request for get /products");
        return proxy(routeKey = "GET /api/v1/products", upstreamPath = "/products", request = req);
    }

    // GET /products/{id}
    resource function get products/[string id](http:Request req) returns http:Response|error {
        // log:printInfo("Received request for get /products/" + id);
        return proxy(routeKey = "GET /api/v1/products/{id}", upstreamPath = "/products/" + id, request = req);
    }

    // GET /orders
    resource function get orders(http:Request req) returns http:Response|error {
        // log:printInfo("Received request for get /orders");
        return proxy(routeKey = "GET /api/v1/orders", upstreamPath = "/orders", request = req);
    }

    //POST /orders
    resource function post orders(http:Request req) returns http:Response|error {
        // log:printInfo("Received request for post /orders");
        return proxy(routeKey = "POST /api/v1/orders", upstreamPath = "/orders", request = req);
    }

    // GET /analytics
    resource function get analytics(http:Request req) returns http:Response|error {
        // log:printInfo("Received request for get /analytics");
        return proxy(routeKey = "GET /api/v1/analytics", upstreamPath = "/analytics", request = req);
    }

    //GET /health
    resource function get health(http:Request req) returns http:Response|error {
        // log:printInfo("Received request for get /health");
        return proxy(routeKey = "GET /api/v1/health", upstreamPath = "/health", request = req);
    }

    // Catchall resource function to handle any method and any path
    // resource function 'default [string... path](http:Request req) returns http:Response|error {

    //     // the relative path
    //     string targetPath = "";
    //     foreach string p in path {
    //         targetPath = targetPath + "/" + p;
    //     }

    //     //the root path
    //     if targetPath == "" {
    //         targetPath = "/";
    //     }

    //     // request to the upstream
    //     http:Response upstreamResponse = check backendClient->forward(targetPath, req);

    //     // response
    //     log:printInfo("before returning the response from upstream");
    //     return upstreamResponse;
    // }
}
