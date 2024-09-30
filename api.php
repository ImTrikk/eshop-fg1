<?php
// index.php

// Define the base URL for the API
$base_url = '/eshop-fg1/api';

// Get the request URI and method, remove the query string from the URI
$request_uri = strtok(str_replace($base_url, '', $_SERVER['REQUEST_URI']), '?');
$request_method = $_SERVER['REQUEST_METHOD'];

// Include the file with your middleware and handler functions
require_once 'middleware/middleware.php';   // Middleware for token validation
require_once 'controllers/AuthController.php';  // User-related handlers
require_once 'controllers/productController.php';  // Product-related handlers

// Define available routes
$routes = [
    'GET' => [
        '/get-user-cart' => 'getUserCart',
        '/users' => 'getUsers',
        '/users/{id}' => 'getUser',
    ],
    'POST' => [
        '/user-create' => 'register',
        '/user-login' => 'login'
    ],
    'PUT' => [
        '/users/{id}' => 'updateUser',
    ],
    'DELETE' => [
        '/users/{id}' => 'deleteUser',
        '/user-logout' => 'logoutUser'
    ],
];


// Find the matching route
$matched_route = null;
$matches = [];

foreach ($routes[$request_method] as $route => $handler) {
    $pattern = preg_replace('/\{[a-zA-Z]+\}/', '([0-9]+)', $route);
    if (preg_match("#^$pattern$#", $request_uri, $matches)) {
        $matched_route = $handler;
        array_shift($matches); // Remove the full match from $matches
        break;
    }
}

if ($matched_route) {
    if (function_exists($matched_route)) {
        // Check if the route is protected and requires a token (Add more routes as needed)
        $protected_routes = ['/get-user-cart'];

        if (in_array($request_uri, $protected_routes)) {
            checkAuthToken($pdo);  // Middleware to check for Bearer token
        }

        // Call the handler function
        call_user_func_array($matched_route, array_merge([$pdo], $matches));
    } else {
        http_response_code(500);
        echo json_encode(['error' => 'Handler not defined']);
    }
} else {
    http_response_code(404);
    echo json_encode(['error' => 'Route not found']);
}
