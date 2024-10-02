<?php

require_once 'router/userRoutes.php'; // Include the Router class
require_once 'router/productRoutes.php'; // Include the Router class
require_once 'middleware/middleware.php';   // Middleware for token validation
require_once 'controllers/AuthController.php';  // User-related handlers
require_once 'controllers/productController.php';  // Product-related handlers
require_once 'database/Database.php'; // Include your database connection class
require_once 'router/Router.php';

// Initialize database connection
$database = new Database();  // Assuming your Database class is properly set up
$pdo = $database->connect(); // This should return a PDO connection

$base_url = '/eshop-fg1/api';
$request_uri = strtok(str_replace($base_url, '', $_SERVER['REQUEST_URI']), '?');
$request_method = $_SERVER['REQUEST_METHOD'];

$router = new Router(); // Initialize the Router



registerUserRoutes($router, $pdo);
productRoutes($router, $pdo);

// Dispatch the request
$router->dispatch($request_uri, $request_method);

