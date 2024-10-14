<?php

require_once 'router/authRoutes.php';
require_once 'router/userRoutes.php';
require_once 'controllers/AuthController.php';
// require_once 'router/productRoutes.php';
// require_once 'router/adminRoutes.php';
require_once 'controllers/productController.php';
require_once 'database/Database.php';
require_once 'router/Router.php';

// Initialize database connection
$database = new Database();
$pdo = $database->connect();

$base_url = '/eshop-fg1/api';
$request_uri = strtok(str_replace($base_url, '', $_SERVER['REQUEST_URI']), '?');
$request_method = $_SERVER['REQUEST_METHOD'];

$router = new Router(); // Initialize the Router
authRoutes($router, $pdo);
userRoutes($router, $pdo);

// Dispatch the request
$router->dispatch($request_uri, $request_method);

