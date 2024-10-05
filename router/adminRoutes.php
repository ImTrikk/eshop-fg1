<?php

require_once 'middleware/AuthMiddleware.php';
require_once 'middleware/roleMiddleware.php';
require_once 'controllers/AdminController.php';

function adminRoutes($router, $pdo)
{
 $router->get('/get-users', function () use ($pdo) {
  // Authenticate user
  authenticate($_REQUEST, function ($request) use ($pdo) {
   // Authorize based on role
   authorize('Admin', $request, function ($request) use ($pdo) {
    getAllUsers($pdo);
   });
  });
 });
}