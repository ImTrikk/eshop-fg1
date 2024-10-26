<?php

require_once 'middleware/AuthMiddleware.php';
require_once 'middleware/roleMiddleware.php';
require_once 'controllers/AdminController.php';

function adminRoutes($router, $pdo)
{
  $router->get('/get-all-users', function () use ($pdo) {
    authenticate($_REQUEST, function ($request) use ($pdo) {
      authorize('Admin', $request, function ($request) use ($pdo) {
        getAllUsers($pdo);
      });
    });
  });

  $router->post('/auth/role/assign', function () use ($pdo) {
    authenticate($_REQUEST, function ($request) use ($pdo) {
      authorize('Admin', $request, function ($request) use ($pdo) {
        assignRole($pdo);
      });
    });
  });

  $router->post('/auth/role/revoke', function () use ($pdo) {
    authenticate($_REQUEST, function ($request) use ($pdo) {
      authorize('Admin', $request, function ($request) use ($pdo) {
        revokeRole($pdo);
      });
    });
  });
}