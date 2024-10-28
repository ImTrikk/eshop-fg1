<?php

require_once __DIR__ . '/../middleware/authMiddleware.php';
require_once __DIR__ . '/../middleware/roleMiddleware.php';

function authRoutes($router, $pdo)
{
    // ====================== AUTHENTICATION ==================== //
    $router->post('/auth/register', function () use ($pdo) {
        register($pdo);
    });

    $router->post('/auth/login', function () use ($pdo) {
        login($pdo);
    });

    $router->post('/auth/password/reset/request', function () use ($pdo) {
        passwordResetRequest();
    });

    $router->post('/auth/password/reset', function () use ($pdo) {
        passwordReset($pdo);
    });

    $router->post('/auth/logout/{id}', function ($id) use ($pdo) {
        authenticate($_REQUEST, function ($request) use ($pdo) {
            authorize(['Admin', 'Buyer', 'Seller'], $_REQUEST, function ($id) use ($pdo) {
                logout($id, $pdo);
            });
        });
    });

    // ====================== AUTHORIZATION ==================== //
    $router->post('/auth/verify/request/{id}', function ($id) use ($pdo) {
        authenticate($_REQUEST, function ($request) use ($pdo, $id) {
            authorize('Seller', $request, function ($request) use ($id, $pdo) {
                verifyUserRequest($id, $pdo);
            });
        });
    });

    $router->get('/auth/verify-email/{token:[a-zA-Z0-9-_\.]+}', function ($token) use ($pdo) {
        verifyUser($token, $pdo, );
    });
}


