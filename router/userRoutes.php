<?php


function userRoutes($router, $pdo)
{
    $router->post('/user-create', function () use ($pdo) {
        register($pdo);
    });

    $router->post('/user-login', function () use ($pdo) {
        login($pdo);
    });

    $router->post('/user-send-otp', function () use ($pdo) {
        sendOtp();
    });

    $router->get('/user/cart/{id}', function ($id) use ($pdo) {
        getUserCart($pdo, $id);
    });
}
