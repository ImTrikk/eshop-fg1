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

    $router->get('/users', function () use ($pdo) {
        // getUsers($pdo);
    });

    $router->get('/user/{id}', function ($id) use ($pdo) {
        // getUser($pdo, $id);
    });


    // $router->post('/user-change-password', function () use ($pdo) {
    //     changePassword($pdo);
    // });

    // $router->put('/users/{id}', function ($id) use ($pdo) {
    //     // updateUser($pdo, $id);
    // });

    // $router->delete('/users/{id}', function ($id) use ($pdo) {
    //     // deleteUser($pdo, $id);
    // });

    // $router->delete('/user-logout', function () use ($pdo) {
    //     // logoutUser($pdo);
    // });
    // Add other routes similarly...
}
