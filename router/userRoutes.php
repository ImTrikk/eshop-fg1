<?php

function userRoutes($router, $pdo)
{
    // ====================== USER PROFILE MANAGEMENT ==================== //
    // $router->get('/auth/user/profile/{id}', function ($id) use ($pdo) {
    //     authenticate($_REQUEST, function ($request) use ($pdo, $id) {
    //         authorizeUser($request, $id, function () use ($pdo, $id) {
    //             userProfile($pdo, $id);
    //         });
    //     });
    // });

    // todo refactor code for authorization
    $router->get('/auth/user/profile/{id}', function ($id) use ($pdo) {
        authenticate($_REQUEST, function ($request) use ($pdo, $id) {
            authorize(['Buyer', 'Seller'], $id, function () use ($pdo, $id) {
                userProfile($pdo, $id);
            });
        });
    });

    $router->post('/user/profile/update', function ($id) use ($pdo) {
        authenticate($_REQUEST, function ($request) use ($pdo, $id) {
            authorizeUser($request, $id, function () use ($pdo, $id) {
                // update user profile logic here
            });
        });
    });

    // Shipping address routes
    $router->post('/user/address/add', function ($id) use ($pdo) {
        authenticate($_REQUEST, function ($request) use ($pdo, $id) {
            authorize('Buyer', $request, function () use ($pdo, $id) {
                addAddress($pdo);
            });
        });
    });

    $router->post('/user/address/update', function ($id) use ($pdo) {
        authenticate($_REQUEST, function ($request) use ($pdo, $id) {
            authorizeUser($request, $id, function () use ($pdo, $id) {
                // update user address logic here
            });
        });
    });

    $router->post('/user/address/remove', function ($id) use ($pdo) {
        authenticate($_REQUEST, function ($request) use ($pdo, $id) {
            authorizeUser($request, $id, function () use ($pdo, $id) {
                // remove user address logic here
            });
        });
    });

    // Photo upload
    $router->post('/user/photo/upload', function ($id) use ($pdo) {
        authenticate($_REQUEST, function ($request) use ($pdo, $id) {
            authorizeUser($request, $id, function () use ($pdo, $id) {
                // upload user photo logic here
            });
        });
    });
}
