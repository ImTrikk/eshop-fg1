<?php

function userRoutes($router, $pdo)
{
    // ====================== USER PROFILE MANAGEMENT ==================== //
    $router->get('/auth/user/profile/{id}', function ($id) use ($pdo) {
        authenticate($_REQUEST, function ($request) use ($pdo, $id) {
            authorize(['Admin', 'Buyer', 'Seller'], $request, function ($request) use ($id, $pdo) {
                // Ensure that non-admin users can only access their own profile
                if ($request['user']->role !== 'Admin') {
                    authorizeUser($request, $id, function ($request) use ($pdo, $id) {
                        userProfile($pdo, $id);
                    });
                } else {
                    // Admin can view any profile
                    userProfile($pdo, $id);
                }
            });
        });
    });

    $router->get('/user/cart/{id}', function ($id) use ($pdo) {
        authenticate($_REQUEST, function ($request) use ($id, $pdo) {
            authorize(['Admin', 'Seller', 'Buyer'], $request, function ($request) use ($id, $pdo) {
                // If the user is not an Admin, they can only view their own cart
                if ($request['user']->role !== 'Admin') {
                    authorizeUser($request, $id, function ($request) use ($pdo, $id) {
                        getUserCart($pdo, $id);
                    });
                } else {
                    // Admin can view any user's cart
                    getUserCart($pdo, $id);
                }
            });
        });
    });

    $router->post('/user/profile/update/{id}', function ($id) use ($pdo) {
        authenticate($_REQUEST, function ($request) use ($pdo, $id) {
            authorize(['Admin', 'Seller', 'Buyer'], $request, function ($request) use ($pdo, $id) {
                authorizeUser($request, $id, function ($request) use ($pdo, $id) {
                    updateProfile($id, $pdo);
                });
            });
        });
    });
}