<?php

function productRoutes($router, $pdo)
{
 $router->get('/get-user-cart/{id}', function ($id) use ($pdo) {
  checkAuthToken($pdo, $id);
  getUserCart($pdo, $id);
 });
}