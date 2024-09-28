<?php

require_once(__DIR__ . '/../database/models/productModel.php');

function getUserCart($pdo) {
 $user_id = $_GET['user_id'] ?? null; // Retrieve the user_id from the query parameters

 if (!$user_id) {
  http_response_code(400); // Bad Request
  echo json_encode(['error' => 'User ID is missing']);
  return;
 }

 $productModel = new ProductModel($pdo);
 $cart = $productModel->getUserCart($user_id); // Query the cart for the given user

 if ($cart) {
  echo json_encode($cart); // Return the cart data
 } else {
  http_response_code(404); // Not Found
  echo json_encode(['error' => 'Cart not found for this user']);
 }
}