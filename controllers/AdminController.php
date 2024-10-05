<?php


require_once 'database/models/adminModels.php';

function getAllUsers($pdo)
{
 if ($_SERVER['REQUEST_METHOD'] === 'GET') {
  $adminModel = new AdminModels($pdo);
  $users = $adminModel->getAllUsers($pdo);
  
  http_response_code(200);
  echo json_encode([
   "message" => "Login successful!",
   "users" => $users,
  ]);
 }
}