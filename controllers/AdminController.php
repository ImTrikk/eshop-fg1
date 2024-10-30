<?php


require 'vendor/autoload.php';
require_once(__DIR__ . '/../database/models/adminModels.php');

function getAllUsers($pdo)
{
 if ($_SERVER['REQUEST_METHOD'] === 'GET') {
  // Get pagination parameters from the request
  $limit = isset($_REQUEST['limit']) ? (int)$_REQUEST['limit'] : 10; // Default to 10 users per page
  $page = isset($_REQUEST['page']) ? (int)$_REQUEST['page'] : 1; // Default to page 1
  $offset = ($page - 1) * $limit; // Calculate the offset

  $adminModel = new AdminModels($pdo);
  $users = $adminModel->getAllUsers($pdo, $limit, $offset); // Pass limit and offset
  
  http_response_code(200);
  echo json_encode([
   "message" => "Users retrieved successfully!",
   "users" => $users,
  ]);
 }
}

function assignRole($pdo)
{
  if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
      // Retrieve JSON data from the request body
      $jsonData = file_get_contents("php://input");
      $data = json_decode($jsonData, true);

      // Validate that the required fields are present
      if (empty($data['email'])) {
        http_response_code(400); // Bad Request
        echo json_encode(['error' => 'Email is required.']);
        return;
      }

      if (empty($data['role'])) {
        http_response_code(400); // Bad Request
        echo json_encode(['error' => 'Role is required.']);
        return;
      }

      $email = $data['email'];
      $role = $data['role'];

      $userData = [
        'email' => $email,
        'role' => $role
      ];

      $error = validateRole($userData);
      if (!empty($error)) {
        http_response_code(400);
        echo json_encode(["errors" => $error]);
        return;
      }

      // Initialize adminModel and attempt to assign role
      $adminModel = new AdminModels($pdo);
      $user = $adminModel->assignUserRole($email, $role);

      if (!$user) {
        http_response_code(404); // Not Found
        echo json_encode(['error' => 'Role assignment failed.']);
        return;
      }

      // If successful, return a success message
      http_response_code(201); // Created
      echo json_encode(['message' => "Assigned role to user successfully", 'User' => $user]);

    } catch (PDOException $e) {
      // Handle database-related errors
      http_response_code(500); // Internal Server Error
      echo json_encode(['error' => 'Database error: ' . $e->getMessage()]);
    } catch (Exception $e) {
      // Handle general errors
      http_response_code(500); // Internal Server Error
      echo json_encode(['error' => 'An unexpected error occurred: ' . $e->getMessage()]);
    }
  }
}

function revokeRole($pdo)
{
  if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
      // Retrieve JSON data from the request body
      $jsonData = file_get_contents("php://input");
      $data = json_decode($jsonData, true);
      $email = $data['email'];
      $role = $data['role'];
 
      $userData = [
        'email' => $email,
        'role' => $role
      ];

      $error = validateRole($userData);
      if (!empty($error)) {
        http_response_code(400);
        echo json_encode(["errors" => $error]);
        return;
      }

      $adminModel = new AdminModels($pdo);
      $success = $adminModel->revokeUserRole($email, $role);

      if (!$success) {
        http_response_code(404); // Not Found
        echo json_encode(['error' => 'Failed to revoke user role.']);
        return;
      }

      // Role revoked successfully
      http_response_code(200); // OK
      echo json_encode(['message' => 'User role successfully revoked.']);
    } catch (PDOException $e) {
      // Handle database-related errors
      http_response_code(500); // Internal Server Error
      echo json_encode(['error' => 'Database error: ' . $e->getMessage()]);
    } catch (Exception $e) {
      // Handle general errors
      http_response_code(500); // Internal Server Error
      echo json_encode(['error' => 'An unexpected error occurred: ' . $e->getMessage()]);
    }
  }
}

