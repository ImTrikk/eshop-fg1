<?php

function checkUserRole($requiredRole) {
 // Check if the user is logged in
 if (!isset($_SESSION['user_role'])) {
  http_response_code(403);
  echo json_encode(['error' => 'Access denied. User not authenticated.']);
 } 

 // Check if the user has the right role
 if ($_SESSION['user_role'] !== $requiredRole) {
  http_response_code(403);
  echo json_encode(['error' => 'Access denied. Insufficient permissions.']);
 }
}

function authMiddleware($pdo) {
 session_start(); // Start the session if not already started
 
 // Check if user is authenticated
 if (!isset($_SESSION['user_id'])) {
  http_response_code(401); // Unauthorized
  echo json_encode(['error' => 'Unauthorized']);
  exit; // Stop execution
 }
}