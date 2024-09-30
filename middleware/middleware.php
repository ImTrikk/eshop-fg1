<?php

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

require_once 'database/Database.php';  // Ensure you have a file that sets up $pdo

// Middleware to check Bearer token
function checkAuthToken($pdo)
{
    // Check if the Authorization header is set
    $headers = getallheaders();
    if (!isset($headers['Authorization'])) {
        http_response_code(401);
        echo json_encode(['error' => 'Authorization header not found']);
        exit();
    }

    // Extract the Bearer token
    $authHeader = $headers['Authorization'];
    if (preg_match('/Bearer\s(\S+)/', $authHeader, $matches)) {
        $token = $matches[1];
        // Validate the token
        if (!validateToken($token, $pdo)) {
            http_response_code(403);
            echo json_encode(['error' => 'Invalid or expired token']);
            exit();
        }
    } else {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid Authorization header format']);
        exit();
    }
}

function validateToken($token, $pdo)
{
    // Your secret key (use a strong key and keep it secret)
    $secretKey = 'your_secret_key_here';

    try {
        // Decode the token
        $decoded = JWT::decode($token, new Key($secretKey, 'HS256'));

        // Extract user ID or any identifying data from the token
        $userId = $decoded->data->user_id;

        // Check the token in the database
        if (isTokenInDatabase($pdo, $userId, $token)) {
            return true; // Token is valid
        } else {
            return false; // Token not found in DB or invalid
        }
    } catch (Exception $e) {
        // Token is invalid or an error occurred
        return false;
    }
}

// Check if the token is in the database
function isTokenInDatabase($pdo, $userId, $token)
{
    // Prepare a statement to check if the token exists
    $stmt = $pdo->prepare('SELECT token FROM user_tokens WHERE user_id = :user_id AND token = :token');
    $stmt->execute([':user_id' => $userId, ':token' => $token]);

    // Check if a row was returned
    return $stmt->fetch() !== false;
}
