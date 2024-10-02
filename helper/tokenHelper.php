<?php
require 'vendor/autoload.php';

use \Firebase\JWT\JWT;
use \Firebase\JWT\Key;


function generateToken($userId, $secretKey)
{

  $expirationTime = 3600 * 3;

  $issuedAt = time();
  $expirationTime = $issuedAt + $expirationTime;
  $payload = [
    'iat' => $issuedAt,
    'exp' => $expirationTime,
    'userId' => $userId
  ];

  return JWT::encode($payload, $secretKey, 'HS256');
}

// require_once 'database/Database.php';


// Middleware to check Bearer token and extract user ID
function checkAuthToken($pdo, $id)
{
    $headers = getallheaders();
    if (!isset($headers['Authorization'])) {
        http_response_code(401);
        echo json_encode(['error' => 'Unauthorized user!']);
        exit();
    }

    $authHeader = $headers['Authorization'];
    if (preg_match('/Bearer\s(\S+)/', $authHeader, $matches)) {
        $token = $matches[1];

        $user_id = $id;

        // Validate the token and return the user ID
        $userId = validateToken($token, $pdo, $user_id);

        if (!$userId) {
            http_response_code(403);
            echo json_encode(value: ['error' => 'Unauthorized user!']);
            exit();
        }
        return $userId; // Return the user ID if token is valid
    } else {
        http_response_code(400);
        echo json_encode(value: ['error' => 'Invalid Authorization header format']);
        exit();
    }
}

// Validate the token and return the user ID
function validateToken($token, $pdo, $user_id)
{
    $secretKey = ucfirst(getenv('JWT_SECRET')); // Your secret key from env


    try {
        // Decode the token
        $decoded = JWT::decode($token, new Key($secretKey, 'HS256'));

        // Extract the user ID from the token
        $userId = $decoded->userId;

        

        if ($user_id !== $userId) {
            return false;
        }

        // Check if the token exists in the database
        if (isTokenInDatabase($pdo, $userId, $token)) {
            return $userId; // Token is valid, return the user ID
        } else {
            return false; // Token not found in DB or invalid
        }

    } catch (Exception $e) {
        // Token is invalid or expired
        echo json_encode([
            'error' => 'Unauthorized user!',
            'message' => $e->getMessage()
        ]);

        http_response_code(401);
        exit();
    }
}


// Optional: Check if the token is in the database
function isTokenInDatabase($pdo, $userId, $token)
{
    $stmt = $pdo->prepare('SELECT token FROM user_tokens WHERE user_id = :user_id AND token = :token');
    $stmt->execute([':user_id' => $userId, ':token' => $token]);
    return $stmt->fetch() !== false;
}
