<?php
require 'vendor/autoload.php';

use \Firebase\JWT\JWT;
use \Firebase\JWT\Key;


function generateToken($userId, $role_name, $secretKey)
{

    $expirationTime = 3600 * 3;

    $issuedAt = time();
    $expirationTime = $issuedAt + $expirationTime;
    $payload = [
        'iat' => $issuedAt,
        'exp' => $expirationTime,
        'user_id' => $userId,
        'role' => $role_name
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
            return $userId;
        } else {
            return false;
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

// verifying token

function verifyToken($token)
{
    $secretKey = ucfirst(getenv('JWT_SECRET'));

    try {
        // Decode the token and check for expiration
        $decoded = JWT::decode($token, new Key($secretKey, 'HS256'));

        // Set HTTP response code for successful verification
        return $decoded;
    } catch (\Firebase\JWT\ExpiredException $e) {
        // Handle token expiration
        http_response_code(401); // Unauthorized
        return json_encode(['error' => "Token has expired"]);
    } catch (\Exception $e) {
        // Handle other errors (e.g., signature invalid, token malformed)
        http_response_code(401); // Unauthorized
        return json_encode(['error' => 'Invalid token: ' . $e->getMessage()]);
    }
}

