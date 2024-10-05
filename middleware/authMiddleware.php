<?php
require 'vendor/autoload.php';
use Firebase\JWT\JWT;
use Firebase\JWT\Key;


function authenticate($request, $next)
{
 // Get headers from the request
 $headers = getallheaders();

 // Check if 'Authorization' header is present
 if (!isset($headers['Authorization'])) {
  http_response_code(401); // Unauthorized
  echo json_encode(['error' => 'Missing Authorization header']);
  exit();
 }

 // Extract the token from the 'Authorization' header
 if (preg_match('/Bearer\s(\S+)/', $headers['Authorization'], $matches)) {
  $token = $matches[1];
 } else {
  http_response_code(400); // Bad request
  echo json_encode(['error' => 'Invalid Authorization header format']);
  exit();
 }

 // Define the secret key from your environment variables
 $secretKey = ucfirst(getenv('JWT_SECRET'));

 try {
  // Decode the JWT using the secret key
  $decodedToken = JWT::decode($token, new Key($secretKey, 'HS256'));

  // Attach user info to request (or use session/global)
  $request['user'] = $decodedToken;

  // Call the next middleware or controller
  return $next($request);

 } catch (Exception $e) {
  // Handle token validation failure
  http_response_code(401); // Unauthorized
  echo json_encode([
   'error' => 'Unauthorized: Invalid or expired token',
   'message' => $e->getMessage()
  ]);
  exit();
 }
}