<?php
require 'vendor/autoload.php';

use \Firebase\JWT\JWT;
use \Firebase\JWT\Key;


function generateToken($userId, $secretKey){ 

 $expirationTime = 3600;

 $issuedAt = time();
 $expirationTime = $issuedAt + $expirationTime;
 $payload = [
  'iat' => $issuedAt, // Issued at
  'exp' => $expirationTime, // Expiration time
  'userId' => $userId // User identifier
 ];

 return JWT::encode($payload, $secretKey, 'HS256');
}

function verifyToken($token){
  try{

  $secret_key = ucfirst(getenv('JWT_SECRET'));  

   $decoded = JWT::decode($token, new Key($secret_key, 'HS256'));

   print_r($decoded);

   http_response_code(200);
   echo json_encode(["Success" => ""]);

  } catch(Exception $e){
   http_response_code(403);
   echo json_encode(["Error" => "Invalid token or expired token"]);
  }
}