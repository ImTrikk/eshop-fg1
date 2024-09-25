<?php

require 'vendor/autoload.php';

use \Firebase\JWT\JWT;

function generateToken($userId, $secretKey){ 

 $expirationTime = 3600;

 $issuedAt = time();
 $expirationTime = $issuedAt + $expirationTime;
 $payload = [
  'iat' => $issuedAt, // Issued at
  'exp' => $expirationTime, // Expiration time
  'userId' => $userId // User identifier
 ];

 return JWT::encode($payload, $secretKey);
}

function verifyToken($token){
 
}