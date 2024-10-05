<?php


function authorize($role, $request, $next)
{

 if (!isset($request['user']) || $request['user']->role !== $role) {
  http_response_code(403); // Forbidden
  echo json_encode(['error' => 'Access denied']);
  exit();
 }

 return $next($request);
}

function authorizeUser($request, $id, $next)
{

 // Ensure the user is authenticated
 if (!isset($request['user'])) {
  http_response_code(403); // Forbidden
  echo json_encode(['error' => 'Access denied: No user information found']);
  exit();
 }

 // Extract the user_id from the JWT (attached by authenticate middleware)
 $tokenUserId = $request['user']->userId; // Correct key in the JWT token

 // Compare the user_id from the URL ($id) with the user_id from the JWT token
 if ($id !== $tokenUserId) {
  http_response_code(403); // Forbidden
  echo json_encode(['error' => 'Access denied: Unauthorized user']);
  exit();
 }

 // Call the next middleware or controller if the user is authorized
 return $next($request);
}
