<?php


function authorize($role, $request, $next)
{

 if (!isset($request['user']) || $request['user']->role !== $role) {
  http_response_code(403); // Forbidden
  echo json_encode(['error' => 'Access denied']);
  exit();
 }

 // Call the next handler after successful authorization
 return $next($request);
}

// function authorize($requiredRole)
// {

//  return function ($request, $response, $next) use ($requiredRole) {
//   // Get user information from the request (set in the authentication middleware)

//   print_r("Authorize!");

//   $user = $request['user'];

//   print_r($user);
//   print_r("Users");

//   // Check if the user has the necessary role
//   if (isset($user->role) && $user->role === $requiredRole) {
//    // User is authorized, proceed to the next middleware or controller
//    return $next($request, $response);
//   } else {
//    http_response_code(403); // Forbidden
//    echo json_encode(['error' => 'Forbidden: You do not have permission to access this resource']);
//    exit();
//   }
//  };
// }