<?php

function userProfile($pdo, $user_id)
{
 if ($_SERVER['REQUEST_METHOD'] === 'GET') {
  try {
   $userModel = new UserModel($pdo);
   $user_profile = $userModel->getUserProfile($user_id);

   if ($user_profile === null) {
    http_response_code(404); // Not Found
    echo json_encode(['error' => 'User profile not found']);
    return;
   }

   http_response_code(200);
   echo json_encode(['message' => 'Retrieved user profile', 'User' => $user_profile]);
  } catch (PDOException $e) {
   // Handle database-related errors
   http_response_code(500); // Internal Server Error
   echo json_encode(['error' => 'Database error: ' . $e->getMessage()]);
  } catch (Exception $e) {
   http_response_code(500); // Internal Server Error
   echo json_encode(['error' => 'An unexpected error occurred: ' . $e->getMessage()]);
  }
 }
}

function updateProfileRequest($pdo)
{
 if ($_SERVER['REQUEST_METHOD'] === "POST") {
  $jsonData = file_get_contents(filename: "php://input");
  $data = json_decode($jsonData, true);

  $email = $data['email'];
  $error = validateEmail($email);

  if (!empty($error)) {
   http_response_code(400);
   echo json_encode(["errors" => $error]);
   return;
  }

  sendOtp($email);
 }
}

function updateProfile($user_id, $pdo)
{
 if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  try {
   $jsonData = file_get_contents("php://input");
   $data = json_decode($jsonData, true);

   // Extract data from JSON
   $firstName = $data['first_name'] ?? '';
   $lastName = $data['last_name'] ?? '';
   $contacts = $data['contacts'] ?? '';
   $email = $data['email'] ?? '';

   // Prepare the data for validation
   $userData = [
    'first_name' => $firstName,
    'last_name' => $lastName,
    'contacts' => $contacts,
    'email' => $email,
   ];

   // validate
   $error = validateUpdateProfile($userData);
   if (!empty($error)) {
    http_response_code(400);
    echo json_encode(["errors" => $error]);
    return;
   }

   $userModel = new UserModel($pdo);
   $updatedUser = $userModel->updateProfile($userData, $user_id);

   http_response_code(200);
   echo json_encode([
    "message" => "User successfully update profile",
    "user" => $updatedUser
   ]);

  } catch (Exception $e) {
   // Handle general errors
   http_response_code(500); // Internal Server Error
   echo json_encode(['error' => 'An unexpected error occurred: ' . $e->getMessage()]);
  }
 }
}
