<?php

// Import database connection
require 'vendor/autoload.php';
require 'database/database.php';
require 'helper/validator.php';
require 'helper/tokenHelper.php';
require 'helper/otpHelper.php';
require_once(__DIR__ . '/../database/models/userModel.php');

function register($pdo)
{
  try {
    // Check if the form is submitted via POST request
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
      // Retrieve the raw POST data
      $jsonData = file_get_contents("php://input");
      // Decode the JSON data into an associative array
      $data = json_decode($jsonData, true);

      // Extract data from JSON
      $firstName = $data['first_name'] ?? '';
      $lastName = $data['last_name'] ?? '';
      $contacts = $data['contacts'] ?? '';
      $email = $data['email'] ?? '';
      $password = $data['password'] ?? '';
      $dateOfBirth = $data['date_of_birth'] ?? '';

      // Prepare the data for validation
      $userData = [
        'first_name' => $firstName,
        'last_name' => $lastName,
        'contacts' => $contacts,
        'email' => $email,
        'password' => $password,
        'date_of_birth' => $dateOfBirth,
      ];

      // Validate user data
      $errors = validateUser($userData);

      if (!empty($errors)) {
        echo json_encode(["errors" => $errors]);
        return;
      }

      // Hash the password for security
      $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

      try {
        $userModel = new userModel(pdo: $pdo);
        $registeredUser = $userModel->registerUser($userData, $hashedPassword);

        $secretKey = ucfirst(getenv('JWT_SECRET'));

        $token = generateToken($registeredUser['user_id'], $registeredUser['role_name'], $secretKey);

        sendVerificationEmail($email, $token);

        http_response_code(201);
        echo json_encode([
          "message" => "User registered successfully! Please check your email to verify your account before logging in.",
          "user" => $registeredUser
        ]);
      } catch (PDOException $e) {
        http_response_code(500);
        echo json_encode(["error" => "Registration failed: " . $e->getMessage()]);
      }
    }
  } catch (PDOException $e) {
    http_response_code(500);
    echo json_encode(["error" => "Internal Server Error " . $e->getMessage()]);
  }
}

function login($pdo)
{
  // Check if the form is submitted via POST request
  if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Get JSON data from the request
    $jsonData = file_get_contents(filename: "php://input");
    $data = json_decode($jsonData, true);


    // todo add a validator for incoming email and password

    $email = $data['email'] ?? '';
    $password = $data['password'] ?? '';

    $userData = [
      'email' => $data['email'],
      'password' => $data['password']
    ];

    $error = validateLogin($userData);

    if (!empty($error)) {
      echo json_encode(["errors" => $error]);
      return;
    }

    // Initialize UserModel
    $userModel = new userModel(pdo: $pdo);
    // make request to check email exist in database

    $emailExist = $userModel->checkEmailExist($email);

    if (!$emailExist) {
      http_response_code(404); // Bad Request
      echo json_encode(["error" => "Email does not exist!"]);
      return;
    }

    // Basic validation
    if (empty($email) || empty($password)) {
      http_response_code(400); // Bad Request
      echo json_encode(["error" => "Email and password are required!"]);
      return;
    }

    // Fetch user by email
    $user = $userModel->getUserByEmail($email);

    if ($user['is_verified'] === 0) {
      http_response_code(403);
      echo json_encode(['error' => 'Account not verified. Please check your email to activate your account.']);
      return;
    }

    // ? need to change this for correct checking, uncomment it
    // if ($user && password_verify($password, $user['password'])) {
    if ($user && $password) {
      // Fetch additional user data (excluding the password)
      $userData = $userModel->getUserData($email);

      $secretKey = ucfirst(getenv('JWT_SECRET'));

      $token = generateToken($userData['user_id'], $userData['role_name'], $secretKey);

      unset($userData['password']);
      unset($user['password']);

      //storing token 
      $userModel->storeToken($userData['user_id'], $token, "JWT");

      setcookie('access_token', $token, [
        'expires' => time() + (3 * 60 * 60), // 3 hours
        'httponly' => true,                  // Ensures the cookie is only sent over HTTP(S)
        'samesite' => 'Strict'               // Helps prevent CSRF attacks
      ]);

      // Successful login response
      http_response_code(200); // OK
      echo json_encode([
        "message" => "Login successful!",
        "user" => $userData,
        "token" => $token // todo remove token later
      ]);
    } else {
      // Failed login
      http_response_code(401); // Unauthorized
      echo json_encode(["error" => "Invalid email or password!"]);
    }
  } else {
    // Method not allowed
    http_response_code(405); // Method Not Allowed
    echo json_encode(["error" => "Invalid request method!"]);
  }
}

function userProfile($pdo, $user_id)
{

  if ($_SERVER['REQUEST_METHOD'] === 'GET') {

    $userModel = new UserModel($pdo);
    $user_profile = $userModel->getUserProfile($user_id);

    print_r("In user profile route");

    http_response_code(200);
    echo json_encode(['message' => 'Retrieved user profile', 'User' => $user_profile]);
  }

}

function assignRole($pdo)
{
  try {
    // Check if the request method is POST
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
      http_response_code(405); // Method Not Allowed
      echo json_encode(['error' => 'Invalid request method. Only POST is allowed.']);
      return;
    }

    // Retrieve JSON data from the request body
    $jsonData = file_get_contents("php://input");
    $data = json_decode($jsonData, true);

    // Validate that the required fields are present
    // todo refactor this later
    if (empty($data['email'])) {
      http_response_code(400); // Bad Request
      echo json_encode(['error' => 'Email is required.']);
      return;
    }

    if (empty($data['role'])) {
      http_response_code(400); // Bad Request
      echo json_encode(['error' => 'Role is required.']);
      return;
    }

    $email = $data['email'];
    $role = $data['role'];

    // Initialize UserModel and attempt to assign role
    $userModel = new UserModel($pdo);
    $user = $userModel->assignUserRole($email, $role);

    if (!$user) {
      http_response_code(404); // Not Found
      echo json_encode(['error' => 'User not found or role assignment failed.']);
      return;
    }

    // If successful, return a success message
    http_response_code(201); // Created
    echo json_encode(['message' => "Assigned role to user successfully", 'User' => $user]);

  } catch (PDOException $e) {
    // Handle database-related errors
    http_response_code(500); // Internal Server Error
    echo json_encode(['error' => 'Database error: ' . $e->getMessage()]);
  } catch (Exception $e) {
    // Handle general errors
    http_response_code(500); // Internal Server Error
    echo json_encode(['error' => 'An unexpected error occurred: ' . $e->getMessage()]);
  }
}

function revokeRole($pdo)
{
  if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
      // Retrieve JSON data from the request body
      $jsonData = file_get_contents("php://input");
      $data = json_decode($jsonData, true);
      $email = $data['email'];
      $role = $data['role'];

      //todo add validation

      $userModel = new UserModel($pdo);
      $success = $userModel->revokeUserRole($email, $role);

      if (!$success) {
        http_response_code(404); // Not Found
        echo json_encode(['error' => 'Failed to revoke user role.']);
        return;
      }

      // Role revoked successfully
      http_response_code(200); // OK
      echo json_encode(['message' => 'User role successfully revoked.']);
    } catch (PDOException $e) {
      // Handle database-related errors
      http_response_code(500); // Internal Server Error
      echo json_encode(['error' => 'Database error: ' . $e->getMessage()]);
    } catch (Exception $e) {
      // Handle general errors
      http_response_code(500); // Internal Server Error
      echo json_encode(['error' => 'An unexpected error occurred: ' . $e->getMessage()]);
    }
  }
}

function passwordResetRequest()
{
  // send otp to user's email
  if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $jsonData = file_get_contents(filename: "php://input");
    $data = json_decode($jsonData, true);

    $email = $data['email'];

    sendOtp($email);
  }
}

function passwordReset($pdo)
{
  if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Get JSON input
    $jsonData = file_get_contents("php://input");
    $data = json_decode($jsonData, true);

    // Extract data from the request
    $otp = $data['otp'] ?? null;
    $email = $data['email'] ?? null;
    $password = $data['password'] ?? null;

    // Validate inputs
    if (!$otp || !$email || !$password) {
      echo json_encode(['error' => 'Missing required fields']);
      return;
    }

    $userReset = [
      'otp' => $data['otp'],
      'email' => $data['email'],
      'password' => $data['password']
    ];

    $errors = validateResetPassword($userReset);

    if (!empty($errors)) {
      echo json_encode(["errors" => $errors]);
      return;
    }

    // Verify the OTP and stop execution if it fails
    if (!verifyOtp($otp)) {
      return; // Stop execution if OTP is invalid
    }

    // Hash the new password
    $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

    // Create an instance of UserModel
    $userModel = new UserModel($pdo);

    // Update the password in the database
    if ($userModel->updatePassword($email, $hashedPassword)) {
      echo json_encode(['message' => 'Password updated successfully']);
    } else {
      echo json_encode(['error' => 'Failed to update password']);
    }
  } else {
    echo json_encode(['error' => 'Invalid request method']);
  }
}


// todo work in here  for email verification
// user clicks link directed to localhost then it should make reques to verify with the token
function verifyUserRequest($user_id, $pdo)
{
  // send OTP to email
  if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $jsonData = file_get_contents(filename: "php://input");
    $data = json_decode($jsonData, true);

    $email = $data['email'];

    $userModel = new UserModel($pdo);
    $userData = $userModel->getUserData($email);

    // get secret key
    $secretKey = ucfirst(getenv('JWT_SECRET'));

    $token = generateToken($userData['user_id'], $userData['role_name'], $secretKey);

    // store token in the data base with EMAIL_VERIFICATION TAG


    $userModel = new UserModel($pdo);
    $userModel->storeToken($user_id, $token, "EMAIL_VERIFICATION");

    // sendEmailVerification
    sendVerificationEmail($email, $token);
    // sendOtp($email);
  }
}

function verifyUser($token, $pdo)
{
  // Ensure the request is a GET request
  if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $token = basename($_SERVER['REQUEST_URI']);

    // Check if token is missing
    if (!$token) {
      http_response_code(400);
      echo json_encode(['error' => 'Token is missing']);
      return;
    }
    // Verify token
    try {
      $decodedToken = verifyToken($token);
      $user_id = $decodedToken->user_id; // Use object property access

    } catch (Exception $e) {
      http_response_code(401); // Unauthorized
      echo json_encode(['error' => 'Invalid or expired token', 'message' => $e->getMessage()]);
      return;
    }

    $userModel = new UserModel($pdo);
    $verificationResult = $userModel->verifyEmail($token, $user_id); // Pass the user_id

    if ($verificationResult['status'] === 'success') {
      // Email verified successfully
      http_response_code(200);
      echo json_encode(['message' => 'Email verified successfully']);
    } else {
      // Email verification failed (e.g., token expired or already used)
      http_response_code(400);
      echo json_encode(['error' => $verificationResult['message']]);
    }
  } else {
    // Invalid request method
    http_response_code(405);
    echo json_encode(['error' => 'Invalid request method. Only GET is allowed.']);
  }
}


// TODO: not working yet, needs testing and validation
function logout($user_id, $pdo)
{
  // Handle logout logic, e.g., clearing session data
  session_start();
  session_destroy();

  $userModel = new UserModel($pdo);
  $userModel->logoutModel($user_id);

  echo json_encode(["message" => "Logged out successfully!"]);
}

function profileUpload($user_id, $pdo)
{
  if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // GET FILE UPLOAD 
  }
}