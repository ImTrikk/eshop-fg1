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
  if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
      // Check if the form is submitted via POST request
      $jsonData = file_get_contents("php://input");
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
      $errors = validateRegistration($userData);

      // check email exist in db
      $userModel = new UserModel($pdo);
      $emailExist = $userModel->checkEmailExist($email);

      if ($emailExist) {
        // If the email exists, return an error response
        http_response_code(400); // Bad Request
        echo json_encode(['error' => 'Email already exists!']);
        return;
      }

      if (!empty($errors)) {
        http_response_code(403);
        echo json_encode(["errors" => $errors]);
        return;
      }

      // Hash the password for security
      $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

      try {
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
        http_response_code(400);
        echo json_encode(["error" => "Registration failed: " . $e->getMessage()]);
      }
    } catch (PDOException $e) {
      http_response_code(500);
      echo json_encode(["error" => "Internal Server Error " . $e->getMessage()]);
    }
  }
}

function login($pdo)
{
  if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
      // Start the session
      session_start();

      // Get JSON data from the request
      $jsonData = file_get_contents("php://input");
      $data = json_decode($jsonData, true);

      $email = $data['email'] ?? '';
      $password = $data['password'] ?? '';

      $userData = [
        'email' => $data['email'],
        'password' => $data['password']
      ];

      // Validate input
      $error = validateLogin($userData);

      if (!empty($error)) {
        http_response_code(400);
        echo json_encode(["errors" => $error]);
        return;
      }

      // Initialize UserModel
      $userModel = new userModel($pdo);
      $emailExist = $userModel->checkEmailExist($email);

      if (!$emailExist) {
        http_response_code(404);
        echo json_encode(["error" => "Email does not exist!"]);
        return;
      }

      // Fetch user by email
      $user = $userModel->getUserByEmail($email);

      if ($user['is_verified'] === 0) {
        http_response_code(403);
        echo json_encode(['error' => 'Account not verified. Please check your email to activate your account.']);
        return;
      }

      // Verify password
      // if ($user && password_verify($password, $user['password'])) {
        if($user){
        // Fetch additional user data (excluding the password)
        $userData = $userModel->getUserData($email);

        // Start session and store user ID
        $_SESSION['user_id'] = $userData['user_id'];

        $secretKey = ucfirst(getenv('JWT_SECRET'));
        $token = generateToken($userData['user_id'], $userData['role_name'], $secretKey);

        unset($userData['password']);
        unset($user['password']);

        // Storing token 
        $userModel->storeToken($userData['user_id'], $token, "JWT");

        // Set cookie with access_token
        setcookie('access_token', $token, [
          'expires' => time() + (3 * 60 * 60), // 3 hours
          'httponly' => true,                  // Ensures the cookie is only sent over HTTP(S)
          'samesite' => 'Strict'               // Helps prevent CSRF attacks
        ]);

        // Successful login response
        http_response_code(200);
        echo json_encode([
          "message" => "Login successful!",
          "user" => $userData,
          "token" => $token
        ]);
      } else {
        // Failed login
        http_response_code(401);
        echo json_encode(["error" => "Invalid email or password!"]);
      }
    } catch (PDOException $e) {
      // Handle database-related errors
      http_response_code(500);
      echo json_encode(['error' => 'Database error: ' . $e->getMessage()]);
    } catch (Exception $e) {
      http_response_code(500);
      echo json_encode(['error' => 'An unexpected error occurred: ' . $e->getMessage()]);
    }
  } else {
    http_response_code(405); // Method Not Allowed
    echo json_encode(["error" => "Invalid request method!"]);
  }
}

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


function passwordResetRequest()
{
  // send otp to user's email
  if ($_SERVER['REQUEST_METHOD'] === 'POST') {
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

function passwordReset($pdo)
{
  if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
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
        http_response_code(200);
        echo json_encode(['message' => 'Password updated successfully']);
      } else {
        http_response_code(400);
        echo json_encode(['error' => 'Failed to update password']);
      }
    } catch (PDOException $e) {
      // Handle database-related errors
      http_response_code(500); // Internal Server Error
      echo json_encode(['error' => 'Database error: ' . $e->getMessage()]);
    } catch (Exception $e) {
      // Handle general errors
      http_response_code(500); // Internal Server Error
      echo json_encode(['error' => 'An unexpected error occurred: ' . $e->getMessage()]);
    }
  } else {
    echo json_encode(['error' => 'Invalid request method']);
  }
}

function verifyUserRequest($user_id, $pdo)
{
  // send OTP to email
  if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
      $jsonData = file_get_contents(filename: "php://input");
      $data = json_decode($jsonData, true);

      $email = $data['email'];

      $error = validateEmail($email);
      if (!empty($error)) {
        http_response_code(400);
        echo json_encode(["errors" => $error]);
        return;
      }

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
    } catch (Exception $e) {
      http_response_code(500); // Internal Server Error
      echo json_encode(['error' => 'An unexpected error occurred: ' . $e->getMessage()]);
    }
  }
}

function verifyUser($token, $pdo)
{
  if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    try {
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
    } catch (PDOException $e) {
      // Handle database-related errors
      http_response_code(500); // Internal Server Error
      echo json_encode(['error' => 'Database error: ' . $e->getMessage()]);
    } catch (Exception $e) {
      http_response_code(500); // Internal Server Error
      echo json_encode(['error' => 'An unexpected error occurred: ' . $e->getMessage()]);
    }
  } else {
    // Invalid request method
    http_response_code(405);
    echo json_encode(['error' => 'Invalid request method. Only GET is allowed.']);
  }
}

// todo verify this later 
function logout()
{
  // Check if the request method is POST
  if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Start the session
    session_start();

    // Remove the access token from the cookie
    if (isset($_COOKIE['access_token'])) {
      // Expire the cookie
      setcookie('access_token', '', time() - 3600, '/'); // Set expiration in the past
    }

    // Clear any session data if applicable
    unset($_SESSION['user_id']); // Remove user ID from session
    session_destroy(); // Destroy the session

    // Return success response
    http_response_code(200); // OK
    echo json_encode(["message" => "Logout successful!"]);
  } else {
    http_response_code(405); // Method Not Allowed
    echo json_encode(["error" => "Invalid request method!"]);
  }
}
