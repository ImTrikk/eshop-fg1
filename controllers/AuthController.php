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

        http_response_code(201);
        echo json_encode(["message" => "User registered successfully!", 'User' => $registeredUser]);
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


    // todo need to change this for correct checking, uncomment it
    // if ($user && password_verify($password, $user['password'])) {
    if ($user && $password) {
      // Fetch additional user data (excluding the password)
      $userData = $userModel->getUserData($email);

      $secretKey = ucfirst(getenv('JWT_SECRET'));

      $token = generateToken($userData['user_id'], $userData['role_name'], $secretKey);

      unset($userData['password']);
      unset($user['password']);

      //storing token 
      $userModel->storeToken($userData['user_id'], $token);

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

function verifyUserRequest()
{
  // send OTP to email
}

function verifyUser()
{
  // recieve otp from reqeust
  // uddate users table to true
}

function userProfile($pdo, $user_id)
{

  if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $userModel = new UserModel($pdo);
    $user_profile = $userModel->getUserProfile($user_id);

    http_response_code(200);
    echo json_encode(['message' => 'Retrieved user profile', 'User' => $user_profile]);
  }

}

function assignRole($pdo)
{
  if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $jsonData = file_get_contents(filename: "php://input");
    $data = json_decode($jsonData, true);

    $user_id = $data['user_id'];
    $role = $data['role'];

    $userModel = new UserModel($pdo);
    $user = $userModel->assignUserRole($user_id, $role);


    http_response_code(201);
    echo json_encode(['message' => "Assigned role to user", 'User' => $user]);
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
    $jsonData = file_get_contents(filename: "php://input");
    $data = json_decode($jsonData, true);

    $email = $data['email'];
    $password = $data['password'];

    // send  email to user with otp
    sendOtp($email);

    // check otp
    // get new user password
    //has password
    // insert hashed_password to database

  }
}

function logout($user_id)
{
  // Handle logout logic, e.g., clearing session data
  session_start();
  session_destroy();

  //remove token form 

  echo json_encode(["message" => "Logged out successfully!"]);
}