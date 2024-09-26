<?php

// Import database connection
require 'vendor/autoload.php';
require 'database/database.php'; 
require 'helper/validator.php';
require 'helper/token.php';
require_once(__DIR__ . '/../database/models/userModel.php');

function register($pdo) {
  try{
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
      $roleId = $data['role_id'] ?? '';

      // Prepare the data for validation
      $validationData = [
      'first_name' => $firstName,
      'last_name' => $lastName,
      'contacts' => $contacts,
      'email' => $email,
      'password' => $password,
      'date_of_birth' => $dateOfBirth,
      'role_id' => $roleId
      ];

      // Validate user data
      $errors = validateUser($validationData);

      if (!empty($errors)) {
        echo json_encode(["errors" => $errors]);
        return;
      }

      // Hash the password for security
      $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

      // Prepare the SQL statement to insert the user data
      $sql = "INSERT INTO users (first_name, last_name, contacts, email, password, date_of_birth, role_id) 
      VALUES (:first_name, :last_name, :contacts, :email, :password, :date_of_birth, :role_id)";

      try {
        $stmt = $pdo->prepare($sql);
        $stmt->execute([
          ':first_name' => $firstName,
          ':last_name' => $lastName,
          ':contacts' => $contacts,
          ':email' => $email,
          ':password' => $hashedPassword,
          ':date_of_birth' => $dateOfBirth,
          ':role_id' => $roleId
        ]);

        http_response_code(201);
        echo json_encode(["message" => "User registered successfully!"]);
      } catch (PDOException $e) {
        http_response_code(500);
        echo json_encode(["error" => "Registration failed: " . $e->getMessage()]);
      }
    }
  } catch(PDOException $e){
    http_response_code(500);
    echo json_encode(["error" => "Internal Server Error " . $e->getMessage()]);

  }
}


function login($pdo) {
  // Check if the form is submitted via POST request
  if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Get JSON data from the request
    $jsonData = file_get_contents(filename: "php://input");
    $data = json_decode($jsonData, true);

    $email = $data['email'] ?? '';
    $password = $data['password'] ?? '';

    // Basic validation
    if (empty($email) || empty($password)) {
      http_response_code(400); // Bad Request
      echo json_encode(["error" => "Email and password are required!"]);
      return;
    }

    // Initialize UserModel
    $userModel = new userModel(pdo: $pdo);

    // Fetch user by email
    $user = $userModel->getUserByEmail($email);

    // Verify password
    if ($user && password_verify($password, $user['password'])) {
    // if ($user && $password) {
      // Fetch additional user data (excluding the password)
      $userData = $userModel->getUserData($email);

      // Generate token (assuming you have a function called generateToken)
      $secretKey = ucfirst(getenv('JWT_SECRET'));
      $token = generateToken($userData['user_id'], $secretKey);

      // Remove sensitive data (like password) from user data before returning it
      unset($userData['password']);
      unset($user['password']);

      // Set token as a cookie (if needed)
      setcookie('auth_token', $token, [
        'expires' => time() + (5 * 60 * 60), // 5 hours
        'httponly' => true, // Ensures the cookie is only sent over HTTP(S)
        'samesite' => 'Strict' // Helps prevent CSRF attacks
      ]);

      // Successful login response
      http_response_code(200); // OK
      echo json_encode([
          "message" => "Login successful!",
          "user" => $userData,
          "token" => $token
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


function logout($user_id) {
  // Handle logout logic, e.g., clearing session data
  session_start();
  session_destroy();

  //remove token form 
  


  echo json_encode(["message" => "Logged out successfully!"]);
}
