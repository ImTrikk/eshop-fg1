<?php

// Import database connection
require 'database/database.php'; 

function register($pdo) {
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

        // Basic validation
        if (empty($firstName) || empty($lastName) || empty($contacts) || empty($email) || empty($password) || empty($dateOfBirth) || empty($roleId)) {
            echo json_encode(["error" => "All fields are required!"]);
            return;
        }

        // Validate email format
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            echo json_encode(["error" => "Invalid email format!"]);
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

            echo json_encode(["message" => "User registered successfully!"]);
        } catch (PDOException $e) {
            echo json_encode(["error" => "Registration failed: " . $e->getMessage()]);
        }
    }
}

function login($pdo) {
    // Check if the form is submitted via POST request
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $jsonData = file_get_contents("php://input");
        $data = json_decode($jsonData, true);

        $email = $data['email'] ?? '';
        $password = $data['password'] ?? '';

        // Basic validation
        if (empty($email) || empty($password)) {
            echo json_encode(["error" => "Email and password are required!"]);
            return;
        }

        // Prepare SQL statement to get user by email
        $sql = "SELECT * FROM users WHERE email = :email";
        $stmt = $pdo->prepare($sql);
        $stmt->execute([':email' => $email]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user && password_verify($password, $user['password'])) {
            // Successful login
            echo json_encode(["message" => "Login successful!", "user" => $user]);
        } else {
            // Failed login
            echo json_encode(["error" => "Invalid email or password!"]);
        }
    }
}

function logout() {
    // Handle logout logic, e.g., clearing session data
    session_start();
    session_destroy();
    echo json_encode(["message" => "Logged out successfully!"]);
}
