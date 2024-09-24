<?php

// Database credentials
$host = 'localhost';  // Change this if you're connecting to a remote server
$dbname = 'eshop-fg1'; // Replace with your database name
$username = 'root';  // Replace with your MySQL username
$password = '';  // Replace with your MySQL password
$charset = 'utf8mb4'; // Charset, utf8mb4 is commonly used for better Unicode support


$dsn = "mysql:host=$host;dbname=$dbname;charset=$charset";

// PDO options
$options = [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, // Enable exceptions on errors
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC, // Set default fetch mode to associative arrays
    PDO::ATTR_EMULATE_PREPARES => false, // Disable emulation of prepared statements
];

try {
    // Create PDO instance
    $pdo = new PDO($dsn, $username, $password, $options);
    echo "Database connection successful!";
} catch (PDOException $e) {
    // Handle any errors
    echo "Database connection failed: " . $e->getMessage();
}
