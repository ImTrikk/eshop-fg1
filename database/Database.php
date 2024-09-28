<?php

// Include the Composer autoload
require 'vendor/autoload.php';

// Correct Dotenv Loader usage
use Dotenv\Loader;

// Create an instance of the Loader and pass the path to the .env file
$loader = new Loader(__DIR__ . '/../.env');

// Load the variables into the environment
$loader->load(); // This loads the .env variables into PHP's environment

// Now, you can access the environment variables with getenv()
$host = getenv('HOST');
$dbname = getenv('DB_NAME');
$username = getenv('USER_NAME');
$password = getenv('PASSWORD');
$charset = getenv('CHARSET');

// PDO configuration for database connection
$dsn = "mysql:host=$host;dbname=$dbname;charset=$charset";

$options = [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES => false,
];

try {
    // Create PDO instance
    $pdo = new PDO($dsn, $username, $password, $options);
    echo "Database connection successful!";
} catch (PDOException $e) {
    // Catch and display any connection errors
    echo "Database connection failed: " . $e->getMessage();
}
