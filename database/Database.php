<?php

// Include the Composer autoload
require 'vendor/autoload.php';

// Correct Dotenv Loader usage
use Dotenv\Loader;

// Create an instance of the Loader and pass the path to the .env file
$loader = new Loader(__DIR__ . '/../.env');

// Load the variables into the environment
$loader->load(); // This loads the .env variables into PHP's environment

class Database
{
    private $pdo;

    public function connect()
    {
        $host = getenv('HOST'); // Get HOST from environment variable
        $db_name = getenv('DB_NAME'); // Get DB_NAME from environment variable
        $username = getenv('USER_NAME'); // Get USER_NAME from environment variable
        $charset = getenv('CHARSET'); // Get CHARSET from environment variable

        // Set up the DSN (Data Source Name)
        $dsn = "mysql:host=$host;dbname=$db_name;charset=$charset"; // No password needed

        $options = [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ];

        try {
            // Create PDO instance
            $this->pdo = new PDO($dsn, $username, null, $options); // Use null for password
            echo "Database connection successful!";
        } catch (PDOException $e) {
            // Catch and display any connection errors
            echo "Database connection failed: " . $e->getMessage();
        }

        return $this->pdo;
    }
}
