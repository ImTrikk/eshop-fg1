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

            // Apply rate limiting
            $this->rateLimit();
        } catch (PDOException $e) {
            // Catch and display any connection errors
            echo "Database connection failed: " . $e->getMessage();
        }

        return $this->pdo;
    }

    private function rateLimit()
    {
        $ip = $_SERVER['REMOTE_ADDR'];
        $current_time = time();
        $time_frame = 60; // 1 minute
        $max_requests = 100; // Max requests allowed

        // Create table if it doesn't exist
        $this->pdo->exec("CREATE TABLE IF NOT EXISTS request_logs (ip VARCHAR(45), timestamp INT)");

        // Remove old requests
        $this->pdo->prepare("DELETE FROM request_logs WHERE timestamp < :time")->execute(['time' => $current_time - $time_frame]);

        // Log the current request
        $this->pdo->prepare("INSERT INTO request_logs (ip, timestamp) VALUES (:ip, :time)")->execute(['ip' => $ip, 'time' => $current_time]);

        // Count requests from this IP
        $stmt = $this->pdo->prepare("SELECT COUNT(*) FROM request_logs WHERE ip = :ip");
        $stmt->execute(['ip' => $ip]);
        $request_count = $stmt->fetchColumn();

        if ($request_count > $max_requests) {
            http_response_code(429); // Too Many Requests
            echo json_encode(['error' => 'Too many requests. Please try again later.']);
            exit();
        }
    }
}
