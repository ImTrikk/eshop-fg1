<?php

class UserModel
{
    private $pdo;

    // Constructor to initialize the PDO connection
    public function __construct($pdo)
    {
        $this->pdo = $pdo;
    }

    // Function to get user by email

    public function registerUser($userData, $hashedPassword)
    {
        $sql = "INSERT INTO users (first_name, last_name, contacts, email, password, date_of_birth, role_id) 
        VALUES (:first_name, :last_name, :contacts, :email, :password, :date_of_birth, :role_id)";
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([
            ':first_name' => $userData['first_name'],
            ':last_name' => $userData['last_name'],
            ':contacts' => $userData['contacts'],
            ':email' => $userData['email'],
            ':password' => $hashedPassword,
            ':date_of_birth' => $userData['date_of_birth'],
            ':role_id' => 1
        ]);

        // Fetch the user details
        $stmt = $this->pdo->prepare("SELECT user_id, CONCAT(first_name, ' ', last_name) AS name, email FROM users WHERE email = :email");
        $stmt->execute([':email' => $userData['email']]);

        // Fetch the data
        return $stmt->fetch(PDO::FETCH_ASSOC); // Return user details including user_id and name
    }


    public function getUserByEmail($email)
    {
        $sql = "SELECT email, password FROM users WHERE email = :email";
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([':email' => $email]);
        return $stmt->fetch(PDO::FETCH_ASSOC); // This returns an associative array
    }


    public function checkEmailExist($email)
    {
        $sql = "SELECT email FROM users WHERE email = :email";
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([':email' => $email]);
        return $stmt->fetch(PDO::FETCH_ASSOC);
    }

    public function getUserData($email)
    {
        $sql = "SELECT user_id, email, first_name, last_name, contacts, rl.role_name FROM users inner join roles rl on rl.role_id = users.role_id WHERE email = :email";
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([':email' => $email]);
        return $stmt->fetch(PDO::FETCH_ASSOC);
    }

    public function assignUserRole($user_id, $role)
    {
        $sql = "UPDATE roles SET role_name = :role WHERE user_id = :user_id";
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([
            ':user_id' => $user_id,
            ':role' => $role
        ]);


        $sql = "SELECT * FROM roles WHERE user_id = :user_id";
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([':user_id' => $user_id]);

        return $stmt->fetch(PDO::FETCH_ASSOC);
    }

    public function getUserProfile($user_id)
    {
        $sql = "SELECT user_id, CONCAT(first_name, ' ', last_name) AS name, email, contacts FROM users WHERE user_id = :user_id";
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([':user_id' => $user_id]);

        $userProfile = $stmt->fetch(PDO::FETCH_ASSOC);

        return $userProfile;
    }

    public function getUserCart($email)
    {
        $sql = "SELECT crt.cart_id, prod.product_name, prod.price, crt.quantity
          from 
           cart crt 
               inner join products prod on prod.product_id = crt.product_id
               inner join users usr on usr.user_id = crt.user_id
               inner join roles rl on rl.role_id = usr.role_id and email = :email";

        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([':email' => $email]);
        return $stmt->fetch(PDO::FETCH_ASSOC);
    }

    public function storeToken($user_id, $token)
    {
        date_default_timezone_set('Asia/Manila');
        try {
            $sql = " INSERT INTO user_tokens (user_id, token, token_type, issued_at, expires_at, is_valid, email_verified) 
            VALUES (:user_id, :token, :token_type, :issued_at, :expires_at, :is_valid, :email_verified)
            ON DUPLICATE KEY UPDATE
                token = :update_token,
                token_type = :update_token_type,
                issued_at = :update_issued_at,
                expires_at = :update_expires_at,
                is_valid = :update_is_valid,
                email_verified = :update_email_verified";

            $stmt = $this->pdo->prepare($sql);
            $stmt->execute([
                ':user_id' => $user_id,
                ':token' => $token,
                ':token_type' => 'JWT',  // Assuming bearer token
                ':issued_at' => date('Y-m-d H:i:s'),
                ':expires_at' => date('Y-m-d H:i:s', strtotime('+3 hours')),
                ':is_valid' => 1,
                ':email_verified' => 1,
                // Update part
                ':update_token' => $token,
                ':update_token_type' => 'JWT',
                ':update_issued_at' => date('Y-m-d H:i:s'),
                ':update_expires_at' => date('Y-m-d H:i:s', strtotime('+3 hours')),
                ':update_is_valid' => 1,
                ':update_email_verified' => 1
            ]);
        } catch (PDOException $e) {
            // Log the error message for debugging
            error_log('Error inserting or updating token: ' . $e->getMessage());
            throw $e;
        }
    }

    public function destroyToken()
    {

    }
}