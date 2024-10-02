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
            ':role_id' => $userData['role_id']
        ]);

        return $this->pdo->lastInsertId(); // Return the ID of the new user
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
        $sql = "SELECT user_id, email, first_name, last_name, contacts FROM users WHERE email = :email";
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([':email' => $email]);
        return $stmt->fetch(PDO::FETCH_ASSOC);
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
        print_r($user_id);
        try {
            $sql = "INSERT INTO user_tokens (user_id, token, token_type, issued_at, expires_at, is_valid, email_verified) 
                VALUES (:user_id, :token, :token_type, :issued_at, :expires_at, :is_valid, :email_verified)";
            $stmt = $this->pdo->prepare($sql);
            $stmt->execute([
                ':user_id' => $user_id,
                ':token' => $token,
                ':token_type' => 'JWT',  // Assuming bearer token
                ':issued_at' => date('Y-m-d H:i:s'),
                ':expires_at' => date('Y-m-d H:i:s', strtotime('+3 hours')),  // 3-hour expiry time
                ':is_valid' => 1,
                ':email_verified' => 1
            ]);
        } catch (PDOException $e) {
            // Log the error message for debugging
            error_log('Error inserting token: ' . $e->getMessage());
            throw $e;
        }
    }



    public function destroyToken()
    {

    }
}