<?php

class UserModel
{
    private $pdo;

    // Constructor to initialize the PDO connection
    public function __construct($pdo)
    {
        $this->pdo = $pdo;
    }

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
            ':role_id' => 1 // make user sa buyer
        ]);

        // Fetch the user details
        // fetch the role name
        $stmt = $this->pdo->prepare("SELECT user_id, role_name, CONCAT(first_name, ' ', last_name) AS name, email FROM users inner join roles rl on users.role_id = rl.role_id WHERE email = :email");
        $stmt->execute([':email' => $userData['email']]);

        // Fetch the data
        return $stmt->fetch(PDO::FETCH_ASSOC); // Return user details including user_id and name
    }


    public function getUserByEmail($email)
    {
        $sql = "SELECT email, password, is_verified FROM users WHERE email = :email";
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

    public function updatePassword($email, $password)
    {
        try {
            // Prepare the SQL statement
            $stmt = $this->pdo->prepare("UPDATE users SET password = :password WHERE email = :email");

            // Bind the parameters
            $stmt->bindParam(':password', $password, PDO::PARAM_STR);
            $stmt->bindParam(':email', $email, PDO::PARAM_STR);

            // Execute the query
            if ($stmt->execute()) {
                return ['status' => 'success', 'message' => 'Password updated successfully'];
            } else {
                return ['status' => 'error', 'message' => 'Failed to update the password'];
            }
        } catch (PDOException $e) {
            // Handle any errors
            return ['status' => 'error', 'message' => 'Error: ' . $e->getMessage()];
        }
    }

    public function verifyEmail($token, $user_id)
    {

        // Update the user's record in the database to verify email
        $updateSql = "UPDATE users SET is_verified = 1 WHERE user_id = :user_id";
        $updateStmt = $this->pdo->prepare($updateSql);
        $updateStmt->execute([':user_id' => $user_id]);

        $deleteSql = "DELETE FROM user_tokens WHERE token = :token";
        $deleteStmt = $this->pdo->prepare($deleteSql);
        $deleteStmt->execute([':token' => $token]);

        // Return success response
        return ['status' => 'success', 'message' => 'Email successfully verified.'];
    }


    public function addAdress($user_id, $shipping_address)
    {
        $sql = 'INSERT into orders (shipping_addres) VALUES (:shipping_address) ';
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute(['shipping_address' => $shipping_address]);

    }

    public function getUserData($email)
    {
        $sql = "SELECT user_id, email, first_name, last_name, contacts, rl.role_name FROM users inner join roles rl on rl.role_id = users.role_id WHERE email = :email";
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([':email' => $email]);
        return $stmt->fetch(PDO::FETCH_ASSOC);
    }

    public function assignUserRole($email, $role_id)
    {
        // Update the user's role_id based on their email in the users table
        $sql = "UPDATE users SET role_id = :role_id WHERE email = :email";
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([
            ':email' => $email,
            ':role_id' => $role_id
        ]);

        // Check if any rows were updated
        if ($stmt->rowCount() === 0) {
            return false;
        }

        // Fetch and return the updated user data
        $sql = "SELECT u.user_id, CONCAT(first_name, ' ', last_name) AS name, u.email, r.role_name 
            FROM users u
            INNER JOIN roles r ON u.role_id = r.role_id
            WHERE u.email = :email";
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([':email' => $email]);

        return $stmt->fetch(PDO::FETCH_ASSOC);
    }


    public function revokeUserRole($email, $role)
    {
        // Update the user's role
        $sql = "UPDATE users SET role_id = :role_id WHERE email = :email";
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([
            ':email' => $email,
            ':role_id' => $role
        ]);

        return $stmt->rowCount() > 0;
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

    public function storeToken($user_id, $token, $token_type)
    {
        date_default_timezone_set('Asia/Manila');
        try {
            // First, check if a token of the specified type (JWT or EMAIL_VERIFICATION) already exists for the user
            $sqlCheck = "SELECT token, token_type FROM user_tokens WHERE user_id = :user_id AND token_type = :token_type";
            $stmtCheck = $this->pdo->prepare($sqlCheck);
            $stmtCheck->execute([
                ':user_id' => $user_id,
                ':token_type' => $token_type
            ]);

            // Determine if a token of this type exists
            $existingToken = $stmtCheck->fetch(PDO::FETCH_ASSOC);

            if ($existingToken) {
                // If a token of the specified type already exists, update it
                $sqlUpdate = "UPDATE user_tokens 
                          SET token = :token, issued_at = :issued_at, expires_at = :expires_at, 
                              is_valid = :is_valid, email_verified = :email_verified
                          WHERE user_id = :user_id AND token_type = :token_type";

                $stmtUpdate = $this->pdo->prepare($sqlUpdate);
                $stmtUpdate->execute([
                    ':user_id' => $user_id,
                    ':token' => $token,
                    ':token_type' => $token_type, // Keep the token type as it is (JWT or EMAIL_VERIFICATION)
                    ':issued_at' => date('Y-m-d H:i:s'),
                    ':expires_at' => date('Y-m-d H:i:s', strtotime('+3 hours')),
                    ':is_valid' => 1,
                    ':email_verified' => ($token_type === 'EMAIL_VERIFICATION') ? 0 : 1 // Set based on token type
                ]);
            } else {
                // If no token of this type exists, insert a new one
                $sqlInsert = "INSERT INTO user_tokens (user_id, token, token_type, issued_at, expires_at, is_valid, email_verified) 
                          VALUES (:user_id, :token, :token_type, :issued_at, :expires_at, :is_valid, :email_verified)";

                $stmtInsert = $this->pdo->prepare($sqlInsert);
                $stmtInsert->execute([
                    ':user_id' => $user_id,
                    ':token' => $token,
                    ':token_type' => $token_type, // Use the provided token type (JWT or EMAIL_VERIFICATION)
                    ':issued_at' => date('Y-m-d H:i:s'),
                    ':expires_at' => date('Y-m-d H:i:s', strtotime('+3 hours')),
                    ':is_valid' => 1,
                    ':email_verified' => ($token_type === 'EMAIL_VERIFICATION') ? 0 : 1 // Set based on token type
                ]);
            }
        } catch (PDOException $e) {
            // Log the error message for debugging
            error_log('Error inserting or updating token: ' . $e->getMessage());
            throw $e;
        }
    }


    public function logoutModel($user_id)
    {
        $sql = 'DELETE * from tokens where user_id = :user_id';
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([':email' => $user_id]);
        return $stmt->fetch(PDO::FETCH_ASSOC);
    }
}