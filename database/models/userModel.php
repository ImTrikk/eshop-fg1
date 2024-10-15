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
        // Prepare the SQL statement
        $sql = "INSERT INTO users (first_name, last_name, contacts, email, password, date_of_birth, role_id) 
        VALUES (:first_name, :last_name, :contacts, :email, :password, :date_of_birth, :role_id)";
        $stmt = $this->pdo->prepare($sql);

        // Bind the parameters
        $stmt->bindParam(':first_name', $userData['first_name']);
        $stmt->bindParam(':last_name', $userData['last_name']);
        $stmt->bindParam(':contacts', $userData['contacts']);
        $stmt->bindParam(':email', $userData['email']);
        $stmt->bindParam(':password', $hashedPassword);
        $stmt->bindParam(':date_of_birth', $userData['date_of_birth']);
        $roleId = 1; // Static value for role_id (buyer role)
        $stmt->bindParam(':role_id', $roleId, PDO::PARAM_INT);

        // Execute the statement
        $stmt->execute();

        // Fetch the user details
        $stmt = $this->pdo->prepare("SELECT user_id, role_name, CONCAT(first_name, ' ', last_name) AS name, email 
            FROM users 
            INNER JOIN roles rl ON users.role_id = rl.role_id 
            WHERE email = :email");
        $stmt->bindParam(':email', $userData['email']);
        $stmt->execute();

        // Fetch the data
        return $stmt->fetch(PDO::FETCH_ASSOC); // Return user details including user_id and name
    }

    public function getUserByEmail($email)
    {
        $sql = "SELECT email, password, is_verified FROM users WHERE email = :email";
        $stmt = $this->pdo->prepare($sql);
        // Bind the parameter
        $stmt->bindParam(':email', $email, PDO::PARAM_STR);
        // Execute the statement
        $stmt->execute();
        // Fetch and return the data
        return $stmt->fetch(PDO::FETCH_ASSOC); // This returns an associative array
    }

    public function checkEmailExist($email)
    {
        $sql = "SELECT email FROM users WHERE email = :email";
        $stmt = $this->pdo->prepare($sql);

        // Bind the parameter
        $stmt->bindParam(':email', $email, PDO::PARAM_STR);

        // Execute the statement
        $stmt->execute();

        // Fetch and return the data
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

    // work on here
    public function updateProfile($data, $user_id)
    {
        try {
            // Prepare the SQL statement to update first_name, last_name, contacts, and password (if needed)
            $stmt = $this->pdo->prepare("
            UPDATE users 
            SET first_name = :first_name, 
                last_name = :last_name, 
                contacts = :contacts 
            WHERE email = :email 
            AND user_id = :user_id
        ");

            // Bind the parameters
            $stmt->bindParam(':first_name', $data['first_name'], PDO::PARAM_STR);
            $stmt->bindParam(':last_name', $data['last_name'], PDO::PARAM_STR);
            $stmt->bindParam(':contacts', $data['contacts'], PDO::PARAM_STR);
            $stmt->bindParam(':email', $data['email'], PDO::PARAM_STR);
            $stmt->bindParam(':user_id', $user_id, PDO::PARAM_INT);

            // Execute the query
            if ($stmt->execute()) {
                return ['status' => 'success', 'message' => 'Profile updated successfully'];
            } else {
                return ['status' => 'error', 'message' => 'Failed to update the profile'];
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

        // Bind the user_id parameter
        $updateStmt->bindParam(':user_id', $user_id, PDO::PARAM_INT);

        // Execute the update statement
        $updateStmt->execute();

        // Prepare the delete statement for user tokens
        $deleteSql = "DELETE FROM user_tokens WHERE token = :token";
        $deleteStmt = $this->pdo->prepare($deleteSql);

        // Bind the token parameter
        $deleteStmt->bindParam(':token', $token, PDO::PARAM_STR);

        // Execute the delete statement
        $deleteStmt->execute();

        // Return success response
        return ['status' => 'success', 'message' => 'Email successfully verified.'];
    }

    public function getUserData($email)
    {
        $sql = "SELECT user_id, email, first_name, last_name, contacts, rl.role_name 
            FROM users 
            INNER JOIN roles rl ON rl.role_id = users.role_id 
            WHERE email = :email";
        $stmt = $this->pdo->prepare($sql);

        // Bind the parameter
        $stmt->bindParam(':email', $email, PDO::PARAM_STR);

        // Execute the statement
        $stmt->execute();

        // Fetch and return the data
        return $stmt->fetch(PDO::FETCH_ASSOC);
    }

    public function addAdress($user_id, $shipping_address)
    {
        $sql = 'INSERT into orders (shipping_addres) VALUES (:shipping_address) ';
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute(['shipping_address' => $shipping_address]);

    }

    public function assignUserRole($email, $role_id)
    {
        // Update the user's role_id based on their email in the users table
        $sql = "UPDATE users SET role_id = :role_id WHERE email = :email";
        $stmt = $this->pdo->prepare($sql);

        // Bind parameters
        $stmt->bindParam(':email', $email, PDO::PARAM_STR);
        $stmt->bindParam(':role_id', $role_id, PDO::PARAM_INT);

        // Execute the update statement
        $stmt->execute();

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

        // Bind the email parameter for the select statement
        $stmt->bindParam(':email', $email, PDO::PARAM_STR);

        // Execute the select statement
        $stmt->execute();

        return $stmt->fetch(PDO::FETCH_ASSOC);
    }

    public function revokeUserRole($email, $role)
    {
        // Update the user's role
        $sql = "UPDATE users SET role_id = :role_id WHERE email = :email";
        $stmt = $this->pdo->prepare($sql);

        // Bind parameters
        $stmt->bindParam(':email', $email, PDO::PARAM_STR);
        $stmt->bindParam(':role_id', $role, PDO::PARAM_INT);

        // Execute the update statement
        $stmt->execute();

        // Return whether any rows were affected
        return $stmt->rowCount() > 0;
    }

    public function getUserProfile($user_id)
    {
        $sql = "SELECT user_id, CONCAT(first_name, ' ', last_name) AS name, email, contacts FROM users WHERE user_id = :user_id";
        $stmt = $this->pdo->prepare($sql);

        // Bind the parameter
        $stmt->bindParam(':user_id', $user_id, PDO::PARAM_INT);

        // Execute the statement
        $stmt->execute();

        // Fetch the user profile
        $userProfile = $stmt->fetch(PDO::FETCH_ASSOC);

        return $userProfile;
    }


    public function getUserCart($email)
    {
        $sql = "SELECT crt.cart_id, prod.product_name, prod.price, crt.quantity
            FROM cart crt 
            INNER JOIN products prod ON prod.product_id = crt.product_id
            INNER JOIN users usr ON usr.user_id = crt.user_id
            INNER JOIN roles rl ON rl.role_id = usr.role_id
            WHERE usr.email = :email"; // Moved email condition to WHERE clause

        $stmt = $this->pdo->prepare($sql);

        // Bind the parameter
        $stmt->bindParam(':email', $email, PDO::PARAM_STR);

        // Execute the statement
        $stmt->execute();

        // Fetch and return the cart details
        return $stmt->fetchAll(PDO::FETCH_ASSOC); // Changed to fetchAll to get all items in the cart
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

    public function invalidateToken($userId)
    {
        // Assuming you have a tokens table to store the tokens
        $stmt = $this->pdo->prepare("UPDATE user_tokens SET is_valid = 0 WHERE user_id = :userId");
        $stmt->bindParam(':userId', $userId);
        $stmt->execute();
    }
}