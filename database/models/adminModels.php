<?php

class AdminModels
{


 private $pdo;

 // Constructor to initialize the PDO connection
 public function __construct($pdo)
 {
  $this->pdo = $pdo;
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

    public function getAllUsers($pdo, $limit, $offset)
    {
        // Updated SQL query to include email, contact, and role_name with pagination
        $sql = "SELECT u.first_name, u.last_name, u.email, u.contacts, r.role_name 
            FROM users u
            INNER JOIN roles r ON u.role_id = r.role_id
            LIMIT :limit OFFSET :offset"; // Added LIMIT and OFFSET

        $stmt = $pdo->prepare($sql);

        // Ensure limit and offset are integers and bind them
        $limit = (int) $limit;
        $offset = (int) $offset;

        $stmt->bindParam(':limit', $limit, PDO::PARAM_INT);
        $stmt->bindParam(':offset', $offset, PDO::PARAM_INT);

        try {
            $stmt->execute();
            return $stmt->fetchAll(PDO::FETCH_ASSOC); // Return the user data with additional fields
        } catch (PDOException $e) {
            // Log the error or handle it as appropriate
            error_log("Error fetching users: " . $e->getMessage());
            return []; // Return an empty array on failure
        }
    }

}
