<?php

class AdminModels
{


 private $pdo;

 // Constructor to initialize the PDO connection
 public function __construct($pdo)
 {
  $this->pdo = $pdo;
 }

 public function getAllUsers($pdo)
 {
  $sql = "SELECT first_name, last_name from users";
  $stmt = $this->pdo->prepare($sql);
  $stmt->execute();
  return $stmt->fetchAll(PDO::FETCH_ASSOC); // Return the cart items
  // todo add limitations [30]
  // todo add pagination for 31-40 ------
  // todo add params
 }
}