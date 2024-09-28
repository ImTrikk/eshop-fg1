<?php

class ProductModel {
 private $pdo;

 public function __construct($pdo) {
  $this->pdo = $pdo;
 }

 public function getUserCart($user_id) {
  $sql = "SELECT * FROM cart WHERE user_id = :user_id";
  $stmt = $this->pdo->prepare($sql);
  $stmt->execute(['user_id' => $user_id]);
  return $stmt->fetchAll(PDO::FETCH_ASSOC); // Return the cart items
 }
}