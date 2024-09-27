<?php

 class UserModel{
 private $pdo;

 // Constructor to initialize the PDO connection
 public function __construct($pdo) {
  $this->pdo = $pdo;
 }

 // Function to get user by email

 public function  registerUser($userData, $hashedPassword){
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

    return $stmt->fetch(PDO::FETCH_ASSOC);
 }

 public function getUserByEmail($email) {
  $sql = "SELECT email, password FROM users WHERE email = :email";
  $stmt = $this->pdo->prepare($sql);
  $stmt->execute([':email' => $email]);
  return $stmt->fetch(PDO::FETCH_ASSOC);
 }

 public function getUserData($email){
  $sql = "SELECT user_id, email, first_name, last_name, contacts FROM users WHERE email = :email";
  $stmt = $this->pdo->prepare($sql);
  $stmt->execute([':email' => $email]);
  return $stmt->fetch(PDO::FETCH_ASSOC);
 }

 public function getUserCart($email){
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

 public function storeToken($email, $token){

 }

 public function destroyToken(){

 }
}