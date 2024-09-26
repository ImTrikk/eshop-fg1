<?php

 class UserModel{
 private $pdo;

 // Constructor to initialize the PDO connection
 public function __construct($pdo) {
  $this->pdo = $pdo;
 }

 // Function to get user by email

 public function  registerUser($request){

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

 public function storeToken($email, $token){
  
 }

 public function destroyToken(){

 }
}