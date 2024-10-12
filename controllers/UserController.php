<?php

function addAddress($pdo)
{
 if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  $jsonData = file_get_contents(filename: "php://input"); 
  $data = json_decode($jsonData, true);

  $email = $data['email'];
  $address = $data['shipping_address'];

  $userModel = new UserModel($pdo);

  $insert = $userModel->addAdress($email, $address);

 }
}

function updateAddress(){
 if($_SERVER['REQUEST_METHOD'] === 'PUT'){

 }
}

// refactor code with buyer and seller roles