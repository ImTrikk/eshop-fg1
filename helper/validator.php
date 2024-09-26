<?php

function validateUser($data) {
 $errors = [];

 // Validate first name
 if (empty($data['first_name'])) {
   echo $data['first_name'];
   $errors[] = 'First name is required.';
 } elseif (!preg_match("/^[a-zA-Z '-]+$/", $data['first_name'])) {
   $errors[] = 'First name can only contain letters, apostrophes, and hyphens.';
 }

 // Validate last name
 if (empty($data['last_name'])) {
   $errors[] = 'Last name is required.';
 } elseif (!preg_match("/^[a-zA-Z'-]+$/", $data['last_name'])) {
   $errors[] = 'Last name can only contain letters, apostrophes, and hyphens.';
 }

 // Validate email
 if (empty($data['email'])) {
   $errors[] = 'Email is required.';
 } elseif (!filter_var($data['email'], FILTER_VALIDATE_EMAIL)) {
   $errors[] = 'Invalid email format.';
 } else {
     // Check if email already exists in the database (pseudo-code)
     // if (emailExists($data['email'])) {
     //     $errors[] = 'Email already exists.';
     // }
 }

 // Validate password
 if (empty($data['password'])) {
   $errors[] = 'Password is required.';
 } elseif (strlen($data['password']) < 8) {
   $errors[] = 'Password must be at least 8 characters.';
 } elseif (!preg_match("/[A-Z]/", $data['password'])) {
   $errors[] = 'Password must contain at least one uppercase letter.';
 } elseif (!preg_match("/[a-z]/", $data['password'])) {
   $errors[] = 'Password must contain at least one lowercase letter.';
 } elseif (!preg_match("/[0-9]/", $data['password'])) {
   $errors[] = 'Password must contain at least one digit.';
 } elseif (!preg_match("/[\W_]/", $data['password'])) {
   $errors[] = 'Password must contain at least one special character.';
 }

 // Validate date of birth
 if (empty($data['date_of_birth'])) {
  $errors[] = 'Date of birth is required.';
 } elseif (!validateDate($data['date_of_birth'])) {
   $errors[] = 'Invalid date format. Use YYYY-MM-DD.';
 } elseif (strtotime($data['date_of_birth']) > strtotime('-13 years')) {
   $errors[] = 'You must be at least 13 years old to register.';
 }

 // Validate role ID
 if (empty($data['role_id'])) {
   $errors[] = 'Role ID is required.';
 } elseif (!is_numeric($data['role_id'])) {
   $errors[] = 'Role ID must be a numeric value.';
 }

 return $errors;
}

function validateEmail($email){
  $errors = [];

  

}

// Helper function to validate date format (YYYY-MM-DD)
function validateDate($date) {
    $d = DateTime::createFromFormat('Y-m-d', $date);
    return $d && $d->format('Y-m-d') === $date;
}
