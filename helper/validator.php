<?php

// not using libraries due to no dynamic error messages

function validateRegistration($data)
{
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

  return $errors;
}

function validateLogin($data)
{
  $errors = [];

  if (empty($data['email'])) {
    $errors['email'] = 'Email is required.';
  } elseif (!filter_var($data['email'], FILTER_VALIDATE_EMAIL)) {
    $errors['email'] = 'Invalid email format.';
  }

  // Check if password is present and of valid length (bcrypt hashes are 60 characters long)
  if (empty($data['password'])) {
    $errors['password'] = 'Password is required.';
  } elseif (strlen($data['password']) < 6) { // For user input password, you can check its length
    $errors['password'] = 'Password must be at least 6 characters long.';
  }

  return $errors;
}

function validateRole($data)
{
  $errors = [];

  // Validate email
  if (empty($data['email'])) {
    $errors['email'] = 'Email is required.';
  } elseif (!filter_var($data['email'], FILTER_VALIDATE_EMAIL)) {
    $errors['email'] = 'Invalid email format.';
  }

  // Validate role
  $validRoles = ['Seller', 'Buyer'];
  if (empty($data['role'])) {
    $errors['role'] = 'Role is required.';
  } elseif (!in_array($data['role'], $validRoles)) {
    $errors['role'] = 'Role must be either "Seller" or "Buyer".';
  }

  return $errors;
}

function validateResetPassword($data)
{
  $errors = [];
  // Validate OTP
  if (empty($data['otp'])) {
    $errors['otp'] = 'OTP is required';
  } else {
    // Optional: Validate the format or length of OTP if needed
    if (!preg_match('/^\d{6}$/', $data['otp'])) {
      $errors['otp'] = 'OTP must be a 6-digit number';
    }
  }

  // Validate Email
  if (empty($data['email'])) {
    $errors['email'] = 'Email is required';
  } else {
    // Check if the email is valid
    if (!filter_var($data['email'], FILTER_VALIDATE_EMAIL)) {
      $errors['email'] = 'Invalid email format';
    }
  }

  // Validate Password
  if (empty($data['password'])) {
    $errors['password'] = 'Password is required';
  } else {
    // Check password strength (e.g., length, complexity)
    if (strlen($data['password']) < 8) {
      $errors['password'] = 'Password must be at least 8 characters long';
    }
    if (!preg_match('/[A-Z]/', $data['password'])) {
      $errors['password'] = 'Password must contain at least one uppercase letter';
    }
    if (!preg_match('/[a-z]/', $data['password'])) {
      $errors['password'] = 'Password must contain at least one lowercase letter';
    }
    if (!preg_match('/[0-9]/', $data['password'])) {
      $errors['password'] = 'Password must contain at least one digit';
    }
    if (!preg_match('/[\W]/', $data['password'])) {
      $errors['password'] = 'Password must contain at least one special character';
    }
  }

  return $errors;
}

function validateVerifyRequest($data)
{
  $errors = [];

  return $errors;
}

function validateEmail($email)
{
  $errors = [];

  if (empty($email)) {
    $errors['email'] = 'Email is required';
  } else {
    // Check if the email is valid
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
      $errors['email'] = 'Invalid email format';
    }
  }

  return $errors;
}


function validateUpdateProfile($data)
{

  $errors = [];

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

  return $errors;
}

// Helper function to validate date format (YYYY-MM-DD)
function validateDate($date)
{
  $d = DateTime::createFromFormat('Y-m-d', $date);
  return $d && $d->format('Y-m-d') === $date;
}