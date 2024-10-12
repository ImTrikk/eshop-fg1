<?php

require_once 'vendor/autoload.php'; // Make sure PHPMailer is installed via Composer
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

// Function to generate a 6-digit OTP code as a string
function generateRandomNumbers($count = 6, $min = 0, $max = 9)
{
 $otp = '';
 for ($i = 0; $i < $count; $i++) {
  $otp .= mt_rand($min, $max); // Generates a random number between $min and $max
 }
 return $otp; // Return OTP as a string
}

function sendOtp($email)
{
 $mail = new PHPMailer(true); // Create PHPMailer instance
 $otp = generateRandomNumbers(); // Generate OTP

 try {
  // SMTP server configuration
  $mail->isSMTP();
  $mail->Host = 'smtp.gmail.com'; // Gmail's SMTP server
  $mail->SMTPAuth = true;
  $mail->Username = getenv('MAIL_EMAIL'); // Your Gmail address
  $mail->Password = getenv('MAIL_PASSWORD'); // Gmail App Password or regular password (with less secure apps enabled)
  $mail->SMTPSecure = 'tls'; // Enable TLS encryption
  $mail->Port = 587; // SMTP port for TLS

  // From email address and name
  $mail->setFrom(getenv('MAIL_EMAIL'), 'E-Commerce');

  // Add recipient
  $mail->addAddress($email);

  // Set reply-to address
  $mail->addReplyTo(getenv('MAIL_EMAIL'), 'E-Commerce');

  // Email content
  $mail->isHTML(true); // Send email in HTML format
  $mail->Subject = "Your OTP Code";
  $mail->Body = "<p>Your OTP code is <strong>$otp</strong>. Please do not share this with anyone else!</p>";
  $mail->AltBody = "Your OTP code is $otp"; // Fallback for non-HTML clients

  // Send the email
  $mail->send();

  // Store OTP in session for verification
  session_start();
  $_SESSION['otp'] = $otp;

  echo json_encode(['message' => 'One time password has been successfully sent to ' . $email]);

 } catch (Exception $e) {
  // Handle errors
  echo "Message could not be sent. Mailer Error: {$mail->ErrorInfo}";
 }

 return $otp; // Return the OTP (in case you want to store it for verification)
}

function verifyOtp($user_otp)
{
 session_start();

 // Retrieve OTP from session
 $stored_otp = isset($_SESSION['otp']) ? $_SESSION['otp'] : null;

 // Check if the OTP matches
 if ($user_otp === $stored_otp) {
  unset($_SESSION['otp']);
  http_response_code(200);
  echo json_encode(['message' => 'OTP verified successfully']);
  return true; // Return true on success
 } else {
  http_response_code(403);
  echo json_encode(['error' => 'Invalid OTP']);
  return false; // Return false on failure
 }
}


function sendVerificationEmail($email, $token)
{
    $mail = new PHPMailer(true); // Create PHPMailer instance

    try {
        // SMTP server configuration
        $mail->isSMTP();
        $mail->Host = 'smtp.gmail.com'; // Gmail's SMTP server
        $mail->SMTPAuth = true;
        $mail->Username = getenv('MAIL_EMAIL'); // Your Gmail address
        $mail->Password = getenv('MAIL_PASSWORD'); // Gmail App Password or regular password
        $mail->SMTPSecure = 'tls'; // Enable TLS encryption
        $mail->Port = 587; // SMTP port for TLS

        // From email address and name
        $mail->setFrom(getenv('MAIL_EMAIL'), 'E-Commerce');

        // Add recipient
        $mail->addAddress($email);

        // Set reply-to address
        $mail->addReplyTo(getenv('MAIL_EMAIL'), 'E-Commerce');

        // URL that the user will click to verify their email
        $verificationLink = "http://localhost/eshop-fg1/api/auth/verify-email/" . urlencode($token);    



        // Email content
        $mail->isHTML(true); // Send email in HTML format
        $mail->Subject = "Verify Your Email Address";
        $mail->Body = "
            <p>Dear user,</p>
            <p>Thank you for signing up! Please click the link below to verify your email address:</p>
            <p><a href='$verificationLink'>Verify Email</a></p>
            <p>If you did not request this, please ignore this email.</p>
            <p>Best regards,<br>E-Commerce Team</p>
        ";
        $mail->AltBody = "Please click the following link to verify your email: $verificationLink"; // Fallback for non-HTML clients

        // Send the email
        $mail->send();

        echo json_encode(['message' => 'Verification email has been successfully sent to ' . $email]);

    } catch (Exception $e) {
        // Handle errors
        echo "Message could not be sent. Mailer Error: {$mail->ErrorInfo}";
    }
}
