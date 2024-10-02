<?php

function sendEmailVerication($email)
{

}

function sendOtp($email)
{

}

function checkOtp()
{
 $jsonData = file_get_contents(filename: "php://input");
 $data = json_decode($jsonData, true);

 $user_otp = $data['otp'];
 $otp = 123456;

 try {

  if ($otp == $user_otp) {
   // next();
  }

 } catch (Exception $e) {
  echo $e;
 }

}
