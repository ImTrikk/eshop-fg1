<?php


function authRoutes($router, $pdo)
{

 // ====================== AUTHENTICATION ==================== //

 $router->post('/auth/register', function () use ($pdo) {
  register($pdo);
 });

 $router->post('/auth/login', function () use ($pdo) {
  login($pdo);
 });

 $router->post('/auth/logout', function () use ($pdo) {
  logout($pdo);
 });

 $router->post('/auth/password/reset/request', function () use ($pdo) {
  passwordResetRequest();
 });

 $router->post('/auth/password/reset', function () use ($pdo) {
  passwordReset($pdo);
 });



 // ====================== AUTHORIZATION ==================== //

 // todo add verify request function router for users
 $router->post('/auth/user/verify/request', function () use ($pdo) {

 });


 $router->post('/auth/user/verify', function () use ($pdo) {

 });

 // todo add authentication and authorization middlewares
 $router->get('/auth/user/profile/{id}', function ($id) use ($pdo) {
  authenticate($_REQUEST, function ($request) use ($pdo, $id) {
   authorizeUser($request, $id, function ($authorizedRequest) use ($pdo, $id) {
    // Fetch and return the user profile if authorized
    userProfile($pdo, $id);
   });
  });
 });


 // todo add authentication and authorization middlewares
 $router->post('/auth/role/assign', function () use ($pdo) {
  authenticate($_REQUEST, function ($request) use ($pdo) {
   authorize('Admin', $request, function ($request) use ($pdo) {
    assignRole($pdo);
   });
  });
 });

 $router->post('/auth/role/revoke', function () use ($pdo) {

 });

 $router->post('/auth/roles/{user_id}', function ($user_id) use ($pdo) {

 });
}
