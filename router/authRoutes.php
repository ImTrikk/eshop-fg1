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

 $router->post('/auth/password/reset/request', function () use ($pdo) {
  passwordResetRequest();
 });

 $router->post('/auth/password/reset', function () use ($pdo) {
  passwordReset($pdo);
 });

 $router->post('/auth/logout/{id}', function ($id) use ($pdo) {
  logout($id, $pdo);
 });


 // ====================== AUTHORIZATION ==================== //

 // todo add verify request function router for users
 $router->post('/auth/user/verify/request/{id}', function ($id) use ($pdo) {
  authenticate($_REQUEST, function ($id) {
   verifyUserRequest($id);
  });
 });

 //
 $router->post('/auth/user/verify/{id}', function ($id) use ($pdo) {
  verifyUser($id, $pdo);
 });

 // todo add authentication and authorization middlewares
 $router->get('/auth/user/profile/{id}', function ($id) use ($pdo) {
  authenticate($_REQUEST, function ($request) use ($pdo, $id) {
   authorizeUser($request, $id, function () use ($pdo, $id) {
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
  authenticate($_REQUEST, function ($request) use ($pdo) {
   authorize('Admin', $request, function ($request) use ($pdo) {
    revokeRole($pdo);
   });
  });
 });

 $router->post('/auth/roles/{user_id}', function ($user_id) use ($pdo) {

 });
}
