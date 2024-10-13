<?php


class Router
{
 private $routes = [];

 public function get($route, $handler)
 {
  $this->addRoute('GET', $route, $handler);
 }

 public function post($route, $handler)
 {
  $this->addRoute('POST', $route, $handler);
 }

 public function put($route, $handler)
 {
  $this->addRoute('PUT', $route, $handler);
 }

 public function delete($route, $handler)
 {
  $this->addRoute('DELETE', $route, $handler);
 }

 private function addRoute($method, $route, $handler)
 {
  $this->routes[$method][$route] = $handler;
 }

//  public function dispatch($requestUri, $requestMethod)
//  {
//   $uri = strtok($requestUri, '?');
//   $matches = [];

//   print_r($requestUri);
//   print_r($requestMethod);

//   if (isset($this->routes[$requestMethod])) {
//    foreach ($this->routes[$requestMethod] as $route => $handler) {

//     $pattern = preg_replace('/\{[a-zA-Z]+\}/', '([\w-]+)', $route);
//     if (preg_match("#^$pattern$#", $uri, $matches)) {
//      array_shift($matches); // Remove the full match from $ 
//      return call_user_func_array($handler, $matches);
//     }
//    }
//   }

//   // Return 404 if no matching route found
//   http_response_code(404);
//   echo json_encode(['error' => 'Route not found']);
//  }
// 

public function dispatch($requestUri, $requestMethod)
{
    $uri = strtok($requestUri, '?');
    $matches = [];

    if (isset($this->routes[$requestMethod])) {
        foreach ($this->routes[$requestMethod] as $route => $handler) {

            // Convert route to a regex pattern and support custom regex inside {param:regex}
            $pattern = preg_replace_callback(
                '/\{([a-zA-Z0-9_]+):([^}]+)\}/',
                function ($matches) {
                    return '(' . $matches[2] . ')'; // Return the custom regex for parameter
                },
                $route
            );

            // Simple pattern for non-custom parameters {param} -> matches alphanumeric, dashes, underscores
            $pattern = preg_replace('/\{[a-zA-Z0-9_]+\}/', '([\w-]+)', $pattern);

            if (preg_match("#^$pattern$#", $uri, $matches)) {
                array_shift($matches); // Remove full match
                return call_user_func_array($handler, $matches);
            }
        }
    }

    // Return 404 if no matching route found
    http_response_code(404);
    echo json_encode(['error' => 'Route not found']);
}

}