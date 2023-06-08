<?php

$server = 'localhost:3308';
$username = 'root';
$password = '';
$database = 'php_login';

try {
  $conn = new PDO("mysql:host=$server;dbname=$database;", $username, $password);
} catch (PDOException $e) {
  die('Connection Failed: ' . $e->getMessage());
}

?>
