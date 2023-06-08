<?php
session_start();

if (isset($_SESSION['user_id'])) {
  require 'database.php';

  $records = $conn->prepare('SELECT id, email, password, rol_id FROM users WHERE id = :id');
  $records->bindParam(':id', $_SESSION['user_id']);
  $records->execute();
  $results = $records->fetch(PDO::FETCH_ASSOC);

  $user = null;

  if (count($results) > 0) {
    $user = $results;
  }
} else {
  header("Location: login.php");
  exit;
}
?>

<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Welcome to your WebApp</title>
    <link href="https://fonts.googleapis.com/css?family=Roboto" rel="stylesheet">
    <link rel="stylesheet" href="assets/css/style.css">
    
    <style>
      body {
        background-color: #D3B1DF;
      }
    </style>
  </head>
  <body>
    <?php require 'partials/header.php' ?>

    <?php if (!empty($user)): ?>
      <?php if ($user['rol_id'] === 1): ?>
        <h1>Panel de Usuario</h1>
        <h1>Welcome, <?= $user['email']; ?></h1>
       
        <a href="logout.php">Logout</a>
      <?php else: ?>
        <?php header("Location: welcome.php"); ?>
      <?php endif; ?>
    <?php else: ?>
      <h1>WELCOME</h1>

      <a href="login.php">Iniciar Sesión</a> or
      <a href="signup.php">Registrarse</a>
    <?php endif; ?>
  </body>
</html>

