<?php
session_start();

if (!isset($_SESSION['user_id'])) {
  header("Location: login.php");
  exit;
}

?>


<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Welcome</title>
  <link href="https://fonts.googleapis.com/css?family=Roboto" rel="stylesheet">
  <link rel="stylesheet" href="assets/css/style.css">

  <style>
    .admin-section {
      background-color: #1BC82B;
      padding: 0px;
      border-radius: 5px;
      text-align: center;
    }

    .welcome-message {
      font-size: 18px;
      font-weight: bold;
    }

    .admin-title {
      font-size: 24px;
      margin-top: 20px;
    }

    .admin-description {
      font-size: 16px;
      margin-top: 10px;
    }

    .admin-menu {
      margin-top: 0px;
      text-align: center;
      background-color: #000000;
      padding: 0px;
      border-radius: 0px;
      display: flex;
      justify-content: center;
    }

    .admin-menu-item {
      margin: 10px;
    }

    .admin-menu-item a {
      display: block;
      padding: 10px 40px;
      background-color: #FF00F7;
      color: #000000;
      text-decoration: none;
      border-radius: 0px;
      transition: background-color 0.3s ease;
    }

    .admin-menu-item a:hover {
      background-color: #0D47A1;
    }

    .logout-link {
      display: inline-block;
      margin-top: 10px;
      color: #ffffff;
      background-color: #dc3545;
      padding: 12px 20px;
      text-decoration: none;
      border-radius: 5px;
      transition: background-color 0.3s ease;
    }

    .logout-link:hover {
      background-color: #c82333;
    }

    /* Estilos para el encabezado */
    .admin-header {
      background-color: #f5f5f5;
      background-color: #D3B1DF;
      padding: 20px;
      text-align: center;
      margin-bottom: 10px;
    }

    .admin-header h1 {
      margin: 0;
      font-size: 24px;
    }
  </style>
  <style>
      body {
        background-color: #D3B1DF;
      }
    </style>
</head>
<body>
  <div class="admin-header">
    <h1>Panel de Administracion</h1>
    
  </div>

  <?php if(isset($_SESSION['user_role']) && $_SESSION['user_role'] == 'admin'): ?>
    <br /><br />Has iniciado sesion como Administrador!
    <div class="admin-section">
        <div class="admin-menu">
            <div class="admin-menu-item">
                <a href="#">Inicio</a>
            </div>
            <div class="admin-menu-item">
                <a href="#">Pedidos</a>
            </div>
            <div class="admin-menu-item">
                <a href="#">Productos</a>
            </div>
            <div class="admin-menu-item">
                <a href="#">Categorías</a>
            </div>
            <div class="admin-menu-item">
                <a href="#">Diseño</a>
            </div>
            <div class="admin-menu-item">
                <a href="#">Marketing</a>
            </div>
            <div class="admin-menu-item">
                <a href="#">Opciones</a>
            </div>
            <div class="admin-menu-item">
                <a href="#">Ayuda</a>
            </div>
        </div>
       
    </div>
    <br><br><br><br><br><br><br><br><br><br><br><br><br><br><br>
    <a class="logout-link" href="logout.php">Logout</a>


  <?php elseif (isset($_SESSION['user_role']) && $_SESSION['user_role'] == 'user'): ?>
    <?php
    header("Location: index.php");
    exit;
    ?>
  <?php endif; ?>
  
</body>
</html>

