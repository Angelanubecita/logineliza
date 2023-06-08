<?php
session_start();

if (!isset($_SESSION['user_id']) || !isset($_SESSION['user_role'])) {
    // Redirige al usuario a la página de inicio de sesión
    header("Location: /prueba/login.php");
    exit();
}

$allowed_roles_admin = ['administrador'];

if (basename($_SERVER['PHP_SELF']) === 'admin.php' && !in_array($_SESSION['user_role'], $allowed_roles_admin)) {
    // Redirige al usuario a la página de inicio de sesión
    header("Location: /prueba/login.php");
    exit();
}
?>

<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Bienvenido</title>
    <link href="https://fonts.googleapis.com/css?family=Roboto" rel="stylesheet">
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body>
<?php require 'partials/header.php' ?>

<?php if (!empty($user)) : ?>
    <br />Bienvenido administrador <?= $user['email']; ?>
    <br /><br />¡Has iniciado sesión correctamente!
    <br /><br /><a href="logout.php">¿Cerrar sesión?</a>
<?php endif; ?>
</body>
</html>
