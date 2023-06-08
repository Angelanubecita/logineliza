<?php
session_start();

if (isset($_SESSION['user_id'])) {
  header('Location: /prueba/welcome.php');
}

require 'database.php';

$message = '';

if (!empty($_POST['email']) && !empty($_POST['password']) && !empty($_POST['confirm_password'])) {
  if ($_POST['password'] !== $_POST['confirm_password']) {
    $message = 'Passwords do not match. Please try again.';
  } else {
    // Verificar el recaptcha
    $secretKey = '6Lcn4NMlAAAAACOoBrUlFlTsER4D0i0G55tLDUEC';
    $response = $_POST['g-recaptcha-response'];
    $remoteIP = $_SERVER['REMOTE_ADDR'];

    $url = file_get_contents("https://www.google.com/recaptcha/api/siteverify?secret=$secretKey&response=$response&remoteip=$remoteIP");
    $responseKeys = json_decode($url, true);

    if ($responseKeys["success"]) {
      $email = $_POST['email'];
      $password = password_hash($_POST['password'], PASSWORD_BCRYPT);

      $stmt = $conn->prepare('SELECT id FROM users WHERE email = :email');
      $stmt->bindParam(':email', $email);
      $stmt->execute();

      if ($stmt->rowCount() > 0) {
        $message = 'Email already exists. Please try again with a different email.';
      } else {
        $stmt = $conn->prepare('INSERT INTO users (email, password) VALUES (:email, :password)');
        $stmt->bindParam(':email', $email);
        $stmt->bindParam(':password', $password);

        if ($stmt->execute()) {
          $message = 'Successfully created new user';

          // Insertar registro en la tabla log_login
          $fecha_hora = date('Y-m-d H:i:s');
          $ip_address = $_SERVER['REMOTE_ADDR'];
          $navegador = $_SERVER['HTTP_USER_AGENT'];
          $os_type = php_uname('s');

          $insert_login = $conn->prepare('INSERT INTO log_login (resultado, fecha_hora, email, ip, navegador, SO, validation)
                                         VALUES (:resultado, :fecha_hora, :email, :ip, :navegador, :SO, :validation)');
          $insert_login->bindValue(':resultado', 'éxito');
          $insert_login->bindValue(':fecha_hora', $fecha_hora);
          $insert_login->bindValue(':email', $email);
          $insert_login->bindValue(':ip', $ip_address);
          $insert_login->bindValue(':navegador', $navegador);
          $insert_login->bindValue(':SO', $os_type);
          $insert_login->bindValue(':validation', 'encontrado');
          $insert_login->execute();
        } else {
          $message = 'Sorry, there was an issue creating your account. Please try again.';
        }
      }
    } else {
      $message = 'reCAPTCHA verification failed. Please try again.';
    }
  }
}
?>

<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Signup Below</title>
    <link href="https://fonts.googleapis.com/css?family=Roboto" rel="stylesheet">
    <link rel="stylesheet" href="assets/css/style.css">
    <style>
      body {
        background-color: #3498db; /* Fondo azul */
      }

      .center {
        margin: auto;
        width: 300px;
        padding: 40px;
        border: 5px solid #ccc;
        border-radius: 10px;
        background-color: #ffcccc; /* Cuadro rosa */
      }

      .center h1 {
        text-align: center;
      }

      .center span {
        display: block;
        text-align: center;
        margin-top: 10px;
      }

      .center form {
        margin-top: 20px;
      }

      .center input[name="email"],
      .center input[name="password"],
      .center input[name="confirm_password"] {
        width: 100%;
        padding: 10px;
        margin-bottom: 10px;
      }

      .center input[type="submit"] {
        width: 100%;
        padding: 10px;
        background-color: #4caf50;
        color: #ffffff;
        border: none;
        border-radius: 5px;
        cursor: pointer;
      }

      .center input[type="submit"]:hover {
        background-color: #45a049;
      }

      .center p {
        text-align: center;
      }
    </style>
    <script src="https://www.google.com/recaptcha/api.js" async defer></script>
  </head>
  <body>
    <?php require 'partials/header.php' ?>

    <div class="center">
      <?php if(!empty($message)): ?>
        <p><?= $message ?></p>
      <?php endif; ?>

      <h1>Signup</h1>
      <span>or <a href="login.php">Login</a></span>

      <form action="signup.php" method="POST">
        <input name="email" type="text" placeholder="Enter your email">
        <input name="password" type="password" placeholder="Enter your Password">
        <input name="confirm_password" type="password" placeholder="Confirm your Password">
        <div class="g-recaptcha" data-sitekey="6Lcn4NMlAAAAADnx1irCKZ2Gs6gx0qCVO5wOVeNO"></div>
        <input type="submit" value="Submit">
      </form>
    </div>
  </body>
</html>


