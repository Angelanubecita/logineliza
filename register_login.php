<?php
require 'database.php';

$fecha_hora = date('Y-m-d H:i:s');
$navegador = $_SERVER['HTTP_USER_AGENT'];
$os_type = php_uname('s');

// Obtén los datos del usuario desde el formulario o desde la sesión
$email = $_POST['email']; // Asegúrate de que esta variable esté definida correctamente
$ip_address = $_SERVER['REMOTE_ADDR'];
$validation = 'éxito';

$insert_login = $conn->prepare('INSERT INTO log_login (resultado, fecha_hora, email, ip, navegador, SO, validation)
                               VALUES (:resultado, :fecha_hora, :email, :ip, :navegador, :SO, :validation)');
$insert_login->bindParam(':resultado', $validation);
$insert_login->bindParam(':fecha_hora', $fecha_hora);
$insert_login->bindParam(':email', $email);
$insert_login->bindParam(':ip', $ip_address);
$insert_login->bindParam(':navegador', $navegador);
$insert_login->bindParam(':SO', $os_type);
$insert_login->bindParam(':validation', $validation);
$insert_login->execute();
?>
