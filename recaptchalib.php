<?php
  /**
   * Esta es la biblioteca de verificación de reCAPTCHA para PHP.
   *
   * @see  https://developers.google.com/recaptcha/docs/verify
   */

  /**
   * Envía una solicitud para verificar el reCAPTCHA.
   *
   * @param  string  $secret  La clave secreta compartida entre su sitio y reCAPTCHA.
   * @param  string  $response  La respuesta a la verificación, desde el campo "g-recaptcha-response".
   * @param  string  $remoteip  (opcional) La dirección IP del usuario que envió la respuesta.
   * @return object  La respuesta de la verificación en forma de objeto.
   */
  function recaptcha_verify($secret, $response, $remoteip = null) {
    $url = 'https://www.google.com/recaptcha/api/siteverify';
    $data = array(
      'secret' => $secret,
      'response' => $response
    );

    if ($remoteip) {
      $data['remoteip'] = $remoteip;
    }

    $options = array(
      'http' => array(
        'header'  => "Content-type: application/x-www-form-urlencoded\r\n",
        'method'  => 'POST',
        'content' => http_build_query($data)
      )
    );

    $context  = stream_context_create($options);
    $result = file_get_contents($url, false, $context);
    return json_decode($result);
  }

  /**
   * Devuelve el código HTML para incluir el reCAPTCHA.
   *
   * @param  string  $site_key  La clave del sitio proporcionada por reCAPTCHA.
   * @return string  El código HTML para incluir el reCAPTCHA.
   */
  function recaptcha_html($site_key) {
    return '<div class="g-recaptcha" data-sitekey="'.$site_key.'"></div>';
  }
?>
