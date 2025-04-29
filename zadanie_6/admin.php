<?php

require ('database.php');

$admin = 0;
if (isset($_SERVER['PHP_AUTH_USER']) && isset($_SERVER['PHP_AUTH_PW'])) {
  $q = $db->prepare("SELECT id from users WHERE role = 'admin' and login = ? and password = ?");
  $q->execute([$_SERVER['PHP_AUTH_USER'], md5($_SERVER['PHP_AUTH_PW'])]);
  $admin = $q->rowCount();
}

if (!$admin) {
  header('HTTP/1.1 401 Unanthorized');
  header('WWW-Authenticate: Basic realm="My site"');
  print ('<h1>401 Требуется авторизация</h1>');
  exit();
}

print ('Вы успешно авторизовались и видите защищенные паролем данные.');

session_start();

if (count($_POST)) {
  $keyPost = key($_POST);
  if (empty($_SESSION['rem_but']) || $_SESSION['rem_but'] != $keyPost) {
    $id = explode('-', $keyPost)[1];

    if (!preg_match('/^[0-9]+$/', $id))
      exit("Введите id");

    $dbf = $db->prepare("SELECT * FROM form_data WHERE id = ?");
    $dbf->execute([$id]);
    if ($dbf->rowCount() != 0) {
      $dels = $db->prepare("DELETE FROM form_data WHERE id = ?");
      $dels->execute([$id]);
      $dels = $db->prepare("DELETE FROM form_data_lang WHERE id_form = ?");
      if (!$dels->execute([$id]))
        exit("Ошибка удаления");
    } else
      exit("Форма не найдена");

    $_SESSION['rem_but'] = $keyPost;
  }
}

?>

<!DOCTYPE html>
<html lang="ru">

<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="stylesheet" href="bootstrap.min.css">
  <link rel="stylesheet" href="adm.css">
  <title>Задание_6_админка</title>
</head>

<body>
  <form method="post" action="">
    <table class="table1">
      <thead>
        <tr>
          <th>id</th>
          <th>ФИО</th>
          <th>Телефон</th>
          <th>Почта</th>
          <th>Дата рождения</th>
          <th>Пол</th>
          <th>Биография</th>
          <th>ЯП</th>
          <th>Редактирование</th>
          <th>Удаление</th>
        </tr>
      </thead>
      <tbody>
        <?php
        $dbFD = $db->query("SELECT * FROM form_data ORDER BY id DESC");
        while ($row = $dbFD->fetch(PDO::FETCH_ASSOC)) {
          echo '<tr data-id=' . $row['id'] . '>
                  <td>' . $row['id'] . '</td>
                  <td>' . $row['fio'] . '</td>
                  <td>' . $row['number'] . '</td>
                  <td>' . $row['email'] . '</td>
                  <td>' . $row['dat'] . '</td>
                  <td>' . (($row['radio'] == "M") ? "Мужской" : "Женский") . '</td>
                  <td>' . $row['bio'] . '</td>
                  <td>';
          $dbl = $db->prepare("SELECT * FROM form_data_lang fd
                                JOIN languages l ON l.id = fd.id_lang
                                WHERE id_form = ?");
          $dbl->execute([$row['id']]);
          while ($row1 = $dbl->fetch(PDO::FETCH_ASSOC))
            echo $row1['name'] . '<br>';
          echo '</td>
                <td><a href="index.php?uid=' . $row['user_id'] . '" target="_blank">Редактировать</a></td>
                <td><button name="butt-' . $row['id'] . '" class="remove">Удалить</button></td>
              </tr>';
        }
        ?>
      </tbody>
    </table>
  </form>


  <table class="table2">
    <tr>
      <td>Язык программирования</td>
      <td>Количество пользователей</td>
    </tr>
    <tbody>
      <?php
      $q = $db->query("SELECT l.id, l.name, count(fd.id_form) as count FROM languages l 
                        LEFT JOIN form_data_lang fd ON fd.id_lang = l.id
                        GROUP by l.id");
      while ($row = $q->fetch(PDO::FETCH_ASSOC))
        echo '<tr>
          <td>' . $row['name'] . '</td>
          <td>' . $row['count'] . '</td>';
      ?>

    </tbody>
  </table>
</body>

</html>
