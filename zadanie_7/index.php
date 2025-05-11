<?php

// Настройки безопасности
ini_set('display_errors', 0);
ini_set('log_errors', 1);
ini_set('error_log', __DIR__ . '/php-errors.log');

$db;
include ('database.php');
header("Content-Type: text/html; charset=UTF-8");

// Усиленные настройки сессии
session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'domain' => $_SERVER['HTTP_HOST'],
    'secure' => true,
    'httponly' => true,
    'samesite' => 'Strict'
]);
session_start();

if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Функция для санитизации входных данных
function sanitizeInput($input, $type = 'string') {
    if (is_array($input)) {
        return array_map('sanitizeInput', $input);
    }
    switch ($type) {
        case 'int':
            return filter_var($input, FILTER_SANITIZE_NUMBER_INT);
        case 'email':
            return filter_var($input, FILTER_SANITIZE_EMAIL);
        case 'string':
        default:
            return htmlspecialchars(strip_tags($input), ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }
}

// Проверка URI
if (strpos($_SERVER['REQUEST_URI'], 'index.php') === false) {
    header('Location: index.php');
    exit();
}

$error = false;
$log = isset($_SESSION['login']);
$adminLog = isset($_SERVER['PHP_AUTH_USER']);
$uid = isset($_SESSION['user_id']) ? sanitizeInput($_SESSION['user_id'], 'int') : '';
$getUid = isset($_GET['uid']) ? sanitizeInput($_GET['uid'], 'int') : '';

if ($adminLog && preg_match('/^[0-9]+$/', $getUid)) {
    $uid = $getUid;
    $log = true;
}

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // CSRF защита
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        error_log('CSRF token validation failed');
        die('Неверный токен безопасности. Пожалуйста, отправьте форму еще раз.');
    }

    $fio = isset($_POST['fio']) ? sanitizeInput($_POST['fio']) : '';
    $number = isset($_POST['number']) ? sanitizeInput($_POST['number']) : '';
    $email = isset($_POST['email']) ? sanitizeInput($_POST['email'], 'email') : '';
    $date = isset($_POST['date']) ? sanitizeInput($_POST['date']) : '';
    $radio = isset($_POST['radio']) ? sanitizeInput($_POST['radio']) : '';
    $language = isset($_POST['language']) ? array_map('sanitizeInput', $_POST['language']) : [];
    $bio = isset($_POST['bio']) ? sanitizeInput($_POST['bio']) : '';
    $check = isset($_POST['check']) ? sanitizeInput($_POST['check']) : '';

    if (isset($_POST['logout_form'])) {
        if ($adminLog && empty($_SESSION['login'])) {
            header('Location: admin.php');
        } else {
            $cookies = ['fio_value', 'number_value', 'email_value', 'date_value', 
                       'radio_value', 'language_value', 'bio_value', 'check_value'];
            foreach ($cookies as $cookie) {
                setcookie($cookie, '', time() - 30 * 24 * 60 * 60, '/', $_SERVER['HTTP_HOST'], true, true);
            }
            session_destroy();
            header('Location: index.php' . (!empty($getUid) ? '?uid=' . $uid : ''));
        }
        exit();
    }

    function check_pole($cook, $str, $flag) {
        global $error;
        $res = false;
        $setval = isset($_POST[$cook]) ? $_POST[$cook] : '';
        if ($flag) {
            setcookie($cook . '_error', $str, time() + 24 * 60 * 60, '/', $_SERVER['HTTP_HOST'], true, true);
            $error = true;
            $res = true;
        }
        if ($cook == 'language') {
            global $language;
            $setval = (!empty($language)) ? implode(",", $language) : '';
        }
        setcookie($cook . '_value', $setval, time() + 30 * 24 * 60 * 60, '/', $_SERVER['HTTP_HOST'], true, true);
        return $res;
    }

    // Валидация полей (остается без изменений, но с санитизированными данными)
    if (!check_pole('fio', 'Это поле пустое', empty($fio)))
        check_pole('fio', 'Неправильный формат: Имя Фамилия (Отчество), только кириллица', !preg_match('/^([а-яё]+-?[а-яё]+)( [а-яё]+-?[а-яё]+){1,2}$/Diu', $fio));
    if (!check_pole('number', 'Это поле пустое', empty($number))) {
        check_pole('number', 'Неправильный формат, должно быть 11 символов', strlen($number) != 11);
        check_pole('number', 'Поле должно содержать только цифры', $number != preg_replace('/\D/', '', $number));
    }
    if (!check_pole('email', 'Это поле пустое', empty($email)))
        check_pole('email', 'Неправильный формат: example@mail.ru', !preg_match('/^\w+([.-]?\w+)@\w+([.-]?\w+)(.\w{2,3})+$/', $email));
    if (!check_pole('date', 'Это поле пустое', empty($date)))
        check_pole('date', 'Неправильная дата', strtotime('now') < strtotime($date));
    check_pole('radio', "Не выбран пол", empty($radio) || !preg_match('/^(M|W)$/', $radio));
    if (!check_pole('bio', 'Это поле пустое', empty($bio)))
        check_pole('bio', 'Слишком длинное поле, максимум символов - 65535', strlen($bio) > 65535);
    check_pole('check', 'Не ознакомлены с контрактом', empty($check));

    if (!check_pole('language', 'Не выбран язык', empty($language))) {
        try {
            $filteredLanguages = array_map('sanitizeInput', $language);
            $inQuery = implode(',', array_fill(0, count($filteredLanguages), '?'));
            $dbLangs = $db->prepare("SELECT id, name FROM languages WHERE name IN ($inQuery)");
            foreach ($filteredLanguages as $key => $value) {
                $dbLangs->bindValue(($key + 1), $value, PDO::PARAM_STR);
            }
            $dbLangs->execute();
            $languages = $dbLangs->fetchAll(PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
            error_log('Language selection error: ' . $e->getMessage());
            die('Ошибка при обработке языков.');
        }
        check_pole('language', 'Неверно выбраны языки', $dbLangs->rowCount() != count($filteredLanguages));
    }

    if (!$error) {
        $cookies = ['fio_error', 'number_error', 'email_error', 'date_error', 
                   'radio_error', 'language_error', 'bio_error', 'check_error'];
        foreach ($cookies as $cookie) {
            setcookie($cookie, '', time() - 30 * 24 * 60 * 60, '/', $_SERVER['HTTP_HOST'], true, true);
        }

        if ($log) {
            try {
                $stmt = $db->prepare("UPDATE form_data SET fio = ?, number = ?, email = ?, dat = ?, radio = ?, bio = ? WHERE user_id = ?");
                $stmt->execute([$fio, $number, $email, $date, $radio, $bio, $_SESSION['user_id']]);

                $stmt = $db->prepare("DELETE FROM form_data_lang WHERE id_form = ?");
                $stmt->execute([$_SESSION['form_id']]);

                $stmt1 = $db->prepare("INSERT INTO form_data_lang (id_form, id_lang) VALUES (?, ?)");
                foreach ($languages as $row) {
                    $stmt1->execute([$_SESSION['form_id'], $row['id']]);
                }
                if ($adminLog) {
                    setcookie('admin_value', '1', time() + 30 * 24 * 60 * 60, '/', $_SERVER['HTTP_HOST'], true, true);
                }
            } catch (PDOException $e) {
                error_log('Database update error: ' . $e->getMessage());
                die('Ошибка при обновлении данных.');
            }
        } else {
            $login = uniqid();
            $pass = uniqid();
            setcookie('login', $login, time() + 24 * 60 * 60, '/', $_SERVER['HTTP_HOST'], true, true);
            setcookie('pass', $pass, time() + 24 * 60 * 60, '/', $_SERVER['HTTP_HOST'], true, true);
            
            try {
                // Используем password_hash вместо md5
                $mpass = password_hash($pass, PASSWORD_DEFAULT);
                $stmt = $db->prepare("INSERT INTO users (login, password) VALUES (?, ?)");
                $stmt->execute([$login, $mpass]);
                $user_id = $db->lastInsertId();

                $stmt = $db->prepare("INSERT INTO form_data (user_id, fio, number, email, dat, radio, bio) VALUES (?, ?, ?, ?, ?, ?, ?)");
                $stmt->execute([$user_id, $fio, $number, $email, $date, $radio, $bio]);
                $fid = $db->lastInsertId();

                $stmt1 = $db->prepare("INSERT INTO form_data_lang (id_form, id_lang) VALUES (?, ?)");
                foreach ($languages as $row) {
                    $stmt1->execute([$fid, $row['id']]);
                }
            } catch (PDOException $e) {
                error_log('User creation error: ' . $e->getMessage());
                die('Ошибка при создании пользователя.');
            }
            
            $cookies = [
                'fio_value' => $fio,
                'number_value' => $number,
                'email_value' => $email,
                'date_value' => $date,
                'radio_value' => $radio,
                'language_value' => implode(",", $language),
                'bio_value' => $bio,
                'check_value' => $check
            ];
            
            foreach ($cookies as $name => $value) {
                setcookie($name, $value, time() + 24 * 60 * 60 * 365, '/', $_SERVER['HTTP_HOST'], true, true);
            }
        }
        setcookie('save', '1', time() + 24 * 60 * 60, '/', $_SERVER['HTTP_HOST'], true, true);
    }
    header('Location: index.php' . (!empty($getUid) ? '?uid=' . $uid : ''));
} else {
    if (($adminLog && !empty($getUid)) || !$adminLog) {
        $cookAdmin = !empty($_COOKIE['admin_value']) ? sanitizeInput($_COOKIE['admin_value']) : '';
        if ($cookAdmin == '1') {
            $cookies = ['fio_value', 'number_value', 'email_value', 'date_value', 
                       'radio_value', 'language_value', 'bio_value', 'check_value'];
            foreach ($cookies as $cookie) {
                setcookie($cookie, '', time() - 30 * 24 * 60 * 60, '/', $_SERVER['HTTP_HOST'], true, true);
            }
        }
    }

    $fio = !empty($_COOKIE['fio_error']) ? sanitizeInput($_COOKIE['fio_error']) : '';
    $number = !empty($_COOKIE['number_error']) ? sanitizeInput($_COOKIE['number_error']) : '';
    $email = !empty($_COOKIE['email_error']) ? sanitizeInput($_COOKIE['email_error']) : '';
    $date = !empty($_COOKIE['date_error']) ? sanitizeInput($_COOKIE['date_error']) : '';
    $radio = !empty($_COOKIE['radio_error']) ? sanitizeInput($_COOKIE['radio_error']) : '';
    $language = !empty($_COOKIE['language_error']) ? sanitizeInput($_COOKIE['language_error']) : '';
    $bio = !empty($_COOKIE['bio_error']) ? sanitizeInput($_COOKIE['bio_error']) : '';
    $check = !empty($_COOKIE['check_error']) ? sanitizeInput($_COOKIE['check_error']) : '';

    $errors = array();
    $messages = array();
    $values = array();
    $error = true;

    function set_val($str, $pole) {
        global $values;
        $values[$str] = empty($pole) ? '' : sanitizeInput($pole);
    }

    function check_pole($str, $pole) {
        global $errors, $messages, $values, $error;
        if ($error) {
            $error = empty($_COOKIE[$str . '_error']);
        }
        $errors[$str] = !empty($_COOKIE[$str . '_error']);
        $messages[$str] = "<div class=\"error\">" . sanitizeInput($pole) . "</div>";
        $values[$str] = empty($_COOKIE[$str . '_value']) ? '' : sanitizeInput($_COOKIE[$str . '_value']);
        setcookie($str . '_error', '', time() - 30 * 24 * 60 * 60, '/', $_SERVER['HTTP_HOST'], true, true);
        return;
    }

    if (!empty($_COOKIE['save'])) {
        setcookie('save', '', time() - 30 * 24 * 60 * 60, '/', $_SERVER['HTTP_HOST'], true, true);
        setcookie('login', '', time() - 30 * 24 * 60 * 60, '/', $_SERVER['HTTP_HOST'], true, true);
        setcookie('pass', '', time() - 30 * 24 * 60 * 60, '/', $_SERVER['HTTP_HOST'], true, true);
        $messages['success'] = 'Спасибо, результаты сохранены.';
        if (!empty($_COOKIE['pass'])) {
            $messages['info'] = sprintf(
                'Вы можете <a href="login.php">войти</a> с логином <strong>%s</strong><br>
                и паролем <strong>%s</strong> для изменения данных.',
                sanitizeInput($_COOKIE['login']),
                sanitizeInput($_COOKIE['pass'])
            );
        }
    }

    check_pole('fio', $fio);
    check_pole('number', $number);
    check_pole('email', $email);
    check_pole('date', $date);
    check_pole('radio', $radio);
    check_pole('language', $language);
    check_pole('bio', $bio);
    check_pole('check', $check);

    $languages = !empty($values['language']) ? explode(',', $values['language']) : [];

    if ($error && $log) {
        try {
            $dbLangs = $db->prepare("SELECT * FROM form_data WHERE user_id = ?");
            $dbLangs->execute([$uid]);
            $user_inf = $dbLangs->fetchAll(PDO::FETCH_ASSOC)[0];

            $form_id = $user_inf['id'];
            $_SESSION['form_id'] = $form_id;

            $dbL = $db->prepare("SELECT l.name FROM form_data_lang f
                                JOIN languages l ON l.id = f.id_lang
                                WHERE f.id_form = ?");
            $dbL->execute([$form_id]);

            $languages = [];
            foreach ($dbL->fetchAll(PDO::FETCH_ASSOC) as $item) {
                $languages[] = sanitizeInput($item['name']);
            }

            set_val('fio', $user_inf['fio']);
            set_val('number', $user_inf['number']);
            set_val('email', $user_inf['email']);
            set_val('date', $user_inf['dat']);
            set_val('radio', $user_inf['radio']);
            set_val('language', implode(',', $languages));
            set_val('bio', $user_inf['bio']);
            set_val('check', "1");
        } catch (PDOException $e) {
            error_log('User data fetch error: ' . $e->getMessage());
            die('Ошибка при получении данных пользователя.');
        }
    }

    include ('form.php');
}
?>
