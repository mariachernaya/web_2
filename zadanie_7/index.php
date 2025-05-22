<?php
ini_set('display_errors', 0);
ini_set('log_errors', 1);
ini_set('error_log', __DIR__ . '/php-errors.log');

$db;
include ('database.php');
header("Content-Type: text/html; charset=UTF-8");
session_start();

if (strpos($_SERVER['REQUEST_URI'], 'index.php') === false) {
    header('Location: index.php');
    exit();
}

$error = false;
$log = isset($_SESSION['login']);
$adminLog = isset($_SERVER['PHP_AUTH_USER']);
$uid = isset($_SESSION['user_id']) ? $_SESSION['user_id'] : '';
$getUid = isset($_GET['uid']) ? strip_tags($_GET['uid']) : '';

if ($adminLog && preg_match('/^[0-9]+$/', $getUid)) {
    $uid = $getUid;
    $log = true;
}

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $fio = isset($_POST['fio']) ? $_POST['fio'] : '';
    $number = isset($_POST['number']) ? $_POST['number'] : '';
    $email = isset($_POST['email']) ? $_POST['email'] : '';
    $date = isset($_POST['date']) ? $_POST['date'] : '';
    $radio = isset($_POST['radio']) ? $_POST['radio'] : '';
    $language = isset($_POST['language']) ? $_POST['language'] : [];
    $bio = isset($_POST['bio']) ? $_POST['bio'] : '';
    $check = isset($_POST['check']) ? $_POST['check'] : '';

    if (isset($_POST['logout_form'])) {
        if ($adminLog && empty($_SESSION['login']))
            header('Location: admin.php');
        else {
            setcookie('fio_value', '', time() - 30 * 24 * 60 * 60);
            setcookie('number_value', '', time() - 30 * 24 * 60 * 60);
            setcookie('email_value', '', time() - 30 * 24 * 60 * 60);
            setcookie('date_value', '', time() - 30 * 24 * 60 * 60);
            setcookie('radio_value', '', time() - 30 * 24 * 60 * 60);
            setcookie('language_value', '', time() - 30 * 24 * 60 * 60);
            setcookie('bio_value', '', time() - 30 * 24 * 60 * 60);
            setcookie('check_value', '', time() - 30 * 24 * 60 * 60);
            session_destroy();
            header('Location: index.php' . (($getUid != NULL) ? '?uid=' . $uid : ''));
        }
        exit();
    }

    function check_pole($cook, $str, $flag)
    {
        global $error;
        $res = false;
        $setval = isset($_POST[$cook]) ? $_POST[$cook] : '';
        if ($flag) {
            setcookie($cook . '_error', $str, time() + 24 * 60 * 60);
            $error = true;
            $res = true;
        }
        if ($cook == 'language') {
            global $language;
            $setval = ($language != '') ? implode(",", $language) : '';
        }
        setcookie($cook . '_value', $setval, time() + 30 * 24 * 60 * 60);
        return $res;
    }

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
            $inQuery = implode(',', array_fill(0, count($language), '?'));
            $dbLangs = $db->prepare("SELECT id, name FROM languages WHERE name IN ($inQuery)");
            foreach ($language as $key => $value)
                $dbLangs->bindValue(($key + 1), $value);
            $dbLangs->execute();
            $languages = $dbLangs->fetchAll(PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
            print ('Error : ' . $e->getMessage());
            exit();
        }
        check_pole('language', 'Неверно выбраны языки', $dbLangs->rowCount() != count($language));
    }

    if (!$error) {
        setcookie('fio_error', '', time() - 30 * 24 * 60 * 60);
        setcookie('number_error', '', time() - 30 * 24 * 60 * 60);
        setcookie('email_error', '', time() - 30 * 24 * 60 * 60);
        setcookie('date_error', '', time() - 30 * 24 * 60 * 60);
        setcookie('radio_error', '', time() - 30 * 24 * 60 * 60);
        setcookie('language_error', '', time() - 30 * 24 * 60 * 60);
        setcookie('bio_error', '', time() - 30 * 24 * 60 * 60);
        setcookie('check_error', '', time() - 30 * 24 * 60 * 60);

        if ($log) {
            $stmt = $db->prepare("UPDATE form_data SET fio = ?, number = ?, email = ?, dat = ?, radio = ?, bio = ? WHERE user_id = ?");
            $stmt->execute([$fio, $number, $email, $date, $radio, $bio, $_SESSION['user_id']]);

            $stmt = $db->prepare("DELETE FROM form_data_lang WHERE id_form = ?");
            $stmt->execute([$_SESSION['form_id']]);

            $stmt1 = $db->prepare("INSERT INTO form_data_lang (id_form, id_lang) VALUES (?, ?)");
            foreach ($languages as $row)
                $stmt1->execute([$_SESSION['form_id'], $row['id']]);
            if ($adminLog)
                setcookie('admin_value', '1', time() + 30 * 24 * 60 * 60);
        } else {
            $login = uniqid();
            $pass = uniqid();
            setcookie('login', $login);
            setcookie('pass', $pass);
            $mpass = md5($pass);
            try {
                $stmt = $db->prepare("INSERT INTO users (login, password) VALUES (?, ?)");
                $stmt->execute([$login, $mpass]);
                $user_id = $db->lastInsertId();

                $stmt = $db->prepare("INSERT INTO form_data (user_id, fio, number, email, dat, radio, bio) VALUES (?, ?, ?, ?, ?, ?, ? )");
                $stmt->execute([$user_id, $fio, $number, $email, $date, $radio, $bio]);
                $fid = $db->lastInsertId();

                $stmt1 = $db->prepare("INSERT INTO form_data_lang (id_form, id_lang) VALUES (?, ?)");
                foreach ($languages as $row)
                    $stmt1->execute([$fid, $row['id']]);
            } catch (PDOException $e) {
                print ('Error : ' . $e->getMessage());
                exit();
            }
            setcookie('fio_value', $fio, time() + 24 * 60 * 60 * 365);
            setcookie('number_value', $number, time() + 24 * 60 * 60 * 365);
            setcookie('email_value', $email, time() + 24 * 60 * 60 * 365);
            setcookie('date_value', $date, time() + 24 * 60 * 60 * 365);
            setcookie('radio_value', $radio, time() + 24 * 60 * 60 * 365);
            setcookie('language_value', implode(",", $language), time() + 24 * 60 * 60 * 365);
            setcookie('bio_value', $bio, time() + 24 * 60 * 60 * 365);
            setcookie('check_value', $check, time() + 24 * 60 * 60 * 365);
        }
        setcookie('save', '1');
    }
    header('Location: index.php' . (($getUid != NULL) ? '?uid=' . $uid : ''));
} else {
    if (($adminLog && !empty($getUid)) || !$adminLog) {
        $cookAdmin = (!empty($_COOKIE['admin_value']) ? $_COOKIE['admin_value'] : '');
        if ($cookAdmin == '1') {
            setcookie('fio_value', '', time() - 30 * 24 * 60 * 60);
            setcookie('number_value', '', time() - 30 * 24 * 60 * 60);
            setcookie('email_value', '', time() - 30 * 24 * 60 * 60);
            setcookie('date_value', '', time() - 30 * 24 * 60 * 60);
            setcookie('radio_value', '', time() - 30 * 24 * 60 * 60);
            setcookie('language_value', '', time() - 30 * 24 * 60 * 60);
            setcookie('bio_value', '', time() - 30 * 24 * 60 * 60);
            setcookie('check_value', '', time() - 30 * 24 * 60 * 60);
        }
    }

    $fio = !empty($_COOKIE['fio_error']) ? $_COOKIE['fio_error'] : '';
    $number = !empty($_COOKIE['number_error']) ? $_COOKIE['number_error'] : '';
    $email = !empty($_COOKIE['email_error']) ? $_COOKIE['email_error'] : '';
    $date = !empty($_COOKIE['date_error']) ? $_COOKIE['date_error'] : '';
    $radio = !empty($_COOKIE['radio_error']) ? $_COOKIE['radio_error'] : '';
    $language = !empty($_COOKIE['language_error']) ? $_COOKIE['language_error'] : '';
    $bio = !empty($_COOKIE['bio_error']) ? $_COOKIE['bio_error'] : '';
    $check = !empty($_COOKIE['check_error']) ? $_COOKIE['check_error'] : '';

    $errors = array();
    $messages = array();
    $values = array();
    $error = true;

    function set_val($str, $pole)
    {
        global $values;
        $values[$str] = empty($pole) ? '' : strip_tags($pole);
    }

    function check_pole($str, $pole)
    {
        global $errors, $messages, $values, $error;
        if ($error)
            $error = empty($_COOKIE[$str . '_error']);
        $errors[$str] = !empty($_COOKIE[$str . '_error']);
        $messages[$str] = "<div class=\"error\">$pole</div>";
        $values[$str] = empty($_COOKIE[$str . '_value']) ? '' : strip_tags($_COOKIE[$str . '_value']);
        setcookie($str . '_error', '', time() - 30 * 24 * 60 * 60);
        return;
    }

    if (!empty($_COOKIE['save'])) {
        setcookie('save', '', 100000);
        setcookie('login', '', 100000);
        setcookie('pass', '', 100000);
        $messages['success'] = 'Спасибо, результаты сохранены.';
        if (!empty($_COOKIE['pass']))
            $messages['info'] = sprintf('Вы можете <a href="login.php">войти</a> с логином <strong>%s</strong><br>
            и паролем <strong>%s</strong> для изменения данных.', strip_tags($_COOKIE['login']), strip_tags($_COOKIE['pass']));
    }

    check_pole('fio', $fio);
    check_pole('number', $number);
    check_pole('email', $email);
    check_pole('date', $date);
    check_pole('radio', $radio);
    check_pole('language', $language);
    check_pole('bio', $bio);
    check_pole('check', $check);

    $languages = explode(',', $values['language']);

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
            foreach ($dbL->fetchAll(PDO::FETCH_ASSOC) as $item)
                $languages[] = $item['name'];

            set_val('fio', $user_inf['fio']);
            set_val('number', $user_inf['number']);
            set_val('email', $user_inf['email']);
            set_val('date', $user_inf['dat']);
            set_val('radio', $user_inf['radio']);
            set_val('language', $language);
            set_val('bio', $user_inf['bio']);
            set_val('check', "1");
        } catch (PDOException $e) {
            print ('Error : ' . $e->getMessage());
            exit();
        }
    }

    include ('form.php');
}
?>
