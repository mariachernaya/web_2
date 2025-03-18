<?php

header("Content-Type: text/html, charset=UTF-8");
$error = false;

if($_SERVER['REQUEST_METHOD'] == 'POST')
{
    $fio = isset($_POST['fio']) ? $_POST['fio'] : '';
    $number = isset($_POST['number']) ? $_POST['number'] : '';
    $email = isset($_POST['email']) ? $_POST['email'] : '';
    $date = isset($_POST['date']) ? $_POST['date'] : '';
    $radio = isset($_POST['radio']) ? $_POST['radio'] : '';
    $language = isset($_POST['language']) ? $_POST['language'] : [];
    $bio = isset($_POST['bio']) ? $_POST['bio'] : '';
    $check = isset($_POST['check']) ? $_POST['check'] : '';
    
    function check_pole($cook, $str, $flag)
    {
        global $error;
        $res = false;
        $setval = isset($_POST[$cook]) ? $_POST[$cook] : '';
        if($flag)
        {
            setcookie($cook.'_error', $str, time() + 24*60*60);
            $error = true;
            $res = true;
        }
        if($cook == 'language')
        {
            global $language;
            $setval = ($language != '') ? implode(",", $language) : '';
        }
        setcookie($cook.'_value', $setval, time() + 30*24*60*60);
        return $res;
    }

    if(!check_pole('fio', 'Это поле пустое', empty($fio)))
        check_pole('fio', 'Неправильный формат: Имя Фамилия, только кириллица', !preg_match('/^([а-яё]+-?[а-яё]+)( [а-яё]+-?[а-яё]+){1,2}$/Diu', $fio));
    if(!check_pole('number', 'Это поле пустое', empty($number)))
    {
        check_pole('number', 'Неправильный формат, должно быть 11 символов', strlen($number) != 11);
        check_pole('number', 'Поле должно содержать только цифры', $number != preg_replace('/\D/', '', $number));
    }
    if(!check_pole('email', 'Это поле пустое', empty($email)))
        check_pole('email', 'Неправильный формат: example@mail.ru', !preg_match('/^\w+([.-]?\w+)@\w+([.-]?\w+)(.\w{2,3})+$/', $email));
    if(!check_pole('date', 'Это поле пустое', empty($date)))
        check_pole('date', 'Неправильная дата', strtotime('now') < strtotime($date));
    check_pole('radio', "Не выбран пол", empty($radio) || !preg_match('/^(M|W)$/', $radio));
    if(!check_pole('bio', 'Это поле пустое', empty($bio)))
        check_pole('bio', 'Слишком длинное поле, максимум символов - 65535', strlen($bio) > 65535);
    check_pole('check', 'Не ознакомлены с контрактом', empty($check));

	$user = 'u68790'; 
	$pass = '4247220'; 
	$db = new PDO('mysql:host=localhost;dbname=u68790', $user, $pass,
	[PDO::ATTR_PERSISTENT => true, PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]); 

    $inQuery = implode(',', array_fill(0, count($language), '?'));

    if(!check_pole('language', 'Не выбран язык', empty($language)))
    {
        try
        {
            $dbLangs = $db->prepare("SELECT id, name FROM languages WHERE name IN ($inQuery)");
            foreach ($language as $key => $value)
                $dbLangs->bindValue(($key+1), $value);
            $dbLangs->execute();
            $languages = $dbLangs->fetchAll(PDO::FETCH_ASSOC);
        }
        catch(PDOException $e)
        {
            print('Error : '.$e->getMessage());
            exit();
        }
        check_pole('language', 'Неверно выбраны языки', $dbLangs->rowCount() != count($language));
    }
    
    if (!$error)
    {
        setcookie('fio_error', '', time() - 30 * 24 * 60 * 60);
        setcookie('number_error', '', time() - 30 * 24 * 60 * 60);
        setcookie('email_error', '', time() - 30 * 24 * 60 * 60);
        setcookie('date_error', '', time() - 30 * 24 * 60 * 60);
        setcookie('radio_error', '', time() - 30 * 24 * 60 * 60);
        setcookie('language_error', '', time() - 30 * 24 * 60 * 60);
        setcookie('bio_error', '', time() - 30 * 24 * 60 * 60);
        setcookie('check_error', '', time() - 30 * 24 * 60 * 60);
        try
        {
            $stmt = $db->prepare("INSERT INTO form_data (fio, number, email, date, radio, bio) VALUES (?, ?, ?, ?, ?, ?)");
            $stmt->execute([$fio, $number, $email, date("l",strtotime($date)), $radio, $bio]);
            $fid = $db->lastInsertId();
            $stmt1 = $db->prepare("INSERT INTO form_data_lang (id_form, id_lang) VALUES (?, ?)");
            foreach($languages as $row)
                $stmt1->execute([$fid, $row['id']]);
        }
        catch(PDOException $e)
        {
            print('Error : ' . $e->getMessage());
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

        setcookie('save', '1');
    }
    header('Location: index.php');
}
else
{
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

    function check_pole($str, $pole)
    {
        global $errors, $messages, $values;
        $errors[$str] = !empty($pole);
        $messages[$str] = "<div class=\"error\">$pole</div>";
        $values[$str] = empty($_COOKIE[$str.'_value']) ? '' : $_COOKIE[$str.'_value'];
        setcookie($str.'_error', '', time() - 30 * 24 * 60 * 60);
        return;
    }

    if (!empty($_COOKIE['save']))
    {
        setcookie('save', '', 100000);
        $messages['success'] = '<div class="message">Данные сохранены</div>';
    }
    else
        $messages['success'] = '';
       
    check_pole('fio', $fio);
    check_pole('number', $number);
    check_pole('email', $email);
    check_pole('date', $date);
    check_pole('radio', $radio);
    check_pole('language', $language);
    check_pole('bio', $bio);
    check_pole('check', $check);

    $languages = explode(',', $values['language']);

    include('form.php');
}
?>
