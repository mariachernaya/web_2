<!DOCTYPE html>
<html lang="ru">
  <head>
    <meta charset="UTF-8" />
    <link rel="stylesheet" href="style.css" />
    <link rel="stylesheet" href="bootstrap.min.css" />
    <title>№3</title>
  </head>
  <body>
	  <form action="" method="POST" class="form">
    <div>
      <div class="head">
        <h2><b>Форма обратной связи</b></h2>
      </div>

      <div>
        <label> <input name="fio" class="input" placeholder="ФИО" /> </label>
      </div>

      <div>
        <label> <input type="tel" name="number" class="input" placeholder="Номер телефона" /> </label>
      </div>

      <div>
        <label> <input name="email" type="email" class="input" placeholder="Почта" /> </label>
      </div>

      <div>
        <label>
          <input name="date" class="input" type="date" />
        </label>
      </div>

      <div>
        <div>Пол</div>
        <div class="mb-1">
          <label> <input class="ml-2" type="radio" name="radio" value="M" /> Муж </label>
          <label> <input class="ml-4" type="radio" name="radio" value="W" /> Жен </label>
        </div>
      </div>

      <div>
        <label class="input">
          <div>Любимый язык программирования</div>
          <select class="my-2" name="language[]" multiple="multiple">
            <option value="Pascal">Pascal</option>
            <option value="C">C</option>
            <option value="C++">C++</option>
            <option value="JavaScript">JavaScript</option>
            <option value="PHP">PHP</option>
            <option value="Python">Python</option>
            <option value="Java">Java</option>
            <option value="Haskel">Haskel</option>
            <option value="Clojure">Clojure</option>
            <option value="Scala">Scala</option>
			<option value="Go">Go</option>
          </select>
        </label>
      </div>

      <div class="my-2">
        <div>Биография</div>
        <label>
          <textarea class="input" name="bio" placeholder="Биография"> </textarea>
        </label>
      </div>

      <div>
        <label class="oznakomlen">
          <label> <input id="oznakomlen" type="checkbox" name="check" /> с контрактом ознакомлен(а) </label>
        </label>
      </div>

      <button type="submit" class="button my-3">Отправить</button>
    </div>
  </form>
</body>
</html>
