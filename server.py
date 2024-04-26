import datetime
import hashlib
import os
import sqlite3
from pprint import pprint
import pytz

from flask import Flask, render_template, request, redirect

app = Flask(__name__)
app.secret_key = os.urandom(24)

con = sqlite3.connect("database.db", check_same_thread=False)
cur = con.cursor()

cur.execute(
    """CREATE TABLE IF NOT EXISTS accounts (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT, 
    password TEXT, first_name TEXT, last_name TEXT, acctype INTEGER DEFAULT (0), expert_type INTEGER DEFAULT (0), 
    raiting INTEGER DEFAULT (0), expert_price INTEGER DEFAULT (0), expert_desc TEXT);""")
cur.execute(
    """CREATE TABLE IF NOT EXISTS tasks (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, 
    expert_id INTEGER, datetime TEXT, task TEXT, status INTEGER DEFAULT (0));""")
cur.execute(
    """CREATE TABLE IF NOT EXISTS expert_entries (id INTEGER PRIMARY KEY AUTOINCREMENT, user_first_name TEXT, 
    user_last_name TEXT, user_id INTEGER DEFAULT (0), expert_id INTEGER, datetime TEXT);""")

expert_types = ['Любые', 'Семейный психолог', 'Подростковый эксперт', 'Психиатр', 'Детский психолог', 'Психотерапевт']


def databaserequest(text, params=None, commit=False):
    if params is None:
        params = []
    dbrequest = cur.execute(f"""{text}""", params)
    if not commit:
        return dbrequest.fetchall()
    else:
        con.commit()
    return True


def isloggin():
    if request.cookies.get("id") and request.cookies.get("email") and request.cookies.get("password"):
        testacc = databaserequest("SELECT * FROM accounts WHERE `email`=? AND `password`=?",
                                  params=[request.cookies.get("email"), request.cookies.get("password")])
        if len(testacc) != 0:
            return True
        else:
            return 2
    return False


def render_page(template, title="", loggin=False, **kwargs):
    logged = isloggin()
    if loggin and not logged:
        return redirect('/login')
    elif logged == 2:
        resp = app.make_response(render_template("process.html",
                                                 title="Ошибка получения информации об аккаунте...",
                                                 redirect="/login"))
        resp.set_cookie('acc_id', f'', max_age=2592000)
        resp.set_cookie('email', f'', max_age=2592000)
        resp.set_cookie('password', f'', max_age=2592000)
        return resp
    else:
        acctype = 0
        if logged:
            acctype = request.cookies.get("acctype")
        return render_template(template, title=title, **kwargs, logged=logged, acctype=acctype)


def check_password(password):
    digits = '1234567890'
    upper_letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    lower_letters = 'abcdefghijklmnopqrstuvwxyz'
    symbols = '!@#$%^&*()-+.,'
    acceptable = digits + upper_letters + lower_letters + symbols

    passwd = set(password)
    if any(char not in acceptable for char in passwd):
        return 'Ошибка. Запрещенный спецсимвол'
    else:
        recommendations = []
        if len(password) < 12:
            recommendations.append(f'увеличить число символов - {12 - len(password)}')
        for what, message in ((digits, 'цифру'),
                              (symbols, 'спецсимвол'),
                              (upper_letters, 'заглавную букву'),
                              (lower_letters, 'строчную букву')):
            if all(char not in what for char in passwd):
                recommendations.append(f'добавить 1 {message}')

        if recommendations:
            return 'Слабый пароль.<br><br>Рекомендации:<br>' + ",<br>".join(recommendations)
        else:
            return "ok"


@app.route('/', methods=["GET", "POST"])
def main():
    notification = None

    if request.method == "POST":
        expert_info = databaserequest("SELECT * FROM accounts WHERE `id` = ?",
                                                  params=[request.form.get("expert")])[0]
        thisdatetime = datetime.datetime.now(pytz.timezone("Europe/Moscow")).strftime("%d.%m.%Y")
        if request.form.get("first_name"):
            databaserequest(
                "INSERT INTO `expert_entries`(`expert_id`, `user_first_name`, `user_last_name`, `datetime`) VALUES ("
                "?, ?, ?, ?)",
                params=[request.form.get("expert"), request.form.get("first_name"), request.form.get("last_name"),
                        thisdatetime],
                commit=True)
        else:
            user_info = databaserequest("SELECT * FROM accounts WHERE `id` = ?",
                                        params=[request.cookies.get("id")])[0]
            databaserequest("INSERT INTO `expert_entries`(`expert_id`, `user_first_name`, `user_last_name`, "
                            "`user_id`, `datetime`)"
                            "VALUES (?, ?, ?, ?, ?)",
                            params=[request.form.get("expert"), user_info[3], user_info[4],
                                    request.cookies.get("id"), thisdatetime], commit=True)
        notification = f"Вы успешно записались на консультацию к эксперту {expert_info[3]} {expert_info[4]}"

    sql = "SELECT * FROM `accounts` WHERE `acctype`=2"

    filters = {
        "expert_type": 0,
        "minprice": -1,
        "maxprice": -1
    }

    if request.args.get("psy_category") and request.args.get("psy_category") != 0:
        sql += f" AND `expert_type`={request.args.get('psy_category')}"
        filters["expert_type"] = int(request.args.get('psy_category'))
    if request.args.get("minprice"):
        sql += f" AND `expert_price` >= {int(request.args.get('minprice'))}"
        filters["minprice"] = int(request.args.get('minprice'))
    if request.args.get("maxprice"):
        sql += f" AND `expert_price` <= {int(request.args.get('maxprice'))}"
        filters["maxprice"] = int(request.args.get('maxprice'))
    sql += " ORDER BY `raiting` DESC"
    experts = databaserequest(sql)
    return render_page('main.html', title="Главная", experts=experts, expert_types=expert_types, notification=notification, **filters)


@app.route('/clients', methods=['GET', 'POST'])
def clients():
    if not isloggin():
        return redirect('/login')
    if request.cookies.get("acctype") == "1":
        return redirect('/')

    if request.method == "POST":
        id = request.form.get("user_id")
        nowdatetime = datetime.datetime.now(pytz.timezone("Europe/Moscow")).strftime("%d.%m.%Y")

        databaserequest("INSERT INTO tasks(`user_id`, `expert_id`, `datetime`, `task`) VALUES (?, ?, ?, ?)",
                        params=[request.form.get("user_id"), request.cookies.get("id"), nowdatetime,
                                request.form.get("text")], commit=True)

        diary = databaserequest("SELECT * FROM `tasks` WHERE `user_id` = ?", params=[id])
        user = databaserequest("SELECT * FROM `accounts` WHERE `id` = ?", params=[id])[0]
        return render_page('user_diary.html', diary=diary, user=user, title="Дневник пользователя")
    else:
        if request.args.get("id"):
            id = request.args.get("id")
            diary = databaserequest("SELECT * FROM `tasks` WHERE `user_id` = ?", params=[id])
            user = databaserequest("SELECT * FROM `accounts` WHERE `id` = ?", params=[id])[0]
            return render_page('user_diary.html', diary=diary, user=user, title="Дневник пользователя")
        else:
            users = databaserequest("SELECT * FROM expert_entries WHERE expert_id = ?", params=[request.cookies.get("id")])
            return render_page("users_list.html", users=users, title="Записанные пользователи")


@app.route('/register', methods=["GET", "POST"])
def register():
    if isloggin():
        return redirect('/account')
    if request.method == 'POST':
        testuser = databaserequest("SELECT * FROM accounts WHERE `email` = ?", params=[request.form.get("email")])
        if len(testuser) == 0:
            error = check_password(request.form.get("password"))
            if error == "ok":
                if request.form.get("password") != request.form.get("password2"):
                    return render_page('register.html', title="Регистрация", error="Пароль и его повтор не совпадают!")
                md5password = request.form.get("password")
                md5password = md5password.encode(encoding='UTF-8', errors='strict')
                md5password = str(hashlib.md5(md5password).hexdigest())
                databaserequest("INSERT INTO accounts(`email`, `password`, `first_name`, `last_name`, `acctype`) "
                                "VALUES (?, ?, ?, ?, ?)",
                                params=[request.form.get("email"),
                                        md5password,
                                        request.form.get("first_name"), request.form.get("last_name"),
                                        request.form.get("role")], commit=True)
                resp = app.make_response(render_template("process.html", title="Авторизация...",
                                                         redirect="/account"))
                resp.set_cookie('id', f'{cur.lastrowid}', max_age=2592000)
                resp.set_cookie('email', f'{request.form.get("email")}', max_age=2592000)
                resp.set_cookie('password', f'{md5password}', max_age=2592000)
                resp.set_cookie('acctype', f'{request.form.get("role")}', max_age=2592000)
                return resp
            else:
                return render_page('register.html', title="Регистрация", error=error)
        else:
            return render_page('register.html', title="Регистрация",
                               error="Пользователь с таким адресом электронной почты уже зарегистрирован.")
    else:
        return render_page('register.html', title="Регистрация")


@app.route('/login', methods=["GET", "POST"])
def login():
    if isloggin():
        return redirect('/account')
    if request.method == 'POST':
        md5password = request.form.get("password")
        md5password = md5password.encode(encoding='UTF-8', errors='strict')
        md5password = str(hashlib.md5(md5password).hexdigest())
        testuser = databaserequest("SELECT * FROM accounts WHERE `email` = ? AND `password` = ?",
                                   params=[request.form.get("email"), md5password])
        if len(testuser) == 0:
            return render_page('login.html', title="Авторизация", error="Неверный логин или пароль!")
        else:
            resp = app.make_response(render_template("process.html", title="Авторизация...",
                                                     redirect="/account"))
            resp.set_cookie('id', f'{testuser[0][0]}', max_age=2592000)
            resp.set_cookie('email', f'{testuser[0][1]}', max_age=2592000)
            resp.set_cookie('password', f'{testuser[0][2]}', max_age=2592000)
            resp.set_cookie('acctype', f'{testuser[0][5]}', max_age=2592000)
            return resp
    else:
        return render_page('login.html', title="Авторизация")


@app.route('/account', methods=['GET', 'POST'])
def account():
    if not isloggin():
        return redirect('/login')

    acc_info = databaserequest("SELECT * FROM accounts WHERE `id`=?", params=request.cookies.get("id"))[0]
    psy_type = acc_info[6]
    psy_price = acc_info[8]
    expert_desc = acc_info[9]
    if request.method == "POST":
        newmd5password = False
        error = False
        if request.form.get("old_password") or request.form.get("new_password"):
            if request.form.get("old_password"):
                md5password = request.form.get("old_password")
                md5password = md5password.encode(encoding='UTF-8', errors='strict')
                md5password = str(hashlib.md5(md5password).hexdigest())

                newmd5password = request.form.get("new_password")
                newmd5password = newmd5password.encode(encoding='UTF-8', errors='strict')
                newmd5password = str(hashlib.md5(newmd5password).hexdigest())
                if md5password == acc_info[2]:
                    error_password = check_password(request.form.get("new_password"))
                    if error_password == "ok":
                        databaserequest("UPDATE accounts SET `password`=? WHERE `id`=?",
                                        params=[newmd5password, request.cookies.get("id")], commit=True)
                    else:
                        error = error_password
                else:
                    error = "Неверный текущий пароль!"
            else:
                error = "Введите текущий пароль!"
        if not error and (request.form.get("psy_type") or request.form.get("price") or request.form.get("expert_desc")):
            if request.form.get("psy_type"):
                psy_type = int(request.form.get("psy_type"))

            if request.form.get("price"):
                psy_price = int(request.form.get("price"))

            if request.form.get("expert_desc"):
                expert_desc = request.form.get("expert_desc")

            databaserequest("UPDATE accounts SET `expert_type`=?, `expert_price`=?, `expert_desc`=? WHERE `id`=?",
                            params=[psy_type, psy_price, expert_desc, request.cookies.get("id")], commit=True)
        if not error:
            if newmd5password:
                return redirect('/logout')
            return render_page("account.html", title="Аккаунт", loggin=True, acc_id=request.cookies.get("id"),
                               acc_email=acc_info[1], acc_password=request.cookies.get("password"),
                               notification=f"Информация о Вашем аккаунте обновлена!", notification_type="success",
                               acc_type=acc_info[5], first_name=acc_info[3],
                               last_name=acc_info[4], psy_type=psy_type, psy_price=psy_price, psy_desc=expert_desc)
        else:
import datetime
import hashlib
import os
import sqlite3
from pprint import pprint
import pytz

from flask import Flask, render_template, request, redirect

app = Flask(__name__)
app.secret_key = os.urandom(24)

con = sqlite3.connect("database.db", check_same_thread=False)
cur = con.cursor()

cur.execute(
    """CREATE TABLE IF NOT EXISTS accounts (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT,
    password TEXT, first_name TEXT, last_name TEXT, acctype INTEGER DEFAULT (0), expert_type INTEGER DEFAULT (0),
    raiting INTEGER DEFAULT (0), expert_price INTEGER DEFAULT (0), expert_desc TEXT);""")
cur.execute(
    """CREATE TABLE IF NOT EXISTS tasks (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER,
    expert_id INTEGER, datetime TEXT, task TEXT, status INTEGER DEFAULT (0));""")
cur.execute(
    """CREATE TABLE IF NOT EXISTS expert_entries (id INTEGER PRIMARY KEY AUTOINCREMENT, user_first_name TEXT,
    user_last_name TEXT, user_id INTEGER DEFAULT (0), expert_id INTEGER, datetime TEXT);""")

expert_types = ['Любые', 'Семейный психолог', 'Подростковый эксперт', 'Психиатр', 'Детский психолог', 'Психотерапевт']


def databaserequest(text, params=None, commit=False):
    if params is None:
        params = []
    dbrequest = cur.execute(f"""{text}""", params)
    if not commit:
        return dbrequest.fetchall()
    else:
        con.commit()
    return True


def isloggin():
    if request.cookies.get("id") and request.cookies.get("email") and request.cookies.get("password"):
        testacc = databaserequest("SELECT * FROM accounts WHERE `email`=? AND `password`=?",
                                  params=[request.cookies.get("email"), request.cookies.get("password")])
        if len(testacc) != 0:
            return True
        else:
            return 2
    return False


def render_page(template, title="", loggin=False, **kwargs):
    logged = isloggin()
    if loggin and not logged:
        return redirect('/login')
    elif logged == 2:
        resp = app.make_response(render_template("process.html",
                                                 title="Ошибка получения информации об аккаунте...",
                                                 redirect="/login"))
        resp.set_cookie('acc_id', f'', max_age=2592000)
        resp.set_cookie('email', f'', max_age=2592000)
        resp.set_cookie('password', f'', max_age=2592000)
        return resp
    else:
        acctype = 0
        if logged:
            acctype = request.cookies.get("acctype")
        return render_template(template, title=title, **kwargs, logged=logged, acctype=acctype)


def check_password(password):
    digits = '1234567890'
    upper_letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    lower_letters = 'abcdefghijklmnopqrstuvwxyz'
    symbols = '!@#$%^&*()-+.,'
    acceptable = digits + upper_letters + lower_letters + symbols

    passwd = set(password)
    if any(char not in acceptable for char in passwd):
        return 'Ошибка. Запрещенный спецсимвол'
    else:
        recommendations = []
        if len(password) < 12:
            recommendations.append(f'увеличить число символов - {12 - len(password)}')
        for what, message in ((digits, 'цифру'),
                              (symbols, 'спецсимвол'),
                              (upper_letters, 'заглавную букву'),
                              (lower_letters, 'строчную букву')):
            if all(char not in what for char in passwd):
                recommendations.append(f'добавить 1 {message}')

        if recommendations:
            return 'Слабый пароль.<br><br>Рекомендации:<br>' + ",<br>".join(recommendations)
        else:
            return "ok"


@app.route('/', methods=["GET", "POST"])
def main():
    notification = None

    if request.method == "POST":
        expert_info = databaserequest("SELECT * FROM accounts WHERE `id` = ?",
                                                  params=[request.form.get("expert")])[0]
        thisdatetime = datetime.datetime.now(pytz.timezone("Europe/Moscow")).strftime("%d.%m.%Y")
        if request.form.get("first_name"):
            databaserequest(
                "INSERT INTO `expert_entries`(`expert_id`, `user_first_name`, `user_last_name`, `datetime`) VALUES ("
                "?, ?, ?, ?)",
                params=[request.form.get("expert"), request.form.get("first_name"), request.form.get("last_name"),
                        thisdatetime],
                commit=True)
        else:
            user_info = databaserequest("SELECT * FROM accounts WHERE `id` = ?",
                                        params=[request.cookies.get("id")])[0]
            databaserequest("INSERT INTO `expert_entries`(`expert_id`, `user_first_name`, `user_last_name`, "
                            "`user_id`, `datetime`)"
                            "VALUES (?, ?, ?, ?, ?)",
                            params=[request.form.get("expert"), user_info[3], user_info[4],
                                    request.cookies.get("id"), thisdatetime], commit=True)
        notification = f"Вы успешно записались на консультацию к эксперту {expert_info[3]} {expert_info[4]}"

    sql = "SELECT * FROM `accounts` WHERE `acctype`=2"

    filters = {
        "expert_type": 0,
        "minprice": -1,
        "maxprice": -1
    }

    if request.args.get("psy_category") and request.args.get("psy_category") != 0:
        sql += f" AND `expert_type`={request.args.get('psy_category')}"
        filters["expert_type"] = int(request.args.get('psy_category'))
    if request.args.get("minprice"):
        sql += f" AND `expert_price` >= {int(request.args.get('minprice'))}"
        filters["minprice"] = int(request.args.get('minprice'))
    if request.args.get("maxprice"):
        sql += f" AND `expert_price` <= {int(request.args.get('maxprice'))}"
        filters["maxprice"] = int(request.args.get('maxprice'))
    sql += " ORDER BY `raiting` DESC"
    experts = databaserequest(sql)
    return render_page('main.html', title="Главная", experts=experts, expert_types=expert_types, notification=notification, **filters)


@app.route('/clients', methods=['GET', 'POST'])
def clients():
    if not isloggin():
        return redirect('/login')
    if request.cookies.get("acctype") == "1":
        return redirect('/')

    if request.method == "POST":
        id = request.form.get("user_id")
        nowdatetime = datetime.datetime.now(pytz.timezone("Europe/Moscow")).strftime("%d.%m.%Y")

        databaserequest("INSERT INTO tasks(`user_id`, `expert_id`, `datetime`, `task`) VALUES (?, ?, ?, ?)",
                        params=[request.form.get("user_id"), request.cookies.get("id"), nowdatetime,
                                request.form.get("text")], commit=True)

        diary = databaserequest("SELECT * FROM `tasks` WHERE `user_id` = ?", params=[id])
        user = databaserequest("SELECT * FROM `accounts` WHERE `id` = ?", params=[id])[0]
        return render_page('user_diary.html', diary=diary, user=user, title="Дневник пользователя")
    else:
        if request.args.get("id"):
            id = request.args.get("id")
            diary = databaserequest("SELECT * FROM `tasks` WHERE `user_id` = ?", params=[id])
            user = databaserequest("SELECT * FROM `accounts` WHERE `id` = ?", params=[id])[0]
            return render_page('user_diary.html', diary=diary, user=user, title="Дневник пользователя")
        else:
            users = databaserequest("SELECT * FROM expert_entries WHERE expert_id = ?", params=[request.cookies.get("id")])
            return render_page("users_list.html", users=users, title="Записанные пользователи")


@app.route('/register', methods=["GET", "POST"])
def register():
    if isloggin():
        return redirect('/account')
    if request.method == 'POST':
        testuser = databaserequest("SELECT * FROM accounts WHERE `email` = ?", params=[request.form.get("email")])
        if len(testuser) == 0:
            error = check_password(request.form.get("password"))
            if error == "ok":
                if request.form.get("password") != request.form.get("password2"):
                    return render_page('register.html', title="Регистрация", error="Пароль и его повтор не совпадают!")
                md5password = request.form.get("password")
                md5password = md5password.encode(encoding='UTF-8', errors='strict')
                md5password = str(hashlib.md5(md5password).hexdigest())
                databaserequest("INSERT INTO accounts(`email`, `password`, `first_name`, `last_name`, `acctype`) "
                                "VALUES (?, ?, ?, ?, ?)",
                                params=[request.form.get("email"),
                                        md5password,
                                        request.form.get("first_name"), request.form.get("last_name"),
                                        request.form.get("role")], commit=True)
                resp = app.make_response(render_template("process.html", title="Авторизация...",
                                                         redirect="/account"))
                resp.set_cookie('id', f'{cur.lastrowid}', max_age=2592000)
                resp.set_cookie('email', f'{request.form.get("email")}', max_age=2592000)
                resp.set_cookie('password', f'{md5password}', max_age=2592000)
                resp.set_cookie('acctype', f'{request.form.get("role")}', max_age=2592000)
                return resp
            else:
                return render_page('register.html', title="Регистрация", error=error)
        else:
            return render_page('register.html', title="Регистрация",
                               error="Пользователь с таким адресом электронной почты уже зарегистрирован.")
    else:
        return render_page('register.html', title="Регистрация")


@app.route('/login', methods=["GET", "POST"])
def login():
    if isloggin():
        return redirect('/account')
    if request.method == 'POST':
        md5password = request.form.get("password")
        md5password = md5password.encode(encoding='UTF-8', errors='strict')
        md5password = str(hashlib.md5(md5password).hexdigest())
        testuser = databaserequest("SELECT * FROM accounts WHERE `email` = ? AND `password` = ?",
                                   params=[request.form.get("email"), md5password])
        if len(testuser) == 0:
            return render_page('login.html', title="Авторизация", error="Неверный логин или пароль!")
        else:
            resp = app.make_response(render_template("process.html", title="Авторизация...",
                                                     redirect="/account"))
            resp.set_cookie('id', f'{testuser[0][0]}', max_age=2592000)
            resp.set_cookie('email', f'{testuser[0][1]}', max_age=2592000)
            resp.set_cookie('password', f'{testuser[0][2]}', max_age=2592000)
            resp.set_cookie('acctype', f'{testuser[0][5]}', max_age=2592000)
            return resp
    else:
        return render_page('login.html', title="Авторизация")


@app.route('/account', methods=['GET', 'POST'])
def account():
    if not isloggin():
        return redirect('/login')

    acc_info = databaserequest("SELECT * FROM accounts WHERE `id`=?", params=request.cookies.get("id"))[0]
    psy_type = acc_info[6]
    psy_price = acc_info[8]
    expert_desc = acc_info[9]
    if request.method == "POST":
        newmd5password = False
        error = False
        if request.form.get("old_password") or request.form.get("new_password"):
            if request.form.get("old_password"):
                md5password = request.form.get("old_password")
                md5password = md5password.encode(encoding='UTF-8', errors='strict')
                md5password = str(hashlib.md5(md5password).hexdigest())

                newmd5password = request.form.get("new_password")
                newmd5password = newmd5password.encode(encoding='UTF-8', errors='strict')
                newmd5password = str(hashlib.md5(newmd5password).hexdigest())
                if md5password == acc_info[2]:
                    error_password = check_password(request.form.get("new_password"))
                    if error_password == "ok":
                        databaserequest("UPDATE accounts SET `password`=? WHERE `id`=?",
                                        params=[newmd5password, request.cookies.get("id")], commit=True)
                    else:
                        error = error_password
                else:
                    error = "Неверный текущий пароль!"
            else:
                error = "Введите текущий пароль!"
        if not error and (request.form.get("psy_type") or request.form.get("price") or request.form.get("expert_desc")):
            if request.form.get("psy_type"):
                psy_type = int(request.form.get("psy_type"))

            if request.form.get("price"):
                psy_price = int(request.form.get("price"))

            if request.form.get("expert_desc"):
                expert_desc = request.form.get("expert_desc")

            databaserequest("UPDATE accounts SET `expert_type`=?, `expert_price`=?, `expert_desc`=? WHERE `id`=?",
                            params=[psy_type, psy_price, expert_desc, request.cookies.get("id")], commit=True)
        if not error:
            if newmd5password:
                return redirect('/logout')
            return render_page("account.html", title="Аккаунт", loggin=True, acc_id=request.cookies.get("id"),
                               acc_email=acc_info[1], acc_password=request.cookies.get("password"),
                               notification=f"Информация о Вашем аккаунте обновлена!", notification_type="success",
                               acc_type=acc_info[5], first_name=acc_info[3],
                               last_name=acc_info[4], psy_type=psy_type, psy_price=psy_price, psy_desc=expert_desc)
        else:
            return render_page("account.html", title="Аккаунт", loggin=True, acc_id=request.cookies.get("id"),
import datetime
import hashlib
import os
import sqlite3
from pprint import pprint
import pytz

from flask import Flask, render_template, request, redirect

app = Flask(__name__)
app.secret_key = os.urandom(24)

con = sqlite3.connect("database.db", check_same_thread=False)
cur = con.cursor()

cur.execute(
    """CREATE TABLE IF NOT EXISTS accounts (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT,
    password TEXT, first_name TEXT, last_name TEXT, acctype INTEGER DEFAULT (0), expert_type INTEGER DEFAULT (0),
    raiting INTEGER DEFAULT (0), expert_price INTEGER DEFAULT (0), expert_desc TEXT);""")
cur.execute(
    """CREATE TABLE IF NOT EXISTS tasks (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER,
    expert_id INTEGER, datetime TEXT, task TEXT, status INTEGER DEFAULT (0));""")
cur.execute(
    """CREATE TABLE IF NOT EXISTS expert_entries (id INTEGER PRIMARY KEY AUTOINCREMENT, user_first_name TEXT,
    user_last_name TEXT, user_id INTEGER DEFAULT (0), expert_id INTEGER, datetime TEXT);""")

expert_types = ['Любые', 'Семейный психолог', 'Подростковый эксперт', 'Психиатр', 'Детский психолог', 'Психотерапевт']


def databaserequest(text, params=None, commit=False):
    if params is None:
        params = []
    dbrequest = cur.execute(f"""{text}""", params)
    if not commit:
        return dbrequest.fetchall()
    else:
        con.commit()
    return True


def isloggin():
    if request.cookies.get("id") and request.cookies.get("email") and request.cookies.get("password"):
        testacc = databaserequest("SELECT * FROM accounts WHERE `email`=? AND `password`=?",
                                  params=[request.cookies.get("email"), request.cookies.get("password")])
        if len(testacc) != 0:
            return True
        else:
            return 2
    return False


def render_page(template, title="", loggin=False, **kwargs):
    logged = isloggin()
    if loggin and not logged:
        return redirect('/login')
    elif logged == 2:
        resp = app.make_response(render_template("process.html",
                                                 title="Ошибка получения информации об аккаунте...",
                                                 redirect="/login"))
        resp.set_cookie('acc_id', f'', max_age=2592000)
        resp.set_cookie('email', f'', max_age=2592000)
        resp.set_cookie('password', f'', max_age=2592000)
        return resp
    else:
        acctype = 0
        if logged:
            acctype = request.cookies.get("acctype")
        return render_template(template, title=title, **kwargs, logged=logged, acctype=acctype)


def check_password(password):
    digits = '1234567890'
    upper_letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    lower_letters = 'abcdefghijklmnopqrstuvwxyz'
    symbols = '!@#$%^&*()-+.,'
    acceptable = digits + upper_letters + lower_letters + symbols

    passwd = set(password)
    if any(char not in acceptable for char in passwd):
        return 'Ошибка. Запрещенный спецсимвол'
    else:
        recommendations = []
        if len(password) < 12:
            recommendations.append(f'увеличить число символов - {12 - len(password)}')
        for what, message in ((digits, 'цифру'),
                              (symbols, 'спецсимвол'),
                              (upper_letters, 'заглавную букву'),
                              (lower_letters, 'строчную букву')):
            if all(char not in what for char in passwd):
                recommendations.append(f'добавить 1 {message}')

        if recommendations:
            return 'Слабый пароль.<br><br>Рекомендации:<br>' + ",<br>".join(recommendations)
        else:
            return "ok"


@app.route('/', methods=["GET", "POST"])
def main():
    notification = None

    if request.method == "POST":
        expert_info = databaserequest("SELECT * FROM accounts WHERE `id` = ?",
                                                  params=[request.form.get("expert")])[0]
        thisdatetime = datetime.datetime.now(pytz.timezone("Europe/Moscow")).strftime("%d.%m.%Y")
        if request.form.get("first_name"):
            databaserequest(
                "INSERT INTO `expert_entries`(`expert_id`, `user_first_name`, `user_last_name`, `datetime`) VALUES ("
                "?, ?, ?, ?)",
                params=[request.form.get("expert"), request.form.get("first_name"), request.form.get("last_name"),
                        thisdatetime],
                commit=True)
        else:
            user_info = databaserequest("SELECT * FROM accounts WHERE `id` = ?",
                                        params=[request.cookies.get("id")])[0]
            databaserequest("INSERT INTO `expert_entries`(`expert_id`, `user_first_name`, `user_last_name`, "
                            "`user_id`, `datetime`)"
                            "VALUES (?, ?, ?, ?, ?)",
                            params=[request.form.get("expert"), user_info[3], user_info[4],
                                    request.cookies.get("id"), thisdatetime], commit=True)
        notification = f"Вы успешно записались на консультацию к эксперту {expert_info[3]} {expert_info[4]}"

    sql = "SELECT * FROM `accounts` WHERE `acctype`=2"

    filters = {
        "expert_type": 0,
        "minprice": -1,
        "maxprice": -1
    }

    if request.args.get("psy_category") and request.args.get("psy_category") != 0:
        sql += f" AND `expert_type`={request.args.get('psy_category')}"
        filters["expert_type"] = int(request.args.get('psy_category'))
    if request.args.get("minprice"):
        sql += f" AND `expert_price` >= {int(request.args.get('minprice'))}"
        filters["minprice"] = int(request.args.get('minprice'))
    if request.args.get("maxprice"):
        sql += f" AND `expert_price` <= {int(request.args.get('maxprice'))}"
        filters["maxprice"] = int(request.args.get('maxprice'))
    sql += " ORDER BY `raiting` DESC"
    experts = databaserequest(sql)
    return render_page('main.html', title="Главная", experts=experts, expert_types=expert_types, notification=notification, **filters)


@app.route('/clients', methods=['GET', 'POST'])
def clients():
    if not isloggin():
        return redirect('/login')
    if request.cookies.get("acctype") == "1":
        return redirect('/')

    if request.method == "POST":
        id = request.form.get("user_id")
        nowdatetime = datetime.datetime.now(pytz.timezone("Europe/Moscow")).strftime("%d.%m.%Y")

        databaserequest("INSERT INTO tasks(`user_id`, `expert_id`, `datetime`, `task`) VALUES (?, ?, ?, ?)",
                        params=[request.form.get("user_id"), request.cookies.get("id"), nowdatetime,
                                request.form.get("text")], commit=True)

        diary = databaserequest("SELECT * FROM `tasks` WHERE `user_id` = ?", params=[id])
        user = databaserequest("SELECT * FROM `accounts` WHERE `id` = ?", params=[id])[0]
        return render_page('user_diary.html', diary=diary, user=user, title="Дневник пользователя")
    else:
        if request.args.get("id"):
            id = request.args.get("id")
            diary = databaserequest("SELECT * FROM `tasks` WHERE `user_id` = ?", params=[id])
            user = databaserequest("SELECT * FROM `accounts` WHERE `id` = ?", params=[id])[0]
            return render_page('user_diary.html', diary=diary, user=user, title="Дневник пользователя")
        else:
            users = databaserequest("SELECT * FROM expert_entries WHERE expert_id = ?", params=[request.cookies.get("id")])
            return render_page("users_list.html", users=users, title="Записанные пользователи")


@app.route('/register', methods=["GET", "POST"])
def register():
    if isloggin():
        return redirect('/account')
    if request.method == 'POST':
        testuser = databaserequest("SELECT * FROM accounts WHERE `email` = ?", params=[request.form.get("email")])
        if len(testuser) == 0:
            error = check_password(request.form.get("password"))
            if error == "ok":
                if request.form.get("password") != request.form.get("password2"):
                    return render_page('register.html', title="Регистрация", error="Пароль и его повтор не совпадают!")
                md5password = request.form.get("password")
                md5password = md5password.encode(encoding='UTF-8', errors='strict')
                md5password = str(hashlib.md5(md5password).hexdigest())
                databaserequest("INSERT INTO accounts(`email`, `password`, `first_name`, `last_name`, `acctype`) "
                                "VALUES (?, ?, ?, ?, ?)",
                                params=[request.form.get("email"),
                                        md5password,
                                        request.form.get("first_name"), request.form.get("last_name"),
                                        request.form.get("role")], commit=True)
                resp = app.make_response(render_template("process.html", title="Авторизация...",
                                                         redirect="/account"))
                resp.set_cookie('id', f'{cur.lastrowid}', max_age=2592000)
                resp.set_cookie('email', f'{request.form.get("email")}', max_age=2592000)
                resp.set_cookie('password', f'{md5password}', max_age=2592000)
                resp.set_cookie('acctype', f'{request.form.get("role")}', max_age=2592000)
                return resp
            else:
                return render_page('register.html', title="Регистрация", error=error)
        else:
            return render_page('register.html', title="Регистрация",
                               error="Пользователь с таким адресом электронной почты уже зарегистрирован.")
    else:
        return render_page('register.html', title="Регистрация")


@app.route('/login', methods=["GET", "POST"])
def login():
    if isloggin():
        return redirect('/account')
    if request.method == 'POST':
        md5password = request.form.get("password")
        md5password = md5password.encode(encoding='UTF-8', errors='strict')
        md5password = str(hashlib.md5(md5password).hexdigest())
        testuser = databaserequest("SELECT * FROM accounts WHERE `email` = ? AND `password` = ?",
                                   params=[request.form.get("email"), md5password])
        if len(testuser) == 0:
            return render_page('login.html', title="Авторизация", error="Неверный логин или пароль!")
        else:
            resp = app.make_response(render_template("process.html", title="Авторизация...",
                                                     redirect="/account"))
            resp.set_cookie('id', f'{testuser[0][0]}', max_age=2592000)
            resp.set_cookie('email', f'{testuser[0][1]}', max_age=2592000)
            resp.set_cookie('password', f'{testuser[0][2]}', max_age=2592000)
            resp.set_cookie('acctype', f'{testuser[0][5]}', max_age=2592000)
            return resp
    else:
        return render_page('login.html', title="Авторизация")


@app.route('/account', methods=['GET', 'POST'])
def account():
    if not isloggin():
        return redirect('/login')

    acc_info = databaserequest("SELECT * FROM accounts WHERE `id`=?", params=request.cookies.get("id"))[0]
    psy_type = acc_info[6]
    psy_price = acc_info[8]
    expert_desc = acc_info[9]
    if request.method == "POST":
        newmd5password = False
        error = False
        if request.form.get("old_password") or request.form.get("new_password"):
            if request.form.get("old_password"):
                md5password = request.form.get("old_password")
                md5password = md5password.encode(encoding='UTF-8', errors='strict')
                md5password = str(hashlib.md5(md5password).hexdigest())

                newmd5password = request.form.get("new_password")
                newmd5password = newmd5password.encode(encoding='UTF-8', errors='strict')
                newmd5password = str(hashlib.md5(newmd5password).hexdigest())
                if md5password == acc_info[2]:
                    error_password = check_password(request.form.get("new_password"))
                    if error_password == "ok":
                        databaserequest("UPDATE accounts SET `password`=? WHERE `id`=?",
                                        params=[newmd5password, request.cookies.get("id")], commit=True)
                    else:
                        error = error_password
                else:
                    error = "Неверный текущий пароль!"
            else:
                error = "Введите текущий пароль!"
        if not error and (request.form.get("psy_type") or request.form.get("price") or request.form.get("expert_desc")):
            if request.form.get("psy_type"):
                psy_type = int(request.form.get("psy_type"))

            if request.form.get("price"):
                psy_price = int(request.form.get("price"))

            if request.form.get("expert_desc"):
                expert_desc = request.form.get("expert_desc")

            databaserequest("UPDATE accounts SET `expert_type`=?, `expert_price`=?, `expert_desc`=? WHERE `id`=?",
                            params=[psy_type, psy_price, expert_desc, request.cookies.get("id")], commit=True)
        if not error:
            if newmd5password:
                return redirect('/logout')
            return render_page("account.html", title="Аккаунт", loggin=True, acc_id=request.cookies.get("id"),
                               acc_email=acc_info[1], acc_password=request.cookies.get("password"),
                               notification=f"Информация о Вашем аккаунте обновлена!", notification_type="success",
                               acc_type=acc_info[5], first_name=acc_info[3],
                               last_name=acc_info[4], psy_type=psy_type, psy_price=psy_price, psy_desc=expert_desc)
        else:
            return render_page("account.html", title="Аккаунт", loggin=True, acc_id=request.cookies.get("id"),
                               acc_email=acc_info[1], acc_password=request.cookies.get("password"),
                               notification=error, notification_type="danger",
                               acc_type=acc_info[5], first_name=acc_info[3],
                               last_name=acc_info[4], psy_type=psy_type, psy_price=psy_price, psy_desc=expert_desc)
    else:
        return render_page("account.html", title="Аккаунт", loggin=True, acc_id=request.cookies.get("id"),
                           acc_email=acc_info[1], acc_password=request.cookies.get("password"),
                           acc_type=acc_info[5], first_name=acc_info[3], last_name=acc_info[4],
                           psy_type=psy_type, psy_price=psy_price, psy_desc=expert_desc)


@app.route("/logout")
def logout():
    resp = app.make_response(render_template("process.html",
                                             title="Выход из аккаунта...",
                                             redirect="/login"))
    resp.set_cookie('acc_id', f'', max_age=2592000)
    resp.set_cookie('email', f'', max_age=2592000)
    resp.set_cookie('password', f'', max_age=2592000)
    return resp


@app.route("/diary")
def diary():
    if not isloggin():
        return redirect('/login')

    if request.cookies.get("acctype") == "2":
        return redirect('/account')
    else:
        if request.args.get("success"):
            id = request.args.get("success")
            databaserequest("UPDATE `tasks` SET `status`=1 WHERE `id`=?", params=[id], commit=True)
        diary = databaserequest("SELECT * FROM `tasks` WHERE `user_id` = ?", params=[request.cookies.get("id")])
    return render_page("diary.html", diary=diary, title="Мой дневник")


@app.errorhandler(404)
def page_not_found(e):
    return render_page('error.html', title="Упс...", error="Страница не найдена!"), 404


@app.errorhandler(500)
def page_not_found(e):
    print("ОШИБКА:\n")
    pprint(e)
    return render_template('error.html', title="Ой... Ошибка...",
                           error="Произошла ошибка при обработке Вашего запроса!"), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 80)))
    con.close()

