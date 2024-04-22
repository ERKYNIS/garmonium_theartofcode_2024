import os
import sqlite3
import hashlib
from pprint import pprint

from flask import Flask, render_template, request, redirect, flash

app = Flask(__name__)
app.secret_key = os.urandom(24)

con = sqlite3.connect("database.db", check_same_thread=False)
cur = con.cursor()

cur.execute(
    """CREATE TABLE IF NOT EXISTS accounts (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT, 
    password TEXT, first_name TEXT, last_name TEXT, acctype INTEGER DEFAULT (0));""")
cur.execute("""CREATE TABLE IF NOT EXISTS experts (expert_id INTEGER, users_id TEXT, desc TEXT);""")
cur.execute(
    """CREATE TABLE IF NOT EXISTS services (id INTEGER PRIMARY KEY AUTOINCREMENT, expert_id INTEGER, 
    title TEXT, desc TEXT, cost INTEGER, rating INTEGER);""")
cur.execute(
    """CREATE TABLE IF NOT EXISTS buys (id INTEGER PRIMARY KEY AUTOINCREMENT, service_id INTEGER, 
    user_id INTEGER, DATETIME TEXT, comment TEXT);""")


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
            resp = app.make_response(render_template("process.html", title="Ошибка получения информации об аккаунте...",
                                                     redirect="/login"))
            resp.set_cookie('acc_id', f'', max_age=2592000)
            resp.set_cookie('email', f'', max_age=2592000)
            resp.set_cookie('password', f'', max_age=2592000)
            return resp
    return False


def render_page(template, title="", loggin=False, acc_access=[0], **kwargs):
    if loggin and not isloggin():
        return redirect('/login')
    elif acc_access[0] != 0 and int(request.cookies.get("acctype")) not in acc_access:
        return render_template('error.html', title="Ошибка",
                               error='У вас нет доступа для просмотра данной страницы!')
    else:
        return render_template(template, title=title, **kwargs)


def check_password(password):
    digits = '1234567890'
    upper_letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    lower_letters = 'abcdefghijklmnopqrstuvwxyz'
    symbols = '!@#$%^&*()-+'
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


@app.route('/')
def main():
    """sql = "SELECT * FROM `accounts` WHERE `role`=2"
    if request.args.get("orderby"):
        sql += f"ORDER BY `{request.args.get('orderby')}`"
    else:
        sql += "ORDER BY `raiting` DESC"
    experts = databaserequest(sql)"""
    experts = []
    return render_page('main.html', title="Добро пожаловать!", experts=experts)


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
            resp.set_cookie('email', f'{testuser[0][2]}', max_age=2592000)
            resp.set_cookie('password', f'{testuser[0][1]}', max_age=2592000)
            return resp
    else:
        return render_page('login.html', title="Авторизация")


@app.route('/account', methods=['GET', 'POST'])
def account():
    if not isloggin():
        return redirect('/login')
    if request.method == "POST":
        databaserequest("UPDATE accounts SET `acctype`=?, `first_name`=?, `last_name`=? WHERE `id`=?",
                        params=[request.form.get("role"), request.form.get("first_name"),
                                request.form.get("last_name"), request.cookies.get("id")], commit=True)
        return render_page("account.html", title="Аккаунт", loggin=True, acc_id=request.cookies.get("id"),
                           acc_email=request.cookies.get("email"), acc_password=request.cookies.get("password"),
                           notification=f"Информация о Вашем аккаунте обновлена!", notification_type="green",
                           acc_type=request.form.get("role"), first_name=request.form.get("first_name"),
                           last_name=request.form.get("last_name"))
    else:
        acc_info = databaserequest("SELECT * FROM accounts WHERE `id`=?", params=request.cookies.get("id"))[0]
        return render_page("account.html", title="Аккаунт", loggin=True, acc_id=request.cookies.get("id"),
                           acc_email=request.cookies.get("email"), acc_password=request.cookies.get("password"),
                           acc_type=acc_info[5], first_name=acc_info[3], last_name=acc_info[4])


@app.route("/logout")
def logout():
    resp = app.make_response(render_template("process.html",
                                             title="Выход из аккаунта...",
                                             redirect="/login"))
    resp.set_cookie('acc_id', f'', max_age=2592000)
    resp.set_cookie('email', f'', max_age=2592000)
    resp.set_cookie('password', f'', max_age=2592000)
    return resp


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
