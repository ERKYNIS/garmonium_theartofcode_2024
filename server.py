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
    title TEXT, desc TEXT, cost INTEGER);""")
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


def render_page(template, title="", loggin=False, acc_access=[0], **kwargs):
    if loggin and not isloggin():
        return redirect('/login')
    elif acc_access[0] != 0 and int(request.cookies.get("acctype")) not in acc_access:
        return render_template('error.html', title="Ошибка",
                               error='У вас нет доступа для просмотра данной страницы!')
    else:
        return render_template(template, title=title, **kwargs)


def isloggin():
    if request.cookies.get("id"):
        return True
    return False


def check_password(password):
    digits = '1234567890'
    upper_letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    lower_letters = 'abcdefghijklmnopqrstuvwxyz'
    symbols = '!@#$%^&*()-+'
    acceptable = digits+upper_letters+lower_letters+symbols

    passwd = set(password)
    if any(char not in acceptable for char in passwd):
        return 'Ошибка. Запрещенный спецсимвол'
    else:
        recommendations = []
        if len(password) < 12:
            recommendations.append(f'увеличить число символов - {12-len(password)}')
        for what, message in ((digits,        'цифру'),
                              (symbols,       'спецсимвол'),
                              (upper_letters, 'заглавную букву'),
                              (lower_letters, 'строчную букву')):
            if all(char not in what for char in passwd):
                recommendations.append(f'добавить 1 {message}')

        if recommendations:
            return "Слабый пароль. Рекомендации:", ", ".join(recommendations)
        else:
            return "ok"


@app.route('/')
def main():
    return render_page('main.html', title="Добро пожаловать!")


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == 'POST':
        testuser = databaserequest("SELECT * FROM accounts WHERE `email` = ?", params=[request.form.get("email")])
        if len(testuser) == 0:
            error = check_password(request.form.get("password"))
            if error == "ok":
                databaserequest("INSERT INTO accounts(`email`, `password`, `first_name`, `last_name`) "
                                "VALUES ('?', '?', '?', '?')",
                                params=[request.form.get("email"),
                                        hashlib.md5(request.form.get("password")).hexdigest(),
                                        request.form.get("first_name"), request.form.get("last_name")])
                return 'ok'
            else:
                return error
        else:
            return "Пользователь с таким адресом электронной почты уже зарегистрирован."
    else:
        return render_page('register.html', title="Регистрация")


@app.errorhandler(404)
def page_not_found(e):
    return render_page('error.html', title="Упс...", error="Страница не найдена!")


@app.errorhandler(500)
def page_not_found(e):
    print("ОШИБКА:\n")
    pprint(e)
    return render_template('error.html', title="Ой... Ошибка...", errors="Произошла ошибка при обработке Вашего запроса!")


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 5000)))
    con.close()
