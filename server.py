import os
from pprint import pprint

from flask import Flask, render_template, request, redirect, flash

app = Flask(__name__)
app.secret_key = os.urandom(24)


@app.route('/')
def main():
    return render_template('main.html', title="Добро пожаловать!")


@app.errorhandler(404)
def page_not_found(e):
    return render_template('errors/404.html', title="Страница не найдена!")


@app.errorhandler(500)
def page_not_found(e):
    print("ОШИБКА:\n")
    pprint(e)
    return render_template('errors/500.html', title="Произошла ошибка!")


if __name__ == '__main__':
    #app.register_blueprint(telegramapi.blueprint)
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 5000)))
    #telegramapi.con.close()
