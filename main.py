import threading
import sqlite3
import webview

from copypaste import copy
from werkzeug.exceptions import abort
from flask import Flask, render_template, request, url_for, flash, redirect

from encript import encrypt_password, decrypt_password, encrypt_aes, decrypt_aes, decrypt_key, decrypt_js

app = Flask('Password Manager')
app.secret_key = b'_1#y2l"F4Q8z\n\xec]/'
app.config['SECRET_KEY'] = 'Tu_puya!+estafsdpa'
inputKey = ''


def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn


def get_sequence():
    conn = get_db_connection()
    num_accounts = conn.execute('SELECT max(id) FROM accounts').fetchone()
    conn.close()
    if num_accounts[0]:
        return num_accounts[0]
    else:
        return 0


def get_account(acc_id):
    conn = get_db_connection()
    account = conn.execute('SELECT * FROM accounts WHERE id = ?', (acc_id,)).fetchone()
    conn.close()
    if account is None:
        abort(404)
    return account


@app.route('/')
def index():
    conn = get_db_connection()
    accounts = conn.execute('SELECT * FROM accounts').fetchall()
    conn.close()
    return render_template('index.html', accounts=accounts)


@app.route('/create', methods=('GET', 'POST'))
def create():
    print(request.form)
    if request.method == 'POST':
        page = request.form['page']
        mail = request.form['mail']
        contra = request.form['contra']
        fact = request.form['fact']
        password = request.form['password']

        if not page or not mail or not contra or not password:
            flash('required!')
        else:
            try:
                contra = decrypt_js(contra)
                print(contra)
                print(password)
                pos_key = get_sequence()
                key = decrypt_key(inputKey, pos_key % 35)
                print(key)
                contra = encrypt_password(contra, password + inputKey, key)
            except Exception as e:
                print('[Error] Create() 1: ' + str(e))
                flash('Error Encriptant!')
            else:
                try:
                    conn = get_db_connection()
                    conn.execute('INSERT INTO accounts (page, mail, contra, fact) VALUES (?, ?, ?, ?)',
                                 (page, mail, contra, fact))
                    conn.commit()
                    conn.close()
                except Exception as e:
                    print('[Error] Create() 2: ' + str(e))
                    flash('Error creant la conta!')
                else:
                    return redirect(url_for('index'))

    return render_template('create.html')


@app.route('/getpasw/<int:id>', methods=("get", "post"))
def getpasw(id):
    # account = get_account(id)
    if request.method == 'POST':
        password = request.form['password']
        if not password:
            flash('required!')
        else:
            conn = get_db_connection()
            contra = conn.execute('SELECT contra FROM accounts WHERE id = ?', (id,)).fetchone()
            conn.close()
            # try:
            key = decrypt_key(inputKey, (id-1) % 35)
            print(key)
            print(password)
            copy(decrypt_password(contra[0], password + inputKey, key))
            # except ValueError:
            #     flash('Contra erronea.')
    return redirect(url_for('index'))


@app.route('/edit/<int:id>', methods=('GET', 'POST'))
def edit(id):
    account = get_account(id)

    if request.method == 'POST':
        page = request.form['page']
        mail = request.form['mail']
        contra = request.form['contra']
        fact = request.form['fact']

        if not page or not mail or not contra:
            flash('required!')
        else:
            conn = get_db_connection()
            conn.execute('UPDATE accounts SET page = ?, mail = ?, contra = ?, fact = ?, created = CURRENT_TIMESTAMP'
                         ' WHERE id = ?',
                         (page, mail, contra, fact, id))
            conn.commit()
            conn.close()
            return redirect(url_for('index'))

    return render_template('edit.html', account=account)


@app.route('/<int:id>/delete', methods=('POST',))
def delete(id):
    account = get_account(id)
    conn = get_db_connection()
    conn.execute('DELETE FROM accounts WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    flash('"{}" was successfully deleted!'.format(account['page']))
    return redirect(url_for('index'))


def start_flask_server():
    app.run(debug=False, port=9876)


if __name__ == '__main__':
    # print(get_sequence())
    inputKey = input('key:')
    # start_flask_server()
    x = threading.Thread(name='Web App', target=start_flask_server)
    x.setDaemon(True)
    x.start()

    webview.create_window('Password Manager', 'http://localhost:9876', width=666, height=600, resizable=True, fullscreen=False)
    webview.start()
    exit(0)
