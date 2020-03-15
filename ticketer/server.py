import hashlib
from flask import Flask, request, jsonify
from cryptography.fernet import Fernet
import sqlite3

app = Flask(__name__)

global uid
uid = 0
SALT = 'tick'

from sqlite3 import Error

def sql_connection():

    try:
        con = sqlite3.connect('ticketer.db')
        return con
    except Error:
        print(Error)

def sql_table(con):

    cursorObj = con.cursor()

    cursorObj.execute('''CREATE TABLE IF NOT EXISTS `keys`(
                      `id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
                      uid integer NOT NULL,
                      hash text NOT NULL,
                      key text NOT NULL,
                      created text NOT NULL);''')

    con.commit()

def insertKey(hash, key, uid):
    con = sqlite3.connect('ticketer.db')
    con.execute('''INSERT INTO keys
                    (uid, hash, key, created)
                    VALUES(?, ?, ?, DATETIME('now'));''', (str(uid), str(hash), key.decode('utf-8'))
                )
    con.commit()
    con.close()

def searchKey(hash, uid):
    con = sqlite3.connect('ticketer.db')
    key = con.execute('''SELECT key
                    FROM keys
                    WHERE keys.hash = "''' + str(hash) + '" AND keys.uid = ' + str(uid) + ';')
    k = key.fetchall()
    key = k[0][0]
    if not key:
        print('ERROR NOT FOUND KEY')
        return 0
    con.close()
    return key

@app.route('/', methods=['GET'])
def hello():
    return 'Hello'

@app.route('/makeKey', methods=['POST'])
def makeKey():
    global uid
    uid += 1

    key = Fernet.generate_key()  # Store this keys or get if you already have it
    print("MAKE " + request.form['userFrom'] + ' to ' + request.form['userTo'] + ' uid = ' + str(uid))
    hash = hashlib.sha256(SALT.encode() + request.form['userFrom'].encode() + request.form['userTo'].encode()).hexdigest()
    insertKey(hash, key, uid)
    return jsonify(key=key.decode('utf-8'), uid=uid)

@app.route('/getKey', methods=['POST'])
def getKey():
    print("GET " + request.form['userFrom'] + ' - ' + request.form['userTo'] + ' - ' + request.form['uid'])
    hash = hashlib.sha256(SALT.encode() + request.form['userFrom'].encode() + request.form['userTo'].encode()).hexdigest()
    key = searchKey(hash, request.form['uid'])
    if not key:
        print('ERROR')
        return 0
    return key


if __name__ == "__main__":
    con = sql_connection()
    sql_table(con)
    con.close()
    app.run(ssl_context=('cert.pem', 'key.pem'), host='127.0.0.1', port='8071')
