import hashlib
from flask import Flask, request, jsonify
from cryptography.fernet import Fernet
import sqlite3
import datetime
from sqlite3 import Error
from apscheduler.schedulers.background import BackgroundScheduler

app = Flask(__name__)
global uid
uid = 0

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
                      created timestamp NOT NULL);''')
    con.commit()

con = sql_connection()
sql_table(con)
con.close()

def create_app():


    def insertKey(hash, key, uid):
        con = sqlite3.connect('ticketer.db')
        con.execute('''INSERT INTO keys
                        (uid, hash, key, created)
                        VALUES(?, ?, ?, ?);''', (str(uid), str(hash), key.decode('utf-8'), datetime.datetime.now()))
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
        hash = hashlib.sha256('SALT'.encode() + request.form['userFrom'].encode() + request.form[
            'userTo'].encode()).hexdigest()
        insertKey(hash, key, uid)
        return jsonify(key=key.decode('utf-8'), uid=uid)

    @app.route('/getKey', methods=['POST'])
    def getKey():
        print("GET " + request.form['userFrom'] + ' - ' + request.form['userTo'] + ' - ' + request.form['uid'])
        hash = hashlib.sha256('SALT'.encode() + request.form['userFrom'].encode() + request.form[
            'userTo'].encode()).hexdigest()
        key = searchKey(hash, request.form['uid'])
        if not key:
            print('ERROR')
            return 0
        return key

    def delete3rdYearsKeys():
        con = sqlite3.connect('ticketer.db')
        con.execute('''DELETE FROM keys WHERE created < NOW() - INTERVAL 3 YEAR''')
        con.commit()
        con.close()

    scheduler = BackgroundScheduler()
    scheduler.add_job(delete3rdYearsKeys, trigger='interval', seconds=60*60*24)
    scheduler.start()

    try:
        # To keep the main thread alive
        return app
    except:
        # shutdown if app occurs except
        scheduler.shutdown()



if __name__ == "__main__":
    app = create_app()
    app.run(port='801', host='0.0.0.0')
