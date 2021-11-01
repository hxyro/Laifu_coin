from wtforms import Form, StringField, DecimalField, IntegerField, TextAreaField, PasswordField, validators
from flask import Flask, flash, render_template, redirect, url_for, session, request, logging
from passlib.hash import sha256_crypt
from flask_mysqldb import MySQL
from functools import wraps
from hashlib import sha256
import time



#flask_main
app = Flask(__name__)



#############################################################################################################
#							                                                                                #
#							                                                                                #
#		  					 _     _            _        _           _                                      #
#		 					| |   | |          | |      | |         (_)                                     #
#							| |__ | | ___   ___| | _____| |__   __ _ _ _ __                                 #
#							| '_ \| |/ _ \ / __| |/ / __| '_ \ / _` | | '_ \                                #
#							| |_) | | (_) | (__|   < (__| | | | (_| | | | | |                               #
#							|_.__/|_|\___/ \___|_|\_\___|_| |_|\__,_|_|_| |_|                               #
#							                                                                                #
#							                                                                                #
#							                                                                                #
#############################################################################################################



def updatehash(*args):
    hash_str = ""; hamsh = sha256()

    for arg in args:
        hash_str += str(arg)

    hamsh.update(hash_str.encode('utf-8'))
    return hamsh.hexdigest()

class Block():

    def __init__(self,number=0, previous_hash="0"*64, data=None, nonce=0):
        self.data = data
        self.number = number
        self.previous_hash = previous_hash
        self.nonce = nonce

    def hash(self):
        return updatehash(self.number, self.previous_hash, self.data, self.nonce)

    def __str__(self):
        return str("Block#: %s\nHash: %s\nPrevious: %s\nData: %s\nNonce: %s\n" %(self.number, self.hash(), self.previous_hash, self.data, self.nonce))


class Blockchain():
    difficulty = 4

    def __init__(self):
        self.chain = []

    def add(self, block):
        self.chain.append(block)

    def remove(self, block):
        self.chain.remove(block)

    def mine(self, block):
        try: block.previous_hash = self.chain[-1].hash()
        except IndexError: pass

        while True:
            if block.hash()[:self.difficulty] == "0" * self.difficulty:
                self.add(block); break
            else:
                block.nonce += 1

    def isValid(self):
        for i in range(1,len(self.chain)):
            _previous = self.chain[i].previous_hash
            _current = self.chain[i-1].hash()
            if _previous != _current or _current[:self.difficulty] != "0"*self.difficulty:
                return False
        return True



#############################################################################################################
#############################################################################################################



#############################################################################################################
#                                                                                                           #
#                                                                                                           #
#                    __  __        _____  ____  _        _____ _   _ _____ _______                          #
#                   |  \/  |      / ____|/ __ \| |      |_   _| \ | |_   _|__   __|                         #
#                   | \  / |_   _| (___ | |  | | |        | | |  \| | | |    | |                            #
#                   | |\/| | | | |\___ \| |  | | |        | | | . ` | | |    | |                            #
#                   | |  | | |_| |____) | |__| | |____   _| |_| |\  |_| |_   | |                            #
#                   |_|  |_|\__, |_____/ \___\_\______| |_____|_| \_|_____|  |_|                            #
#                            __/ |                                                                          #
#                           |___/                                                                           #
#                                                                                                           #
#                                                                                                           #
#############################################################################################################

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'Ayush@2003'
app.config['MYSQL_DB'] = 'blockchain'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
mysql = MySQL(app)

class InvalidTransactionException(Exception): pass
class InsufficientFundsException(Exception): pass

class Table():
    def __init__(self, table_name, *args):
        self.table = table_name
        self.columns = "(%s)" %",".join(args)
        self.columnsList = args

        if isnewtable(table_name):
            create_data = ""
            for column in self.columnsList:
                create_data += "%s varchar(100)," %column

            cur = mysql.connection.cursor()
            cur.execute("CREATE TABLE %s(%s)" %(self.table, create_data[:len(create_data)-1]))
            cur.close()

    def getall(self):
        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM %s" %self.table)
        data = cur.fetchall(); return data

    def getone(self, search, value):
        data = {}; cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM %s WHERE %s = \"%s\"" %(self.table, search, value))
        if result > 0: data = cur.fetchone()
        cur.close(); return data

    def deleteone(self, search, value):
        cur = mysql.connection.cursor()
        cur.execute("DELETE from %s where %s = \"%s\"" %(self.table, search, value))
        mysql.connection.commit(); cur.close()

    def deleteall(self):
        self.drop()
        self.__init__(self.table, *self.columnsList)

    def drop(self):
        cur = mysql.connection.cursor()
        cur.execute("DROP TABLE %s" %self.table)
        cur.close()

    def insert(self, *args):
        data = ""
        for arg in args:
            data += "\"%s\"," %(arg)

        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO %s%s VALUES(%s)" %(self.table, self.columns, data[:len(data)-1]))
        mysql.connection.commit()
        cur.close()

def sql_raw(execution):
    cur = mysql.connection.cursor()
    cur.execute(execution)
    mysql.connection.commit()
    cur.close()

def isnewtable(tableName):
    cur = mysql.connection.cursor()

    try:
        result = cur.execute("SELECT * from %s" %tableName)
        cur.close()
    except:
        return True
    else:
        return False

def isnewuser(username):
    users = Table("users", "name", "email", "username", "password")
    data = users.getall()
    usernames = [user.get('username') for user in data]

    return False if username in usernames else True

def send_money(sender, recipient, amount):
    try: amount = float(amount)
    except ValueError:
        raise InvalidTransactionException("Invalid Transaction.")

    if amount > get_balance(sender) and sender != "BANK":
        raise InsufficientFundsException("Insufficient Funds.")

    elif sender == recipient or amount <= 0.00:
        raise InvalidTransactionException("Invalid Transaction.")

    elif isnewuser(recipient):
        raise InvalidTransactionException("User Does Not Exist.")

    blockchain = get_blockchain()
    number = len(blockchain.chain) + 1
    data = "%s-->%s-->%s" %(sender, recipient, amount)
    blockchain.mine(Block(number, data=data))
    sync_blockchain(blockchain)

def get_balance(username):
    balance = 0.00
    blockchain = get_blockchain()

    for block in blockchain.chain:
        data = block.data.split("-->")
        if username == data[0]:
            balance -= float(data[2])
        elif username == data[1]:
            balance += float(data[2])
    return balance

def get_blockchain():
    blockchain = Blockchain()
    blockchain_sql = Table("blockchain", "number", "hash", "previous", "data", "nonce")
    for b in blockchain_sql.getall():
        blockchain.add(Block(int(b.get('number')), b.get('previous'), b.get('data'), int(b.get('nonce'))))

    return blockchain

def sync_blockchain(blockchain):
    blockchain_sql = Table("blockchain", "number", "hash", "previous", "data", "nonce")
    blockchain_sql.deleteall()

    for block in blockchain.chain:
        blockchain_sql.insert(str(block.number), block.hash(), block.previous_hash, block.data, block.nonce)




#############################################################################################################
#############################################################################################################



#############################################################################################################
#							                                                                                #
#							                                                                                #
#							          _    __                                                               #
#							         | |  / _|                                                              #
#							__      _| |_| |_ ___  _ __ _ __ ___  ___                                       #
#							\ \ /\ / / __|  _/ _ \| '__| '_ ` _ \/ __|                                      #
#							 \ V  V /| |_| || (_) | |  | | | | | \__ \                                      #
#							  \_/\_/  \__|_| \___/|_|  |_| |_| |_|___/                                      #
#							                                                                                #
#							                                                                                #
#							                                                                                # 
#############################################################################################################



class RegisterForm(Form):
    name = StringField('Full Name', [validators.Length(min=1,max=50)])
    username = StringField('Username', [validators.Length(min=4,max=25)])
    email = StringField('Email', [validators.Length(min=6,max=50)])
    password = PasswordField('Password', [validators.DataRequired(), validators.EqualTo('confirm', message='Passwords do not match')])
    confirm = PasswordField('Confirm Password')

class SendMoneyForm(Form):
    username = StringField('Username', [validators.Length(min=4,max=25)])
    amount = StringField('Amount', [validators.Length(min=1,max=10)])

class BuyForm(Form):
    amount = StringField('Amount', [validators.Length(min=1,max=10)])



#############################################################################################################
#############################################################################################################



#############################################################################################################
#									                                                                        #
#									                 _                                                      #
#									                (_)                                                     #
#									 _ __ ___   __ _ _ _ __                                                 #
#									| '_ ` _ \ / _` | | '_ \                                                #
#									| | | | | | (_| | | | | |                                               #
#									|_| |_| |_|\__,_|_|_| |_|                                               #
#									                                                                        #
#									                                                                        #
#									                                                                        #
#############################################################################################################



def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash("Unauthorized, please login.", "danger")
            return redirect(url_for('login'))
    return wrap

def log_in_user(username):
    users = Table("users", "name", "email", "username", "password")
    user = users.getone("username", username)

    session['logged_in'] = True
    session['username'] = username
    session['name'] = user.get('name')
    session['email'] = user.get('email')

@app.route("/register", methods = ['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    users = Table("users", "name", "email", "username", "password")

    if request.method == 'POST' and form.validate():
        username = form.username.data
        email = form.email.data
        name = form.name.data

        if isnewuser(username):
            password = sha256_crypt.encrypt(form.password.data)
            users.insert(name,email,username,password)
            log_in_user(username)
            return redirect(url_for('dashboard'))
        else:
            flash('User already exists', 'danger')
            return redirect(url_for('register'))

    return render_template('register.html', form=form)

@app.route("/login", methods = ['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        candidate = request.form['password']

        users = Table("users", "name", "email", "username", "password")
        user = users.getone("username", username)
        accPass = user.get('password')

        if accPass is None:
            flash("Username is not found", 'danger')
            return redirect(url_for('login'))
        else:
            if sha256_crypt.verify(candidate, accPass):
                log_in_user(username)
                flash('You are now logged in.', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash("Invalid password", 'danger')
                return redirect(url_for('login'))

    return render_template('login.html')

@app.route("/transaction", methods = ['GET', 'POST'])
@is_logged_in
def transaction():
    form = SendMoneyForm(request.form)
    balance = get_balance(session.get('username'))

    if request.method == 'POST':
        try:
            send_money(session.get('username'), form.username.data, form.amount.data)
            flash("Money Sent!", "success")
        except Exception as e:
            flash(str(e), 'danger')
        return redirect(url_for('transaction'))
    return render_template('transaction.html', balance=balance, form=form, page='transaction')

@app.route("/buy", methods = ['GET', 'POST'])
@is_logged_in
def buy():
    form = BuyForm(request.form)
    balance = get_balance(session.get('username'))

    if request.method == 'POST':
        try:
            send_money("BANK", session.get('username'), form.amount.data)
            flash("Purchase Successful!", "success")
        except Exception as e:
            flash(str(e), 'danger')
        return redirect(url_for('dashboard'))
    return render_template('buy.html', balance=balance, form=form, page='buy')

@app.route("/logout")
@is_logged_in
def logout():
    session.clear()
    flash("Logout success", "success")
    return redirect(url_for('login'))

@app.route("/dashboard")
@is_logged_in
def dashboard():
    balance = get_balance(session.get('username'))
    blockchain = get_blockchain().chain
    ct = time.strftime("%I:%M %p")
    return render_template('dashboard.html', balance=balance, session=session, ct=ct, blockchain=blockchain, page='dashboard')

@app.route("/")
@app.route("/index")
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.secret_key = 'secret123'
    app.run(debug = True)



#############################################################################################################
#############################################################################################################
