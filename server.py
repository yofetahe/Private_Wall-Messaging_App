from flask import Flask, render_template, redirect, request, session, flash, url_for
from flask_bcrypt import Bcrypt
from mysqlconnection import connectToMySQL
import re

app = Flask('__name__')
app.secret_key = "developement_info"
bcrypt = Bcrypt(app)

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$') 
NAME_REGEX = re.compile(r'^[a-zA-Z ]')
PASSWORD_1_REGEX = re.compile(r'^[A-Z]')
PASSWORD_2_REGEX = re.compile(r'^[0-9]')

DB_NAME = 'private_wall'

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/get_log_in_form")
def get_log_in_form():
    # to check the user is on session or not
    if 'email' in session:
        return redirect("/home")

    return render_template("login.html", email='')

@app.route("/login", methods=['POST'])
def login():
    # to check the user is on session or not
    if 'email' in session:
        return redirect("/home")

    # Check if email and password is given or not
    errorCounter = 0
    email = request.form['email']
    password = request.form['password']
    if len(email) == 0:
        errorCounter += 1
        flash("Email is required", 'email')
    if len(password) == 0:
        errorCounter += 1
        flash("Password is required", 'password')
    if errorCounter > 0:
        return render_template("login.html", email=email)

    # Check if email and password exist in the database
    mysql = connectToMySQL(DB_NAME)
    query = "SELECT * FROM users WHERE email = %(email)s;"
    data = {
        "email": request.form['email']
    }
    user = mysql.query_db(query, data)
    if user and bcrypt.check_password_hash(user[0]['password'], request.form['password']):
        session['fname'] = user[0]['first_name']
        session['email'] = email
        session['userid'] = user[0]['id']
        
        return redirect("/home")
    else:
        flash("Incorrect information", 'general')
        return render_template("login.html", email=email)

@app.route("/get_user_registration_form")
def get_user_registration_form():
    # to check the user is on session or not
    if 'email' in session:
        return redirect("/home")

    return render_template("sign_up_form.html", fname='', lname='', email='')

@app.route("/register_user", methods=['POST'])
def register_user():
    # to check the user is on session or not
    if 'email' in session:
        return redirect("/home")

    fname = request.form['first_name']
    lname = request.form['last_name']
    email = request.form['email']
    # date_from = request.form['date_from']
    # date_to = request.form['date_to']
    password = request.form['password']
    confirm_password = request.form['confirm_password']

    # validate the information given
    errorCounter = 0
    
    if len(fname) == 0:
        errorCounter += 1
        flash("First name is required", 'first_name')
    else:
        if not NAME_REGEX.match(fname) or len(fname) < 2:
            errorCounter += 1
            flash("Invalid first name content and must contain only letter", 'first_name')
    if len(lname) == 0:
        errorCounter += 1
        flash("Last name is required", 'last_name')
    else:
        if not NAME_REGEX.match(lname) or len(lname) < 2:
            errorCounter += 1
            flash("Invalid last name content and must contain only letter", 'last_name')
    if len(email) == 0:
        errorCounter += 1
        flash("Email is required", 'email')
    else:
        if not EMAIL_REGEX.match(email):
            errorCounter += 1
            flash("Email is not valid", 'email')
    if len(password) == 0:
        errorCounter += 1
        flash("Password is required", 'password')
    else:
        if not re.search('[A-Z]',password) or not re.search('[0-9]',password):
            flash("The password should include at least one capital letter and one number", 'password')
        if len(password) < 8:
            flash("Password must be at least 8 character", 'password')    
    if len(confirm_password) == 0:
        errorCounter += 1
        flash("Confirm passowrd is required", 'confirm_password')
    else:
        if password != confirm_password:
            errorCounter += 1
            flash("Password don't match", 'password')

    if errorCounter > 0:
        return render_template("sign_up_form.html", fname=fname, lname=lname, email=email)
    else:
        # check whether the email already exist or not
        mysql = connectToMySQL(DB_NAME)
        query = "SELECT * FROM users WHERE email = %(email)s;"
        data = {
            "email":email
        }
        user = mysql.query_db(query, data)
        if user:
            flash("Email already register", 'email')
            return render_template("sign_up_form.html", fname=fname, lname=lname, email=email)

        # insert the information to database
        hash_password = bcrypt.generate_password_hash(password)
        mysql = connectToMySQL(DB_NAME)
        query = """INSERT INTO users(first_name, last_name, email, password, create_at) 
                    VALUES(%(fname)s, %(lname)s, %(email)s, %(hash_password)s, NOW())"""
        data = {
            "fname": fname,
            "lname": lname,
            "email": email,
            "hash_password": hash_password
        }
        userid = mysql.query_db(query, data)
        
        session['fname'] = fname
        session['email'] = email
        session['userid'] = userid

        return redirect("/home")

@app.route("/home")
def home():
    # to check the user is on session or not
    if 'email' in session:
        msgList=getMessageList()
        usersList = getAppUsersList()
        numOfMsgSent = countNumberOfMessageSent()
        numOfMsgReceived = countNumberOfMessageReceived()
        return render_template("home.html", msgList=msgList, msgCount=len(msgList), usersList=usersList, numOfMsgSent=numOfMsgSent, numOfMsgReceived=numOfMsgReceived)
    else:
        return redirect("/")

@app.route("/logout")
def logout():
    session.pop('fname')
    session.pop('email')
    session.pop('userid')
    return redirect("/")

# returns the message list sent to a specific user
def getMessageList():
    mysql = connectToMySQL(DB_NAME)
    query = """SELECT a.id, a.message_content, b.first_name, b.last_name, a.create_at, 
                    TIMESTAMPDIFF(SECOND,a.create_at,now()) sec, 
                    TIMESTAMPDIFF(MINUTE,a.create_at,now()) min, 
                    TIMESTAMPDIFF(HOUR,a.create_at,now()) hr, 
                    TIMESTAMPDIFF(DAY,a.create_at,now()) dy, 
                    TIMESTAMPDIFF(MONTH,a.create_at,now()) mon 
                FROM messages a join users b ON a.message_from = b.id 
                WHERE message_to = %(id)s"""
    data = {
        "id": session['userid']
    }
    return mysql.query_db(query, data)

# returns the list of users in the app
def getAppUsersList():
    mysql = connectToMySQL(DB_NAME)
    query = "SELECT * FROM users WHERE email != %(email)s;"
    data = {
        "email": session['email']
    }
    return mysql.query_db(query, data)

# returns the number of message sent by specific user
def countNumberOfMessageSent():
    mysql = connectToMySQL(DB_NAME)
    query = "SELECT count(id) as num FROM messages WHERE message_from = %(id)s;"
    data = {
        "id":session['userid']
    }
    msgCount = mysql.query_db(query, data)
    return msgCount[0]['num']

def countNumberOfMessageReceived():
    mysql = connectToMySQL(DB_NAME)
    query = "SELECT count(id) as num FROM messages WHERE message_to = %(id)s;"
    data = {
        "id":session['userid']
    }
    msgCount = mysql.query_db(query, data)
    return msgCount[0]['num']

@app.route("/send_message", methods=['POST'])
def send_message():
    userid = request.form['users']
    message_content = request.form['message_content']

    errorCounter = 0

    if len(userid) == 0:
        errorCounter += 1
        flash("Please select to whom you want to send message", 'users')
    if len(message_content) == 0:
        errorCounter += 1
        flash("Message is required", 'message')
    if errorCounter == 0:
        mysql = connectToMySQL(DB_NAME)
        query = "INSERT INTO messages(message_content, message_from, message_to, create_at) VALUES(%(content)s, %(from)s, %(to)s, NOW())"
        data = {
            "content":message_content,
            "from": session['userid'],
            "to": userid
        }
        mysql.query_db(query, data)
    return redirect("/home")

@app.route("/delete_message/<msg_id>")
def delete_message(msg_id):
    # check if the message belong to the logged-in user or not
    mysql = connectToMySQL(DB_NAME)
    query = "SELECT message_to FROM messages WHERE id = %(msg_id)s;"
    data = {
        "msg_id": msg_id
    }
    msgList = mysql.query_db(query, data)    
    if session['userid'] != msgList[0]['message_to']:
        # print(request.environ['REMOTE_ADDR'])
        # print(request.remote_addr)
        return redirect("danger/"+str(msg_id)+"/'"+str(request.remote_addr)+"'")

    # delete the message
    mysql = connectToMySQL(DB_NAME)
    query = "DELETE FROM messages WHERE id = %(msg_id)s;"
    data = {
        "msg_id": msg_id
    }
    mysql.query_db(query, data)
    return redirect("/home")

@app.route("/danger/<msg_id>/<ipaddress>")
def danger(msg_id, ipaddress):
    return render_template("danger.html", msg_id = msg_id, ipaddress=ipaddress)

@app.route("/search_friend", methods=['POST'])
def search_friend():
    mysql = connectToMySQL(DB_NAME)
    query = "SELECT * FROM users WHERE first_name LIKE %%(val)s OR last_name LIKE %%(val)s;"
    data = { "val": str(request.form['searchFriend'])+"%" }
    usersList = mysql.query_db(query, data)
    return render_template("partial/users_list.html", usersList=usersList)

if __name__ == '__main__':
    app.run(debug=True)