from flask import Flask, render_template, request, url_for, redirect, session,flash
from pymongo import MongoClient
import bcrypt
from flask_pymongo import PyMongo
from flask_mail import Mail, Message
import os
from flask_bcrypt import Bcrypt
#set app as a Flask instance 
app = Flask(__name__)


app.secret_key = b'\x9b\x1c\xe0\x9d\x1d\xaf\xc4\xec\xb4\xe8\xaf\xed\xcf\xb3\xea\xa4'  # Use a random secret key

app.config['MONGO_DBNAME'] = 'Pfe'
app.config['MONGO_URI'] = 'mongodb+srv://admin:QORuUa6PDqUfnIgj@cluster0.xktf2oc.mongodb.net/Pfe?retryWrites=true&w=majority'

mongo = PyMongo(app)

# Flask-Mail configuration
app.config['SECRET_KEY'] = "tsfyguaistyatuis589566875623568956"

app.config['MAIL_SERVER'] = "smtp.googlemail.com"

app.config['MAIL_PORT'] = 587

app.config['MAIL_USE_TLS'] = True

app.config['MAIL_USERNAME'] = "yassminezariat1@gmail.com"

app.config['MAIL_PASSWORD'] = "tpop mvct gtfq kpfa"

app.config['MAIL_DEFAULT_SENDER'] = "yassminezariat1@gmail.com" 

mail = Mail(app)
bcrypt = Bcrypt(app)


@app.route('/auth-forgot-password-basic', methods=['POST', 'GET'])
def forgotpassword():
    if request.method == 'POST':
        email = request.form['email']
        users = mongo.db.users
        user = users.find_one({'email': email})
        
        if user:
            token = os.urandom(24).hex()
            users.update_one({'email': email}, {'$set': {'reset_token': token}})
            reset_link = url_for('reset_password', token=token, _external=True)
            msg = Message('Password Reset Request', recipients=[email])
            msg.body = f'Please use the following link to reset your password: {reset_link}'
            mail.send(msg)
            flash('A password reset link has been sent to your email.', 'info')
        else:
            flash('Email address not found.', 'danger')
    return render_template('auth-forgot-password-basic.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    users = mongo.db.users
    user = users.find_one({'reset_token': token})
    
    if not user:
        flash('Invalid or expired token', 'danger')
        return redirect(url_for('forgotpassword'))
    
    if request.method == 'POST':
        password1 = request.form['password1']
        password2 = request.form['password2']
        
        if password1 == password2:
            hashpass = bcrypt.hashpw(password1.encode('utf-8'), bcrypt.gensalt())
            users.update_one({'reset_token': token}, {'$set': {'password': hashpass, 'reset_token': None}})
            flash('Your password has been reset successfully.', 'success')
            return redirect(url_for('authloginbasic'))
        else:
            flash('Passwords do not match', 'danger')
    email = user.get('email')
   
    return render_template('reset-password.html', token=token, email=email)


@app.route('/auth-forgot-password-basic')
def first():
    return render_template('auth-forgot-password-basic.html')

@app.route('/auth-login-basic', methods=['POST', 'GET'])
def authloginbasic():
    if request.method == 'POST':
        users = mongo.db.users
        login_user = users.find_one({'username': request.form['email-username']}) or users.find_one({'email': request.form['email-username']})

        if login_user:
            if bcrypt.checkpw(request.form['password'].encode('utf-8'), login_user['password']):
                session['username'] = login_user['username']
                flash('You have successfully logged in', 'success')
                return redirect(url_for('auth-login-basic'))  # Assuming you have an 'index' route
            else:
                flash('Invalid username/email or password', 'danger')
        else:
            flash('Invalid username/email or password', 'danger')
    return render_template('auth-login-basic.html')



@app.route('/auth-register-basic', methods=['POST', 'GET'])
def authregisterbasic():
    if request.method == 'POST':
        users = mongo.db.users  # Ensure this line doesn't raise an error
        existing_user = users.find_one({'username': request.form['username']})

        if existing_user is None:
            if request.form['password1'] == request.form['password2']:
                hashpass = bcrypt.hashpw(request.form['password1'].encode('utf-8'), bcrypt.gensalt())
                users.insert_one({
                    'username': request.form['username'],
                    'email': request.form['email'],
                    'password': hashpass
                })
                session['username'] = request.form['username']
                flash('You have successfully registered', 'success')
                return redirect(url_for('authloginbasic'))
            else:
                flash('Passwords do not match', 'danger')
        else:
            flash('Username already exists', 'danger')
    return render_template('auth-register-basic.html')

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)