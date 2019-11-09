#!/usr/bin/env python3
from flask import Flask, render_template, redirect, url_for, request, flash, session, safe_join, send_from_directory
import time
#from flask_caching import Cache
from flask_sessionstore import Session
from subprocess import check_output
import subprocess
import os
from flask_wtf.csrf import CSRFProtect
from flask_sqlalchemy import SQLAlchemy 
from flask_login import login_user
from flask_login import UserMixin
from flask_login import LoginManager, logout_user, login_required
from flask_login import current_user
from sqlalchemy.orm import relationship
from datetime import datetime
from sqlalchemy import Column, Integer, DateTime
import bcrypt
from flask_bcrypt import generate_password_hash, check_password_hash
from flask_bcrypt import Bcrypt



#secret_key = 'test'
#SECRET_KEY = 'the swauaewriojerwer iorjoijreioajei'
app = Flask(__name__, static_folder='static')
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
#secret_key = 'test'
#SECRET_KEY = 'the swauaewriojerwer iorjoijreioajei'
#app.secret_key = 'test'
app.config['SECRET_KEY'] = 'test'
app.config['SESSION_TYPE'] = 'filesystem'
#app.config['USE_SIGNER'] = True
#SESSION_USE_SIGNER = True
#SESSION_COOKIE_SECURE=True,
#SESSION_COOKIE_HTTPONLY=True
#SESSION_COOKIE_SAMESITE='Lax'
app.config['SESSION_USE_SIGNER'] = True
#app.config['SESSION_COOKIE_SECURE']=True,
#app.config['SESSION_COOKIE_HTTPONLY']=True
#app.config['SESSION_COOKIE_SAMESITE']='Lax'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///example.sqlite"
db = SQLAlchemy(app)




class Userinfo(db.Model, UserMixin):
    myid = db.Column(db.Integer, primary_key=True)
    myusername = db.Column(db.String, unique=True, nullable=False)
    mypassword = db.Column(db.String, unique=True, nullable=False)
    twofactorbro = db.Column(db.String, unique=True, nullable=True)
    #    myinputquery = db.Column(db.String, unique=True, nullable=True)
 #   myoutputquery = db.Column(db.String, unique=True, nullable=True)

    def __init__(self , myusername ,mypassword , twofactorbro):
        self.myusername = myusername
        self.mypassword = mypassword
        self.twofactorbro = twofactorbro
    
    def is_authenticated(self):
        return True
 
    def is_active(self):
        return self.myid
 
    def is_anonymous(self):
        return False
 
    def get_id(self):
        return self.myid
 
    def __repr__(self):
        return '<User %r>' % (self.myusername)

class queryinfo(db.Model, UserMixin):
    __tablename__ = 'Queries'
    myidtwo = db.Column(db.Integer, primary_key=True)
    myauthor = db.Column(db.Integer,db.ForeignKey(Userinfo.myid))
    myinputquery = db.Column(db.String, unique=False, nullable=True)
    myoutputquery = db.Column(db.String, unique=False, nullable=True)
    queryusername = relationship("Userinfo",primaryjoin="and_(queryinfo.myauthor==Userinfo.myid," "Userinfo.myusername)")
    def __init__(self , myauthor , myinputquery, myoutputquery,):
        self.myauthor = myauthor
        self.myinputquery = myinputquery
        self.myoutputquery = myoutputquery

class logstime(db.Model, UserMixin):
    myidthree = db.Column(db.Integer, primary_key=True)
    loggeduser = db.Column(db.Integer,db.ForeignKey(Userinfo.myid))
    lastlogintime = Column(DateTime, nullable=True)
    lastlogouttime = Column(DateTime, nullable=True)
    logsqueryusername = relationship("Userinfo",primaryjoin="and_(logstime.loggeduser==Userinfo.myid," "Userinfo.myusername)")

  #  def __init__(self , loggeduser , lastlogintime, lastlogouttime,):
   #     self.loggeduser = loggeduser
    #    self.lastlogintime = lastlogintime
     #   self.lastlogouttime = lastlogouttime
 #   def __init__(self , loggeduser , lastlogintime, lastlogouttime):
  #      self.loggeduser = loggeduser
  #      self.lastlogintime = lastlogintime
   #     self.lastlogouttime = lastlogouttime

    #users = db.relationship(users)

#WTF_CSRF_ENABLED = True
# cache = Cache(app, config={'CACHE_TYPE': 'simple'})
sess = Session(app)
csrf = CSRFProtect(app)
csrf.init_app(app)
#sess.init_app(app)


#@app.route('/robots.txt', methods=['POST', 'GET'])
#def static_from_root():
 #   return send_from_directory(app.static_folder, request.path[1:])
@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        enc_pass = bcrypt.generate_password_hash(request.form['password'])
        #print(request.form['password'],enc_pass)
        my_registered_user = Userinfo.query.filter_by(myusername=request.form['username']).first()
        if my_registered_user is not None:
            flash('Username exists' , 'error')
            return redirect(url_for('register'))
        #my_registered_user_two = Userinfo.query.filter_by(twofactorbro=request.form['twoFactor']).first()
       # if my_registered_user_two is not None:
        #    flash('2fa is in use, are you already registered? Please relogin' , 'error')
         #   return redirect(url_for('register'))
        if request.form['twoFactor'] == '':
            pass
        elif not request.form['twoFactor'].isdigit():
            flash('Two-factor failure')
            return render_template('register.html')
        elif  not (len(request.form['twoFactor']) < 13):  
            flash('Two-factor failure')
            return render_template('register.html')
        elif not (len(request.form['twoFactor']) >= 10):
            flash('Two-factor failure')
            return render_template('register.html')
        user = Userinfo(myusername=request.form['username'], mypassword=enc_pass,twofactorbro=request.form['twoFactor'])
        db.session.add(user)
        db.session.commit()
        flash('Registered Successfully, Please Login')

        '''with open('Login.txt', 'r') as file:
            for line in file:
                userN, passW, twoF = line.strip().split(',')
                if userN == request.form['username']:
                    flash('User already exists please login')
                    return render_template('register.html')
        file.close()
        with open('Login.txt', 'r') as file:
            for line in file:
                userN, passW, twoF = line.strip().split(',')
            if userN != request.form['username'] and twoF == request.form['twoFactor']:
                flash('2fa is in use, are you already registered? Please relogin.')
                return render_template('register.html')

        file.close()
        if not request.form['twoFactor'].isdigit():
            flash('Two-factor failure')
            return render_template('register.html')
        if  not (len(request.form['twoFactor']) < 13):  
            flash('Two-factor failure')
            return render_template('register.html')
        if not (len(request.form['twoFactor']) >= 10):
            flash('Two-factor failure')
            return render_template('register.html')
        with open('Login.txt', 'a') as file:
            #userN, passW, twoF = line.strip().split(',')
            file.write(request.form['username'])
            file.write(',')#\n
            file.write(request.form['password'])
            file.write(',')
            if request.form['twoFactor'] == '':
                file.write('\n')
            else:
                file.write(request.form['twoFactor'])
                file.write('\n')
            file.close()
            flash('Registered successfully, Please Login')      '''

    return render_template('register.html')


    #return "Hello World!"
 #file = open("Login.txt","a")
  #  file.write (username)
   # file.write (",")
    #file.write (password)
    #file.write("\n")
    #file.close()

@app.route('/login', methods=['POST', 'GET'])
# @cache.cached(timeout=0)
def login():

    # error = None
    #isauthenticated = False
    if request.method == 'POST':
        enc_pass = bcrypt.generate_password_hash(request.form['password'])
        
        
        inputuser=request.form['username']
        myuser = db.session.query(Userinfo).filter(Userinfo.myusername==request.form['username']).first()
        enc_pass_a = bcrypt.check_password_hash(enc_pass, myuser.mypassword)
        if enc_pass_a is None:
            flash('Username or Password is invalid' , 'error')
            return redirect(url_for('login'))
        #print(myuser)
        #print(request.form['password'],enc_pass,enc_pass_a)
        registered_user = Userinfo.query.filter_by(myusername=request.form['username'],twofactorbro=request.form['twoFactor']).first()
        if registered_user is None:
            flash('Username or Password is invalid' , 'error')
            return redirect(url_for('login'))
        login_user(registered_user)
        currettime= datetime.now()
        #currettime=str(currettime)
        full = "%Y-%m-%d %H:%M:%S.%f"
        myfmt = "%Y-%m-%d %H:%M:%S"
        #currettime=datetime.strptime(currettime, full)
        update_logs = logstime(loggeduser=request.form['username'],lastlogintime=datetime.now())
        db.session.add(update_logs)
        db.session.commit()
        #print(update_logs)
        flash('Logged in successfully')
        '''with open('Login.txt', 'r') as file:
            for line in file:
                userN, passW, twoF = line.strip().split(',')
            #   print("", userN,passW,twoF)
            #   print("", request.form['username'],request.form['password'],request.form['twoFactor'])
                if userN == request.form['username']:
                    if passW == request.form['password']:
                        if twoF == '':
                            flash('Logged in successfully')     
                            return render_template('login.html')
                        if twoF == request.form['twoFactor']:
                            flash('Logged in successfully')
                            #isauthenticated = True
                            session['auth'] = True
                            return render_template('login.html')
                            #return redirect(url_for('spell_check'))
                        elif twoF != request.form['twoFactor']:
                            flash('Two-factor failure')
                            session['auth'] = False
                            return render_template('login.html')
        if not ((userN == request.form['username']) and (passW == request.form['password'])):
            flash('Incorrect')
            session['auth'] = False'''
    return render_template('login.html')

@login_manager.user_loader
def user_loader(user_id):
    user = Userinfo.query.filter_by(myid=user_id).first()
    if user:
        return user
    return None

@app.route('/spell_check', methods=['POST', 'GET'])
@login_required
def spell_check():
    if request.method == 'POST':
        words = request.form['word']
        misspelled = 'misspelled-words: '
        seperator = '|'
        thewords = 'Original Input: '
        with open('output-words.txt', 'w') as f:#pattern = ,
            f.write(str(words))
            f.close()
#stdout = subprocess.check_output(["./templates/some.sh", words, dictionary])#.decode('utf-8')
        process = subprocess.check_output(['./a.out', 'output-words.txt', "wordlist.txt"]).decode('utf-8').replace("\n",", ").rstrip(", ")#[:-2] 
        posts = queryinfo(myauthor=current_user.myid, myinputquery=words,myoutputquery=process)
        db.session.add(posts)
        db.session.commit()
        #return '{} {} {} {} {} {} {}'.format(misspelled, seperator, process, seperator, thewords, seperator, words)
        return render_template('spell_check.html',bruhthemisspelledwords=process, bruhtheinput=words)
    return render_template('spell_check.html')

    #misspelledOut = process.replace("\n", ", ").strip().strip(',')
#       misspelledOut = [x for x in pattern.split(process) if x]
    
@app.route('/success')
def flash_success():
    flash('This message will be visible!')
    time.sleep(1)
    return redirect(url_for('hello'))

@app.route('/logout')
@login_required
def logout():
    update_logs = logstime(loggeduser=current_user.myusername,lastlogouttime=datetime.now())
    db.session.add(update_logs)
    db.session.commit()
    logout_user()
    flash('Logged out successfully, try to access spell check without logging. I will redirect you back to login hahahahahahaha')
    return redirect(url_for('login'))

@app.route('/history', methods=['POST', 'GET'])
@login_required
def history():
    #users = db.session.query(queryinfo).all()
    if request.method == 'POST':
        if current_user.myusername == 'admin':
            inputuser = request.form['username']
            #print(inputuser)
            users = db.session.query(queryinfo, Userinfo).join(Userinfo).filter_by(myusername=inputuser)
            return render_template('history.html', posts=users)
    if request.method == 'GET':
        if current_user.myusername == 'admin':
            users = db.session.query(queryinfo, Userinfo).join(Userinfo).all()
        #for post in users:
        #print (post.myinputquery, post.myoutputquery)
            return render_template('history.html',posts=users)
        if not current_user.myusername == 'admin':
            users = db.session.query(queryinfo, Userinfo).join(Userinfo).filter_by(myusername=current_user.myusername)
            return render_template('history.html',posts=users)
    

#return f'<h1>The user is located in: {post.myinputquery, post.myoutputquery}</h1>'
    #allposts = db.session.query(queryinfo.myinputquery).filter(queryinfo.myauthor == current_user.myid).first()
    #return f'<h1>The user is located in: {post}</h1>'
    #return render_template('history.html',bruhthemisspelledwords=process)

@app.route('/history/query<int:query_number>', methods=['POST', 'GET'])
@login_required
def query_history(query_number):
    if request.method == 'POST':
        if not current_user.myusername == 'admin':
            the_post = db.session.query(queryinfo, Userinfo).filter_by(myidtwo=query_number).join(Userinfo).filter_by(myusername=current_user.myusername)
            return render_template('history.html',posts=the_post)
        if current_user.myusername == 'admin':
            inputuser = request.form['username']
            #print(inputuser)
            the_post = db.session.query(queryinfo, Userinfo).filter_by(myidtwo=query_number).join(Userinfo).filter_by(myusername=inputuser)
            return render_template('history.html',posts=the_post)
    #print(query_number)<--major key without this i wouldnt have understood what i was doing.
    if request.method == 'GET':
        if current_user.myusername == 'admin':
            the_post = db.session.query(queryinfo, Userinfo).filter_by(myidtwo=query_number).join(Userinfo).all()
            return render_template('history.html',posts=the_post)

    #return render_template('history.html')
    #f'<h1>Query Bro </h1><p> Username: { current_user.myusername } { the_post.myinputquery}</p>'
#{{ the_post.myusername }} 
#{{ the_post.myinputquery }}
#{{ the_post.myoutputquery }}

@app.route('/login_history', methods=['POST', 'GET'])
@login_required
def loginhistory():
    if request.method == 'POST':
        if current_user.myusername == 'admin':
            inputuser = request.form['username']
            #print(inputuser)
            users = db.session.query(logstime).filter(logstime.loggeduser==inputuser)
            #users = db.session.query(logstime).join(Userinfo).filter(Userinfo.myusername==inputuser)
    #print(users)
            return render_template('login_history.html', posts=users)
    if request.method == 'GET':
        if current_user.myusername == 'admin':
            users = db.session.query(logstime).all()
            return render_template('login_history.html', posts=users)
    #return render_template('login_history.html')




if __name__ == '__main__':
    db.create_all()
    app.run(debug=True, host= '0.0.0.0')
