
import email
import functools
from re import X
from unittest import result
from email import message
from flask import Flask, render_template, request, flash, redirect, url_for,session, g, make_response, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from db import get_db
import utils
from email.message import EmailMessage
import smtplib
import os
from db import get_db, close_db


# from mensajes import mensajes

app = Flask(__name__)
app.secret_key = os.urandom(24)

@app.route( '/' )
def index():
    if g.user:
        return redirect( url_for( 'escribir' ) )
    return render_template( 'login.html' )

@app.route('/register', methods=['GET','POST'])
def register():
    if g.user:
        return redirect( url_for( 'escribir' ) )
    try:
        if request.method == 'POST':
            name= request.form['nombre']
            username = request.form['username']
            password = request.form['password']
            email = request.form['email']
            error = None  
            db = get_db()

            if not utils.isPasswordValid(password):
                error = 'La contraseña no es válida. Debe tener al menos 8 caracteres, una mayúscula, una minúscula, un número y un caracter especial'
                flash(error)
                return render_template('register.html', error=error)
            
            if not utils.isEmailValid(email):
                error = 'El email no es válido'
                flash(error)
                return render_template('register.html', error=error)
            
           
            if db.execute( 'SELECT * FROM usuario WHERE correo = ?', (email,) ).fetchone() is not None:
                error = 'El correo ya existe'.format( email )
                flash( error )
                return render_template( 'register.html' )
            credentials = {
                'user': 'ovenegas@uninorte.edu.co',
                'password': 'oscar_9404',
            }           
            db.execute(
                'INSERT INTO usuario (nombre, usuario, correo, contraseña) VALUES (?,?,?,?)',
                (name, username, email, generate_password_hash(password))
            )
            db.commit()
            close_db() 
            send_email(credentials, receiver = email, subject="Activa tu cuenta", message = 'Gracias por registrarte')
            flash('Usuario registrado con exito, activa el usuario en enlace enviado a tu correo', 'success')                       
            return redirect(url_for('login'))                      
        return render_template('register.html')           
    except:
        return render_template('register.html')


@app.route('/login', methods=['GET','POST'])
def login():   
    try:
        if g.user:
            return redirect( url_for( 'escribir' ) )
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            db = get_db()
            error = None
           
            if not username:
                error = 'Debes ingresar el usuario'
                flash( error )
                return render_template( 'login.html' )

            if not password:
                error = 'Contraseña requerida'
                flash( error )
                return render_template( 'login.html' )
    
            user = db.execute(
                'SELECT * FROM usuario WHERE usuario = ? AND contraseña = ?', (username, password)
            ).fetchone()
            print( user )
            if user is None:
                user = db.execute(
                    'SELECT * FROM usuario WHERE usuario = ?', (username,)
                ).fetchone()
                if user is None:
                    error = 'Usuario no existe'
                else:
                    #Validar contraseña hash            
                    store_password = user[4]
                    result = check_password_hash(store_password, password)
                    if result is False:
                        error = 'Contraseña inválida'
                    else:
                        session.clear()
                        session['user_id'] = user[0]
                        resp = make_response( redirect( url_for( 'escribir' ) ) )
                        resp.set_cookie( 'username', username )
                        return resp
                    flash( error )
            else:
                session.clear()
                session['user_id'] = user[0]
                return redirect( url_for( 'escribir' ) )
            flash( error )
            close_db()
        return render_template( 'login.html' )
    except Exception as e:
        print(e)
        return render_template( 'login.html' )

def login_required(view):
    @functools.wraps( view )
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect( url_for( 'login' ) )

        return view( **kwargs )

    return wrapped_view

@app.route('/escribir', methods=['GET','POST'])
@login_required
def escribir():
    if request.method == 'POST':
        #from_id = g.user['id']
        to_username = request.form['para']
        subject = request.form['asunto']
        body = request.form['mensaje']
        db = get_db()

        if not to_username:
            flash( 'Para campo requerido' )
            return render_template( 'escribir.html' )

        if not subject:
            flash( 'Asunto es requerido' )
            return render_template( 'escribir.html' )

        if not body:
            flash( 'Mensaje es requerido' )
            return render_template( 'escribir.html' )

        error = None
        userto = None

        userto = db.execute(
            'SELECT * FROM usuario WHERE usuario = ?', (to_username,)
        ).fetchone()

        if userto is None:
            error = 'No existe ese usuario'
            flash('No existe ese usuario', 'error')
            
        if error is not None:
            flash( error )
            
        else:
            db = get_db()
            db.execute(
                'INSERT INTO mensaje (from_id, to_id, asunto, mensaje)'
                ' VALUES (?, ?, ?, ?)',
                (g.user['id'], userto['id'], subject, body)
            )
            db.commit()
            
            error = 'Mensaje enviado'
            flash('Mensaje enviado', 'succes')
        
        close_db()
    return render_template( 'escribir.html' )
  
@app.route('/mensajes')
@login_required
def mensajes():
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM mensaje WHERE to_id = ?', (g.user['id'],))
    mensajes = cursor.fetchall()
    print(mensajes)   
    return render_template('mensajes.html', mensajes=mensajes)



@app.before_request
def load_logged_in_user():
    user_id = session.get( 'user_id' )

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM usuario WHERE id = ?', (user_id,)
        ).fetchone()
        close_db()

@app.route( '/logout' )
def logout():
    session.clear()
    return redirect( url_for( 'login' ) )

def send_email(credentials, receiver, subject, message):
    # Create Email
    email = EmailMessage()
    email["From"] = credentials['user']
    email["To"] = receiver
    email["Subject"] = subject
    email.set_content(message)

    # Send Email
    smtp = smtplib.SMTP("smtp-mail.outlook.com", port=587)
    smtp.starttls()
    smtp.login(credentials['user'], credentials['password'])
    smtp.sendmail(credentials['user'], receiver, email.as_string())
    smtp.quit()


if __name__ == '__main__':
    app.run(debug=True)