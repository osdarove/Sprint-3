from asyncio.windows_events import NULL
import email
from email import message
from flask import Flask, render_template, request, flash, jsonify, redirect, url_for, flash
from db import get_db
import utils
from email.message import EmailMessage
import smtplib
import os
from db import get_db, close_db


# from mensajes import mensajes

app = Flask(__name__)
app.secret_key = os.urandom(24)
@app.route('/')
def index():
    return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':

        username = request.form['username']        
        password = request.form['password']

        db = get_db()
        cursor = db.cursor()
        cursor.execute('SELECT * FROM registro WHERE nombre = ? AND contraseña = ?', (username, password))
        user = cursor.fetchone()
        cursor.close()
        if user is None:
            flash('Usuario o contraseña incorrectos', 'error')
        else:           
            return redirect('mensajes')           
    return render_template('login.html')
@app.route('/escribir', methods=['GET','POST'])
def escribir():
    if request.method == 'POST':
        tuid = request.form['nombre']
        destino = request.form['descripcion']
        asunto= request.form['precio']
        mensaje = request.form['stock']
        
        try:
            if not tuid or not destino or not mensaje or not asunto:
                flash('Todos los campos son obligatorios', 'error')
                return redirect(url_for('register_product'))

            db = get_db()
            cursor = db.cursor()
            cursor.execute('INSERT INTO mensajes (from_id, to_id, asunto, mensaje) VALUES (?,?,?,?)', (tuid, destino, asunto, mensaje))
            db.commit()
            close_db()
            flash('Producto registrado con exito', 'success')
            return redirect(url_for('escribir'))
        except:
            flash('Error al registrar el producto', 'error')
            return render_template('escribir.html')
    return render_template('escribir.html')

@app.route('/register', methods=['GET','POST'])
def register():
    try:
        if request.method == 'POST':
            username = request.form['nombre']
            password = request.form['password']
            email = request.form['email']
            error = None
             

                     
            if not utils.isPasswordValid(password):
                error = 'La contraseña no es válida. Debe tener al menos 8 caracteres, una mayúscula, una minúscula, un número y un caracter especial'
                flash(error)
                return render_template('register.html', error=error)
            
            if not utils.isEmailValid(email):
                error = 'El email no es válido'
                flash(error)
                return render_template('register.html', error=error)
            credentials = {
                'user': 'ovenegas@uninorte.edu.co',
                'password': 'oscar_9404',
            }
            send_email(credentials, receiver = email, subject="Activa tu cuenta", message = 'Gracias por registrarte')
            db = get_db()
            cursor = db.cursor()
            cursor.execute('INSERT INTO registro (nombre, correo, contraseña) VALUES (?,?,?)', ( username, email, password))
            db.commit()
            close_db() 
            flash('Usuario registrado con exito', 'success')                       
            return redirect(url_for('login'))                      
        return render_template('register.html')           
    except:
        return render_template('register.html')






@app.route('/mensajes')
def mensajes():
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM mensajes')
    mensajes = cursor.fetchall()
    print(mensajes)   
    return render_template('mensajes.html', mensajes=mensajes)

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