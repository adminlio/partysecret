from flask import Flask, render_template, request, redirect, url_for, session
import bcrypt
import os
import json

app = Flask(__name__)
app.secret_key = "TU_LLAVE_SECRETA_AQUI"

archivo_contraseñas = "pj.json"

# Cargar usuarios desde JSON
def cargar_usuarios():
    if not os.path.exists(archivo_contraseñas):
        return {}
    with open(archivo_contraseñas, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {}

# Guardar usuarios en JSON
def guardar_usuarios(usuarios):
    with open(archivo_contraseñas, "w", encoding="utf-8") as f:
        json.dump(usuarios, f, indent=4)

# Registrar usuario
def registrar_usuario(usuario, contraseña):
    usuarios = cargar_usuarios()
    if usuario in usuarios:
        return False  # usuario ya existe
    contraseña_bytes = contraseña.encode('utf-8')
    hash_seguro = bcrypt.hashpw(contraseña_bytes, bcrypt.gensalt()).decode('utf-8')
    usuarios[usuario] = hash_seguro
    guardar_usuarios(usuarios)
    return True

# Verificar login
def verificar_usuario(usuario, contraseña):
    usuarios = cargar_usuarios()
    if usuario not in usuarios:
        return False
    hash_guardado = usuarios[usuario].encode('utf-8')
    return bcrypt.checkpw(contraseña.encode('utf-8'), hash_guardado)

# Página de registro
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        usuario = request.form['usuario']
        contraseña = request.form['contraseña']
        if registrar_usuario(usuario, contraseña):
            return "✅ Usuario registrado!<br><a href='/login'>Ir a login</a>"
        else:
            return "❌ El usuario ya existe. Elige otro."
    return render_template("registro.html")

# Página de login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        usuario = request.form['usuario']
        contraseña = request.form['contraseña']
        if verificar_usuario(usuario, contraseña):
            session['usuario'] = usuario
            return redirect(url_for('index'))
        else:
            return "❌ Usuario o contraseña incorrectos."
    return render_template("login.html")

# Página principal
@app.route('/')
def index():
    if 'usuario' in session:
        return f"🎉 Bienvenido a Mundodefiesta, {session['usuario']}!<br>" \
               f"<a href='/logout'>Cerrar sesión</a>" + \
               (" | <a href='/usuarios'>Ver usuarios</a>" if session['usuario'] == "admin" else "")
    return redirect(url_for('login'))

# Página de administración: listar y borrar usuarios
@app.route('/usuarios', methods=["GET", "POST"])
def usuarios():
    if 'usuario' not in session or session['usuario'] != "admin":
        return "⛔ Acceso denegado. Solo el administrador puede ver esta página."

    lista_usuarios = cargar_usuarios()

    if request.method == "POST":
        usuario_a_borrar = request.form.get("borrar")
        if usuario_a_borrar in lista_usuarios:
            del lista_usuarios[usuario_a_borrar]
            guardar_usuarios(lista_usuarios)
            return redirect(url_for("usuarios"))

    return render_template("usuarios.html", usuarios=lista_usuarios)

# Logout
@app.route('/logout')
def logout():
    session.pop('usuario', None)
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(debug=True)