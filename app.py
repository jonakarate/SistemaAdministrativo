import os
from functools import wraps
from datetime import datetime

from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash
from dotenv import load_dotenv


# ============================================================
# CONFIGURACIÓN
# ============================================================

load_dotenv()

app = Flask(__name__)

app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "CAMBIAR_ESTA_CLAVE")

app.config["SQLALCHEMY_DATABASE_URI"] = (
    f"postgresql+psycopg2://"
    f"{os.getenv('DB_USER')}:"
    f"{os.getenv('DB_PASSWORD')}@"
    f"{os.getenv('DB_HOST')}:"
    f"{os.getenv('DB_PORT')}/"
    f"{os.getenv('DB_NAME')}"
)

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


# ============================================================
# MODELO USUARIO
# ============================================================

class Usuario(db.Model):
    __tablename__ = "usuario"

    id = db.Column(db.BigInteger, primary_key=True)
    empleado_id = db.Column(db.BigInteger)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True)
    password_hash = db.Column(db.Text, nullable=False)
    activo = db.Column(db.Boolean, nullable=False)
    bloqueado = db.Column(db.Boolean, nullable=False)
    intentos_fallidos = db.Column(db.Integer, nullable=False)
    debe_cambiar_password = db.Column(db.Boolean, nullable=False)


# ============================================================
# MODELO ROL
# ============================================================

class Rol(db.Model):
    __tablename__ = "rol"

    id = db.Column(db.BigInteger, primary_key=True)
    nombre = db.Column(db.String(50), unique=True, nullable=False)
    descripcion = db.Column(db.String(150))
    activo = db.Column(db.Boolean, nullable=False)


# ============================================================
# MODELO USUARIO_ROL
# ============================================================

class UsuarioRol(db.Model):
    __tablename__ = "usuario_rol"

    id = db.Column(db.BigInteger, primary_key=True)
    usuario_id = db.Column(db.BigInteger, nullable=False)
    rol_id = db.Column(db.BigInteger, nullable=False)
    activo = db.Column(db.Boolean, nullable=False)

# ============================================================
# MODELO PERMISO_SISTEMA
# ============================================================

class PermisoSistema(db.Model):

    __tablename__ = "permiso_sistema"

    id = db.Column(
        db.BigInteger,
        primary_key=True
    )

    codigo = db.Column(
        db.String(100),
        nullable=False
    )

    nombre = db.Column(
        db.String(150),
        nullable=False
    )

    modulo = db.Column(
        db.String(100),
        nullable=False
    )

    descripcion = db.Column(
        db.Text,
        nullable=True
    )

    activo = db.Column(
        db.Boolean,
        nullable=False
    )

    created_at = db.Column(
        db.DateTime,
        nullable=False
    )

    updated_at = db.Column(
        db.DateTime,
        nullable=False
    )


# ============================================================
# MODELO ROL_PERMISO
# ============================================================

class RolPermiso(db.Model):

    __tablename__ = "rol_permiso"

    id = db.Column(
        db.BigInteger,
        primary_key=True
    )

    rol_id = db.Column(
        db.BigInteger,
        nullable=False
    )

    permiso_id = db.Column(
        db.BigInteger,
        nullable=False
    )

    activo = db.Column(
        db.Boolean,
        nullable=False
    )

    created_at = db.Column(
        db.DateTime,
        nullable=False
    )

    updated_at = db.Column(
        db.DateTime,
        nullable=False
    )

# ============================================================
# MODELO EMPRESA
# ============================================================

class Empresa(db.Model):

    __tablename__ = "empresa"

    id = db.Column(db.BigInteger, primary_key=True)
    nombre = db.Column(db.String(150), nullable=False)
    razon_social = db.Column(db.String(150))
    nit = db.Column(db.String(50))
    telefono = db.Column(db.String(50))
    email = db.Column(db.String(150))
    direccion = db.Column(db.Text)
    activo = db.Column(db.Boolean, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False)
    updated_at = db.Column(db.DateTime, nullable=False)

# ============================================================
# MODELO SUCURSAL
# ============================================================

class Sucursal(db.Model):

    __tablename__ = "sucursal"

    id = db.Column(db.BigInteger, primary_key=True)
    empresa_id = db.Column(db.BigInteger, nullable=False)
    nombre = db.Column(db.String(150), nullable=False)
    codigo = db.Column(db.String(50))
    telefono = db.Column(db.String(50))
    direccion = db.Column(db.Text)
    activo = db.Column(db.Boolean, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False)
    updated_at = db.Column(db.DateTime, nullable=False)

# ============================================================
# MODELO AREA
# ============================================================

class Area(db.Model):

    __tablename__ = "area"

    id = db.Column(db.BigInteger, primary_key=True)
    sucursal_id = db.Column(db.BigInteger, nullable=False)
    nombre = db.Column(db.String(150), nullable=False)
    descripcion = db.Column(db.Text)
    activo = db.Column(db.Boolean, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False)
    updated_at = db.Column(db.DateTime, nullable=False)

# ============================================================
# MODELO CARGO
# ============================================================

class Cargo(db.Model):

    __tablename__ = "cargo"

    id = db.Column(db.BigInteger, primary_key=True)
    nombre = db.Column(db.String(150), nullable=False)
    descripcion = db.Column(db.Text)
    activo = db.Column(db.Boolean, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False)
    updated_at = db.Column(db.DateTime, nullable=False)

# ============================================================
# SISTEMA DE PERMISOS
# ============================================================

def tiene_permiso(codigo_permiso):
    """
    Verifica si el usuario actualmente conectado
    tiene un permiso específico.
    """

    usuario_id = session.get("usuario_id")

    if not usuario_id:
        return False

    # Obtener el rol activo del usuario
    usuario_rol = (
        UsuarioRol.query
        .filter_by(
            usuario_id=usuario_id,
            activo=True
        )
        .first()
    )

    if not usuario_rol:
        return False

    # SUPERADMIN tiene acceso total
    rol = (
        Rol.query
        .filter_by(
            id=usuario_rol.rol_id,
            activo=True
        )
        .first()
    )

    if not rol:
        return False

    if rol.nombre == "SUPERADMIN":
        return True

    # Verificar el permiso específico
    permiso = (
        db.session.query(RolPermiso)
        .join(
            PermisoSistema,
            RolPermiso.permiso_id == PermisoSistema.id
        )
        .filter(
            RolPermiso.rol_id == rol.id,
            RolPermiso.activo == True,
            PermisoSistema.codigo == codigo_permiso,
            PermisoSistema.activo == True
        )
        .first()
    )

    return permiso is not None


def requiere_permiso(codigo_permiso):
    """
    Protege una ruta mediante un permiso del sistema.
    """

    def decorador(func):

        @wraps(func)
        def funcion_protegida(*args, **kwargs):

            # No hay sesión iniciada
            if "usuario_id" not in session:
                return redirect(url_for("login"))

            # El usuario no tiene el permiso
            if not tiene_permiso(codigo_permiso):
                flash(
                    "No tiene permisos para realizar esta acción.",
                    "error"
                )
                return redirect(url_for("dashboard"))

            return func(*args, **kwargs)

        return funcion_protegida

    return decorador
# Permitir usar tiene_permiso() dentro de las plantillas Jinja
app.jinja_env.globals["tiene_permiso"] = tiene_permiso

# ============================================================
# INICIO
# ============================================================

@app.route("/")
def inicio():

    if "usuario_id" in session:
        return redirect(url_for("dashboard"))

    return redirect(url_for("login"))


# ============================================================
# LOGIN
# ============================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Ingrese usuario y contraseña.", "error")
            return render_template("login.html")

        usuario = Usuario.query.filter_by(username=username).first()

        if usuario is None:
            flash("Usuario o contraseña incorrectos.", "error")
            return render_template("login.html")

        if not usuario.activo:
            flash("El usuario está inactivo.", "error")
            return render_template("login.html")

        if usuario.bloqueado:
            flash("El usuario está bloqueado.", "error")
            return render_template("login.html")

        if not check_password_hash(usuario.password_hash, password):

            usuario.intentos_fallidos += 1
            db.session.commit()

            flash("Usuario o contraseña incorrectos.", "error")
            return render_template("login.html")

        # Login correcto

        usuario.intentos_fallidos = 0
        db.session.commit()

        session.clear()

        session["usuario_id"] = usuario.id
        session["username"] = usuario.username

        usuario_rol = (
            UsuarioRol.query
            .filter_by(usuario_id=usuario.id, activo=True)
            .first()
        )

        if usuario_rol:

            rol = (
                Rol.query
                .filter_by(id=usuario_rol.rol_id, activo=True)
                .first()
            )

            if rol:
                session["rol_id"] = rol.id
                session["rol"] = rol.nombre

        return redirect(url_for("dashboard"))

    return render_template("login.html")


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/dashboard")
def dashboard():

    if "usuario_id" not in session:
        return redirect(url_for("login"))

    return render_template("dashboard.html")

# ============================================================
# LOGOUT
# ============================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("login"))

# ============================================================
# USUARIOS
# ============================================================

@app.route("/usuarios")
@requiere_permiso("USUARIO_VER")
def usuarios():

    usuarios = Usuario.query.order_by(Usuario.id.asc()).all()

    return render_template(
        "usuarios.html",
        usuarios=usuarios
    )

# ============================================================
# NUEVO USUARIO
# ============================================================

@app.route("/usuarios/nuevo", methods=["GET", "POST"])
@requiere_permiso("USUARIO_CREAR")
def nuevo_usuario():

    roles = (
        Rol.query
        .filter_by(activo=True)
        .order_by(Rol.nombre.asc())
        .all()
    )

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        password_confirmacion = request.form.get(
            "password_confirmacion",
            ""
        )
        rol_id = request.form.get("rol_id", "").strip()

        # ----------------------------------------------------
        # VALIDACIONES
        # ----------------------------------------------------

        if not username:
            flash("El nombre de usuario es obligatorio.", "error")
            return render_template(
                "nuevo_usuario.html",
                roles=roles
            )

        if not password:
            flash("La contraseña es obligatoria.", "error")
            return render_template(
                "nuevo_usuario.html",
                roles=roles
            )

        if password != password_confirmacion:
            flash("Las contraseñas no coinciden.", "error")
            return render_template(
                "nuevo_usuario.html",
                roles=roles
            )

        if len(password) < 8:
            flash(
                "La contraseña debe tener al menos 8 caracteres.",
                "error"
            )
            return render_template(
                "nuevo_usuario.html",
                roles=roles
            )

        if not rol_id:
            flash("Debe seleccionar un rol.", "error")
            return render_template(
                "nuevo_usuario.html",
                roles=roles
            )

        # ----------------------------------------------------
        # VERIFICAR USUARIO EXISTENTE
        # ----------------------------------------------------

        usuario_existente = (
            Usuario.query
            .filter_by(username=username)
            .first()
        )

        if usuario_existente:
            flash(
                "El nombre de usuario ya está registrado.",
                "error"
            )
            return render_template(
                "nuevo_usuario.html",
                roles=roles
            )

        # ----------------------------------------------------
        # VERIFICAR EMAIL EXISTENTE
        # ----------------------------------------------------

        if email:
            email_existente = (
                Usuario.query
                .filter_by(email=email)
                .first()
            )

            if email_existente:
                flash(
                    "El correo electrónico ya está registrado.",
                    "error"
                )
                return render_template(
                    "nuevo_usuario.html",
                    roles=roles
                )

        # ----------------------------------------------------
        # VERIFICAR ROL
        # ----------------------------------------------------

        rol = (
            Rol.query
            .filter_by(
                id=int(rol_id),
                activo=True
            )
            .first()
        )

        if not rol:
            flash("El rol seleccionado no es válido.", "error")
            return render_template(
                "nuevo_usuario.html",
                roles=roles
            )

        # ----------------------------------------------------
        # CREAR USUARIO
        # ----------------------------------------------------

        nuevo = Usuario(
            username=username,
            email=email if email else None,
            password_hash=generate_password_hash(password),
            activo=True,
            bloqueado=False,
            intentos_fallidos=0,
            debe_cambiar_password=True
        )

        db.session.add(nuevo)
        db.session.flush()

        # ----------------------------------------------------
        # ASIGNAR ROL
        # ----------------------------------------------------

        usuario_rol = UsuarioRol(
            usuario_id=nuevo.id,
            rol_id=rol.id,
            activo=True
        )

        db.session.add(usuario_rol)

        db.session.commit()

        flash(
            f"Usuario '{username}' creado correctamente.",
            "success"
        )

        return redirect(url_for("usuarios"))

    return render_template(
        "nuevo_usuario.html",
        roles=roles
    )

# ============================================================
# EDITAR USUARIO
# ============================================================

@app.route("/usuarios/<int:usuario_id>/editar", methods=["GET", "POST"])
@requiere_permiso("USUARIO_EDITAR")
def editar_usuario(usuario_id):

    usuario = Usuario.query.get_or_404(usuario_id)

    roles = (
        Rol.query
        .filter_by(activo=True)
        .order_by(Rol.nombre.asc())
        .all()
    )

    # --------------------------------------------------------
    # OBTENER ROL ACTUAL
    # --------------------------------------------------------

    usuario_rol_actual = (
        UsuarioRol.query
        .filter_by(
            usuario_id=usuario.id,
            activo=True
        )
        .first()
    )

    rol_actual_id = (
        usuario_rol_actual.rol_id
        if usuario_rol_actual
        else None
    )

    # --------------------------------------------------------
    # GUARDAR CAMBIOS
    # --------------------------------------------------------

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        password_confirmacion = request.form.get(
            "password_confirmacion",
            ""
        )
        rol_id = request.form.get("rol_id", "").strip()

        activo = request.form.get("activo") == "1"
        bloqueado = request.form.get("bloqueado") == "1"

        # ----------------------------------------------------
        # VALIDAR USUARIO
        # ----------------------------------------------------

        if not username:
            flash(
                "El nombre de usuario es obligatorio.",
                "error"
            )

            return render_template(
                "editar_usuario.html",
                usuario=usuario,
                roles=roles,
                rol_actual_id=rol_actual_id
            )

        # ----------------------------------------------------
        # VERIFICAR USERNAME DUPLICADO
        # ----------------------------------------------------

        usuario_existente = (
            Usuario.query
            .filter(
                Usuario.username == username,
                Usuario.id != usuario.id
            )
            .first()
        )

        if usuario_existente:
            flash(
                "El nombre de usuario ya está registrado.",
                "error"
            )

            return render_template(
                "editar_usuario.html",
                usuario=usuario,
                roles=roles,
                rol_actual_id=rol_actual_id
            )

        # ----------------------------------------------------
        # VERIFICAR EMAIL DUPLICADO
        # ----------------------------------------------------

        if email:

            email_existente = (
                Usuario.query
                .filter(
                    Usuario.email == email,
                    Usuario.id != usuario.id
                )
                .first()
            )

            if email_existente:
                flash(
                    "El correo electrónico ya está registrado.",
                    "error"
                )

                return render_template(
                    "editar_usuario.html",
                    usuario=usuario,
                    roles=roles,
                    rol_actual_id=rol_actual_id
                )

        # ----------------------------------------------------
        # VERIFICAR ROL
        # ----------------------------------------------------

        if not rol_id:

            flash(
                "Debe seleccionar un rol.",
                "error"
            )

            return render_template(
                "editar_usuario.html",
                usuario=usuario,
                roles=roles,
                rol_actual_id=rol_actual_id
            )

        rol = (
            Rol.query
            .filter_by(
                id=int(rol_id),
                activo=True
            )
            .first()
        )

        if not rol:

            flash(
                "El rol seleccionado no es válido.",
                "error"
            )

            return render_template(
                "editar_usuario.html",
                usuario=usuario,
                roles=roles,
                rol_actual_id=rol_actual_id
            )

        # ----------------------------------------------------
        # VALIDAR NUEVA CONTRASEÑA
        # ----------------------------------------------------

        if password:

            if password != password_confirmacion:

                flash(
                    "Las contraseñas no coinciden.",
                    "error"
                )

                return render_template(
                    "editar_usuario.html",
                    usuario=usuario,
                    roles=roles,
                    rol_actual_id=rol_actual_id
                )

            if len(password) < 8:

                flash(
                    "La contraseña debe tener al menos 8 caracteres.",
                    "error"
                )

                return render_template(
                    "editar_usuario.html",
                    usuario=usuario,
                    roles=roles,
                    rol_actual_id=rol_actual_id
                )

            usuario.password_hash = generate_password_hash(password)

            # Al cambiar la contraseña manualmente,
            # ya no es obligatorio cambiarla al iniciar sesión.
            usuario.debe_cambiar_password = False

        # ----------------------------------------------------
        # ACTUALIZAR DATOS DEL USUARIO
        # ----------------------------------------------------

        usuario.username = username
        usuario.email = email if email else None
        usuario.activo = activo
        usuario.bloqueado = bloqueado

        # ----------------------------------------------------
        # ACTUALIZAR ROL
        # ----------------------------------------------------

        relaciones = (
            UsuarioRol.query
            .filter_by(
                usuario_id=usuario.id
            )
            .all()
        )

        # Desactivar todas las relaciones actuales
        for relacion in relaciones:
            relacion.activo = False

        # Buscar si la relación con el nuevo rol YA EXISTE
        relacion_rol = (
            UsuarioRol.query
            .filter_by(
                usuario_id=usuario.id,
                rol_id=rol.id
            )
            .first()
        )

        if relacion_rol:
            # La relación ya existe: simplemente la reactivamos
            relacion_rol.activo = True

        else:
            # La relación no existe: la creamos
            nueva_relacion = UsuarioRol(
                usuario_id=usuario.id,
                rol_id=rol.id,
                activo=True
            )

            db.session.add(nueva_relacion)


        # ----------------------------------------------------
        # GUARDAR
        # ----------------------------------------------------

        db.session.commit()

        flash(
            f"Usuario '{usuario.username}' actualizado correctamente.",
            "success"
        )

        return redirect(url_for("usuarios"))

    # --------------------------------------------------------
    # MOSTRAR FORMULARIO
    # --------------------------------------------------------

    return render_template(
        "editar_usuario.html",
        usuario=usuario,
        roles=roles,
        rol_actual_id=rol_actual_id
    )
# ============================================================
# BLOQUEAR USUARIO
# ============================================================

@app.route("/usuarios/<int:usuario_id>/bloquear", methods=["POST"])
@requiere_permiso("USUARIO_BLOQUEAR")
def bloquear_usuario(usuario_id):

    usuario = Usuario.query.get_or_404(usuario_id)

    # Evitar que el usuario se bloquee a sí mismo
    if usuario.id == session.get("usuario_id"):

        flash(
            "No puede bloquear su propio usuario.",
            "error"
        )

        return redirect(url_for("usuarios"))

    usuario.bloqueado = True
    usuario.intentos_fallidos = 0

    db.session.commit()

    flash(
        f"Usuario '{usuario.username}' bloqueado correctamente.",
        "success"
    )

    return redirect(url_for("usuarios"))


# ============================================================
# DESBLOQUEAR USUARIO
# ============================================================

@app.route("/usuarios/<int:usuario_id>/desbloquear", methods=["POST"])
@requiere_permiso("USUARIO_BLOQUEAR")
def desbloquear_usuario(usuario_id):

    usuario = Usuario.query.get_or_404(usuario_id)

    usuario.bloqueado = False
    usuario.intentos_fallidos = 0

    db.session.commit()

    flash(
        f"Usuario '{usuario.username}' desbloqueado correctamente.",
        "success"
    )

    return redirect(url_for("usuarios"))

# ============================================================
# ROLES
# ============================================================

@app.route("/roles")
@requiere_permiso("ROL_VER")
def roles():

    roles = (
        Rol.query
        .order_by(Rol.id.asc())
        .all()
    )

    permisos_por_rol = {}

    for rol in roles:

        cantidad = (
            db.session.query(RolPermiso)
            .filter(
                RolPermiso.rol_id == rol.id,
                RolPermiso.activo == True
            )
            .count()
        )

        permisos_por_rol[rol.id] = cantidad

    return render_template(
        "roles.html",
        roles=roles,
        permisos_por_rol=permisos_por_rol
    )

# ============================================================
# EDITAR PERMISOS DE UN ROL
# ============================================================

@app.route("/roles/<int:rol_id>/permisos", methods=["GET", "POST"])
@requiere_permiso("ROL_EDITAR")
def editar_permisos_rol(rol_id):

    rol = Rol.query.get_or_404(rol_id)

    # Todos los permisos activos del sistema, ordenados por módulo
    permisos = (
        PermisoSistema.query
        .filter_by(activo=True)
        .order_by(
            PermisoSistema.modulo.asc(),
            PermisoSistema.nombre.asc()
        )
        .all()
    )

    # --------------------------------------------------------
    # GUARDAR CAMBIOS
    # --------------------------------------------------------

    if request.method == "POST":

        # SUPERADMIN tiene acceso total garantizado por código
        # (ver tiene_permiso()). No se edita desde aquí para
        # evitar inconsistencias entre la interfaz y el acceso real.
        if rol.nombre == "SUPERADMIN":

            flash(
                "El rol SUPERADMIN tiene acceso total y no se puede modificar.",
                "error"
            )

            return redirect(url_for("roles"))

        ids_seleccionados = request.form.getlist("permisos")

        ids_seleccionados = set(
            int(permiso_id) for permiso_id in ids_seleccionados
        )

        ahora = datetime.utcnow()

        # Relaciones que ya existen entre este rol y los permisos
        relaciones_existentes = (
            RolPermiso.query
            .filter_by(rol_id=rol.id)
            .all()
        )

        relaciones_por_permiso_id = {
            relacion.permiso_id: relacion
            for relacion in relaciones_existentes
        }

        for permiso in permisos:

            debe_estar_activo = permiso.id in ids_seleccionados

            relacion = relaciones_por_permiso_id.get(permiso.id)

            if relacion:

                # Ya existe la relación: solo actualizamos su estado
                # si cambió, para no tocar filas innecesariamente.
                if relacion.activo != debe_estar_activo:
                    relacion.activo = debe_estar_activo
                    relacion.updated_at = ahora

            else:

                # No existe la relación todavía.
                # Solo la creamos si el permiso fue marcado.
                if debe_estar_activo:

                    nueva_relacion = RolPermiso(
                        rol_id=rol.id,
                        permiso_id=permiso.id,
                        activo=True,
                        created_at=ahora,
                        updated_at=ahora
                    )

                    db.session.add(nueva_relacion)

        db.session.commit()

        flash(
            f"Permisos del rol '{rol.nombre}' actualizados correctamente.",
            "success"
        )

        return redirect(url_for("roles"))

    # --------------------------------------------------------
    # MOSTRAR FORMULARIO
    # --------------------------------------------------------

    # IDs de permisos actualmente activos para este rol
    permisos_activos_ids = {
        relacion.permiso_id
        for relacion in (
            RolPermiso.query
            .filter_by(rol_id=rol.id, activo=True)
            .all()
        )
    }

    # Agrupar permisos por módulo para mostrarlos ordenados
    permisos_por_modulo = {}

    for permiso in permisos:
        permisos_por_modulo.setdefault(permiso.modulo, []).append(permiso)

    return render_template(
        "editar_permisos_rol.html",
        rol=rol,
        permisos_por_modulo=permisos_por_modulo,
        permisos_activos_ids=permisos_activos_ids
    )

# ============================================================
# EMPRESAS
# ============================================================

@app.route("/empresas")
@requiere_permiso("EMPRESA_VER")
def empresas():

    empresas = (
        Empresa.query
        .order_by(Empresa.nombre.asc())
        .all()
    )

    return render_template(
        "empresas.html",
        empresas=empresas
    )


# ============================================================
# NUEVA EMPRESA
# ============================================================

@app.route("/empresas/nueva", methods=["GET", "POST"])
@requiere_permiso("EMPRESA_CREAR")
def nueva_empresa():

    if request.method == "POST":

        nombre = request.form.get("nombre", "").strip()
        razon_social = request.form.get("razon_social", "").strip()
        nit = request.form.get("nit", "").strip()
        telefono = request.form.get("telefono", "").strip()
        email = request.form.get("email", "").strip()
        direccion = request.form.get("direccion", "").strip()

        if not nombre:
            flash(
                "El nombre de la empresa es obligatorio.",
                "error"
            )
            return render_template("nueva_empresa.html")

        ahora = datetime.utcnow()

        nueva = Empresa(
            nombre=nombre,
            razon_social=razon_social if razon_social else None,
            nit=nit if nit else None,
            telefono=telefono if telefono else None,
            email=email if email else None,
            direccion=direccion if direccion else None,
            activo=True,
            created_at=ahora,
            updated_at=ahora
        )

        db.session.add(nueva)
        db.session.commit()

        flash(
            f"Empresa '{nueva.nombre}' creada correctamente.",
            "success"
        )

        return redirect(url_for("empresas"))

    return render_template("nueva_empresa.html")


# ============================================================
# EDITAR EMPRESA
# ============================================================

@app.route("/empresas/<int:empresa_id>/editar", methods=["GET", "POST"])
@requiere_permiso("EMPRESA_EDITAR")
def editar_empresa(empresa_id):

    empresa = Empresa.query.get_or_404(empresa_id)

    if request.method == "POST":

        nombre = request.form.get("nombre", "").strip()
        razon_social = request.form.get("razon_social", "").strip()
        nit = request.form.get("nit", "").strip()
        telefono = request.form.get("telefono", "").strip()
        email = request.form.get("email", "").strip()
        direccion = request.form.get("direccion", "").strip()

        if not nombre:
            flash(
                "El nombre de la empresa es obligatorio.",
                "error"
            )
            return render_template(
                "editar_empresa.html",
                empresa=empresa
            )

        empresa.nombre = nombre
        empresa.razon_social = razon_social if razon_social else None
        empresa.nit = nit if nit else None
        empresa.telefono = telefono if telefono else None
        empresa.email = email if email else None
        empresa.direccion = direccion if direccion else None
        empresa.updated_at = datetime.utcnow()

        db.session.commit()

        flash(
            f"Empresa '{empresa.nombre}' actualizada correctamente.",
            "success"
        )

        return redirect(url_for("empresas"))

    return render_template(
        "editar_empresa.html",
        empresa=empresa
    )


# ============================================================
# DESACTIVAR EMPRESA
# ============================================================

@app.route("/empresas/<int:empresa_id>/desactivar", methods=["POST"])
@requiere_permiso("EMPRESA_ELIMINAR")
def desactivar_empresa(empresa_id):

    empresa = Empresa.query.get_or_404(empresa_id)

    empresa.activo = False
    empresa.updated_at = datetime.utcnow()

    db.session.commit()

    flash(
        f"Empresa '{empresa.nombre}' desactivada correctamente.",
        "success"
    )

    return redirect(url_for("empresas"))


# ============================================================
# ACTIVAR EMPRESA
# ============================================================

@app.route("/empresas/<int:empresa_id>/activar", methods=["POST"])
@requiere_permiso("EMPRESA_ELIMINAR")
def activar_empresa(empresa_id):

    empresa = Empresa.query.get_or_404(empresa_id)

    empresa.activo = True
    empresa.updated_at = datetime.utcnow()

    db.session.commit()

    flash(
        f"Empresa '{empresa.nombre}' activada correctamente.",
        "success"
    )

    return redirect(url_for("empresas"))


# ============================================================
# SUCURSALES
# ============================================================

@app.route("/sucursales")
@requiere_permiso("SUCURSAL_VER")
def sucursales():

    sucursales = (
        db.session.query(Sucursal, Empresa)
        .join(Empresa, Sucursal.empresa_id == Empresa.id)
        .order_by(Sucursal.nombre.asc())
        .all()
    )

    return render_template(
        "sucursales.html",
        sucursales=sucursales
    )


# ============================================================
# NUEVA SUCURSAL
# ============================================================

@app.route("/sucursales/nueva", methods=["GET", "POST"])
@requiere_permiso("SUCURSAL_CREAR")
def nueva_sucursal():

    empresas_disponibles = (
        Empresa.query
        .filter_by(activo=True)
        .order_by(Empresa.nombre.asc())
        .all()
    )

    if request.method == "POST":

        empresa_id = request.form.get("empresa_id", "").strip()
        nombre = request.form.get("nombre", "").strip()
        codigo = request.form.get("codigo", "").strip()
        telefono = request.form.get("telefono", "").strip()
        direccion = request.form.get("direccion", "").strip()

        if not nombre:
            flash(
                "El nombre de la sucursal es obligatorio.",
                "error"
            )
            return render_template(
                "nueva_sucursal.html",
                empresas_disponibles=empresas_disponibles
            )

        if not empresa_id:
            flash(
                "Debe seleccionar una empresa.",
                "error"
            )
            return render_template(
                "nueva_sucursal.html",
                empresas_disponibles=empresas_disponibles
            )

        empresa = (
            Empresa.query
            .filter_by(id=int(empresa_id), activo=True)
            .first()
        )

        if not empresa:
            flash(
                "La empresa seleccionada no es válida.",
                "error"
            )
            return render_template(
                "nueva_sucursal.html",
                empresas_disponibles=empresas_disponibles
            )

        ahora = datetime.utcnow()

        nueva = Sucursal(
            empresa_id=empresa.id,
            nombre=nombre,
            codigo=codigo if codigo else None,
            telefono=telefono if telefono else None,
            direccion=direccion if direccion else None,
            activo=True,
            created_at=ahora,
            updated_at=ahora
        )

        db.session.add(nueva)
        db.session.commit()

        flash(
            f"Sucursal '{nueva.nombre}' creada correctamente.",
            "success"
        )

        return redirect(url_for("sucursales"))

    return render_template(
        "nueva_sucursal.html",
        empresas_disponibles=empresas_disponibles
    )


# ============================================================
# EDITAR SUCURSAL
# ============================================================

@app.route("/sucursales/<int:sucursal_id>/editar", methods=["GET", "POST"])
@requiere_permiso("SUCURSAL_EDITAR")
def editar_sucursal(sucursal_id):

    sucursal = Sucursal.query.get_or_404(sucursal_id)

    empresas_disponibles = (
        Empresa.query
        .filter_by(activo=True)
        .order_by(Empresa.nombre.asc())
        .all()
    )

    if request.method == "POST":

        empresa_id = request.form.get("empresa_id", "").strip()
        nombre = request.form.get("nombre", "").strip()
        codigo = request.form.get("codigo", "").strip()
        telefono = request.form.get("telefono", "").strip()
        direccion = request.form.get("direccion", "").strip()

        if not nombre:
            flash(
                "El nombre de la sucursal es obligatorio.",
                "error"
            )
            return render_template(
                "editar_sucursal.html",
                sucursal=sucursal,
                empresas_disponibles=empresas_disponibles
            )

        if not empresa_id:
            flash(
                "Debe seleccionar una empresa.",
                "error"
            )
            return render_template(
                "editar_sucursal.html",
                sucursal=sucursal,
                empresas_disponibles=empresas_disponibles
            )

        empresa = (
            Empresa.query
            .filter_by(id=int(empresa_id), activo=True)
            .first()
        )

        if not empresa:
            flash(
                "La empresa seleccionada no es válida.",
                "error"
            )
            return render_template(
                "editar_sucursal.html",
                sucursal=sucursal,
                empresas_disponibles=empresas_disponibles
            )

        sucursal.empresa_id = empresa.id
        sucursal.nombre = nombre
        sucursal.codigo = codigo if codigo else None
        sucursal.telefono = telefono if telefono else None
        sucursal.direccion = direccion if direccion else None
        sucursal.updated_at = datetime.utcnow()

        db.session.commit()

        flash(
            f"Sucursal '{sucursal.nombre}' actualizada correctamente.",
            "success"
        )

        return redirect(url_for("sucursales"))

    return render_template(
        "editar_sucursal.html",
        sucursal=sucursal,
        empresas_disponibles=empresas_disponibles
    )


# ============================================================
# DESACTIVAR SUCURSAL
# ============================================================

@app.route("/sucursales/<int:sucursal_id>/desactivar", methods=["POST"])
@requiere_permiso("SUCURSAL_ELIMINAR")
def desactivar_sucursal(sucursal_id):

    sucursal = Sucursal.query.get_or_404(sucursal_id)

    sucursal.activo = False
    sucursal.updated_at = datetime.utcnow()

    db.session.commit()

    flash(
        f"Sucursal '{sucursal.nombre}' desactivada correctamente.",
        "success"
    )

    return redirect(url_for("sucursales"))


# ============================================================
# ACTIVAR SUCURSAL
# ============================================================

@app.route("/sucursales/<int:sucursal_id>/activar", methods=["POST"])
@requiere_permiso("SUCURSAL_ELIMINAR")
def activar_sucursal(sucursal_id):

    sucursal = Sucursal.query.get_or_404(sucursal_id)

    sucursal.activo = True
    sucursal.updated_at = datetime.utcnow()

    db.session.commit()

    flash(
        f"Sucursal '{sucursal.nombre}' activada correctamente.",
        "success"
    )

    return redirect(url_for("sucursales"))

# ============================================================
# AREAS
# ============================================================

@app.route("/areas")
@requiere_permiso("AREA_VER")
def areas():

    areas = (
        db.session.query(Area, Sucursal, Empresa)
        .join(Sucursal, Area.sucursal_id == Sucursal.id)
        .join(Empresa, Sucursal.empresa_id == Empresa.id)
        .order_by(Area.nombre.asc())
        .all()
    )

    return render_template(
        "areas.html",
        areas=areas
    )


# ============================================================
# NUEVA AREA
# ============================================================

@app.route("/areas/nueva", methods=["GET", "POST"])
@requiere_permiso("AREA_CREAR")
def nueva_area():

    sucursales_disponibles = (
        db.session.query(Sucursal, Empresa)
        .join(Empresa, Sucursal.empresa_id == Empresa.id)
        .filter(Sucursal.activo == True)
        .order_by(Sucursal.nombre.asc())
        .all()
    )

    if request.method == "POST":

        sucursal_id = request.form.get("sucursal_id", "").strip()
        nombre = request.form.get("nombre", "").strip()
        descripcion = request.form.get("descripcion", "").strip()

        if not nombre:
            flash(
                "El nombre del área es obligatorio.",
                "error"
            )
            return render_template(
                "nueva_area.html",
                sucursales_disponibles=sucursales_disponibles
            )

        if not sucursal_id:
            flash(
                "Debe seleccionar una sucursal.",
                "error"
            )
            return render_template(
                "nueva_area.html",
                sucursales_disponibles=sucursales_disponibles
            )

        sucursal = (
            Sucursal.query
            .filter_by(id=int(sucursal_id), activo=True)
            .first()
        )

        if not sucursal:
            flash(
                "La sucursal seleccionada no es válida.",
                "error"
            )
            return render_template(
                "nueva_area.html",
                sucursales_disponibles=sucursales_disponibles
            )

        ahora = datetime.utcnow()

        nueva = Area(
            sucursal_id=sucursal.id,
            nombre=nombre,
            descripcion=descripcion if descripcion else None,
            activo=True,
            created_at=ahora,
            updated_at=ahora
        )

        db.session.add(nueva)
        db.session.commit()

        flash(
            f"Área '{nueva.nombre}' creada correctamente.",
            "success"
        )

        return redirect(url_for("areas"))

    return render_template(
        "nueva_area.html",
        sucursales_disponibles=sucursales_disponibles
    )


# ============================================================
# EDITAR AREA
# ============================================================

@app.route("/areas/<int:area_id>/editar", methods=["GET", "POST"])
@requiere_permiso("AREA_EDITAR")
def editar_area(area_id):

    area = Area.query.get_or_404(area_id)

    sucursales_disponibles = (
        db.session.query(Sucursal, Empresa)
        .join(Empresa, Sucursal.empresa_id == Empresa.id)
        .filter(Sucursal.activo == True)
        .order_by(Sucursal.nombre.asc())
        .all()
    )

    if request.method == "POST":

        sucursal_id = request.form.get("sucursal_id", "").strip()
        nombre = request.form.get("nombre", "").strip()
        descripcion = request.form.get("descripcion", "").strip()

        if not nombre:
            flash(
                "El nombre del área es obligatorio.",
                "error"
            )
            return render_template(
                "editar_area.html",
                area=area,
                sucursales_disponibles=sucursales_disponibles
            )

        if not sucursal_id:
            flash(
                "Debe seleccionar una sucursal.",
                "error"
            )
            return render_template(
                "editar_area.html",
                area=area,
                sucursales_disponibles=sucursales_disponibles
            )

        sucursal = (
            Sucursal.query
            .filter_by(id=int(sucursal_id), activo=True)
            .first()
        )

        if not sucursal:
            flash(
                "La sucursal seleccionada no es válida.",
                "error"
            )
            return render_template(
                "editar_area.html",
                area=area,
                sucursales_disponibles=sucursales_disponibles
            )

        area.sucursal_id = sucursal.id
        area.nombre = nombre
        area.descripcion = descripcion if descripcion else None
        area.updated_at = datetime.utcnow()

        db.session.commit()

        flash(
            f"Área '{area.nombre}' actualizada correctamente.",
            "success"
        )

        return redirect(url_for("areas"))

    return render_template(
        "editar_area.html",
        area=area,
        sucursales_disponibles=sucursales_disponibles
    )


# ============================================================
# DESACTIVAR AREA
# ============================================================

@app.route("/areas/<int:area_id>/desactivar", methods=["POST"])
@requiere_permiso("AREA_ELIMINAR")
def desactivar_area(area_id):

    area = Area.query.get_or_404(area_id)

    area.activo = False
    area.updated_at = datetime.utcnow()

    db.session.commit()

    flash(
        f"Área '{area.nombre}' desactivada correctamente.",
        "success"
    )

    return redirect(url_for("areas"))


# ============================================================
# ACTIVAR AREA
# ============================================================

@app.route("/areas/<int:area_id>/activar", methods=["POST"])
@requiere_permiso("AREA_ELIMINAR")
def activar_area(area_id):

    area = Area.query.get_or_404(area_id)

    area.activo = True
    area.updated_at = datetime.utcnow()

    db.session.commit()

    flash(
        f"Área '{area.nombre}' activada correctamente.",
        "success"
    )

    return redirect(url_for("areas"))

# ============================================================
# CARGOS
# ============================================================

@app.route("/cargos")
@requiere_permiso("CARGO_VER")
def cargos():

    cargos = (
        Cargo.query
        .order_by(Cargo.nombre.asc())
        .all()
    )

    return render_template(
        "cargos.html",
        cargos=cargos
    )


# ============================================================
# NUEVO CARGO
# ============================================================

@app.route("/cargos/nuevo", methods=["GET", "POST"])
@requiere_permiso("CARGO_CREAR")
def nuevo_cargo():

    if request.method == "POST":

        nombre = request.form.get("nombre", "").strip()
        descripcion = request.form.get("descripcion", "").strip()

        if not nombre:
            flash(
                "El nombre del cargo es obligatorio.",
                "error"
            )
            return render_template("nuevo_cargo.html")

        ahora = datetime.utcnow()

        nuevo = Cargo(
            nombre=nombre,
            descripcion=descripcion if descripcion else None,
            activo=True,
            created_at=ahora,
            updated_at=ahora
        )

        db.session.add(nuevo)
        db.session.commit()

        flash(
            f"Cargo '{nuevo.nombre}' creado correctamente.",
            "success"
        )

        return redirect(url_for("cargos"))

    return render_template("nuevo_cargo.html")


# ============================================================
# EDITAR CARGO
# ============================================================

@app.route("/cargos/<int:cargo_id>/editar", methods=["GET", "POST"])
@requiere_permiso("CARGO_EDITAR")
def editar_cargo(cargo_id):

    cargo = Cargo.query.get_or_404(cargo_id)

    if request.method == "POST":

        nombre = request.form.get("nombre", "").strip()
        descripcion = request.form.get("descripcion", "").strip()

        if not nombre:
            flash(
                "El nombre del cargo es obligatorio.",
                "error"
            )
            return render_template(
                "editar_cargo.html",
                cargo=cargo
            )

        cargo.nombre = nombre
        cargo.descripcion = descripcion if descripcion else None
        cargo.updated_at = datetime.utcnow()

        db.session.commit()

        flash(
            f"Cargo '{cargo.nombre}' actualizado correctamente.",
            "success"
        )

        return redirect(url_for("cargos"))

    return render_template(
        "editar_cargo.html",
        cargo=cargo
    )


# ============================================================
# DESACTIVAR CARGO
# ============================================================

@app.route("/cargos/<int:cargo_id>/desactivar", methods=["POST"])
@requiere_permiso("CARGO_ELIMINAR")
def desactivar_cargo(cargo_id):

    cargo = Cargo.query.get_or_404(cargo_id)

    cargo.activo = False
    cargo.updated_at = datetime.utcnow()

    db.session.commit()

    flash(
        f"Cargo '{cargo.nombre}' desactivado correctamente.",
        "success"
    )

    return redirect(url_for("cargos"))


# ============================================================
# ACTIVAR CARGO
# ============================================================

@app.route("/cargos/<int:cargo_id>/activar", methods=["POST"])
@requiere_permiso("CARGO_ELIMINAR")
def activar_cargo(cargo_id):

    cargo = Cargo.query.get_or_404(cargo_id)

    cargo.activo = True
    cargo.updated_at = datetime.utcnow()

    db.session.commit()

    flash(
        f"Cargo '{cargo.nombre}' activado correctamente.",
        "success"
    )

    return redirect(url_for("cargos"))

# ============================================================
# EJECUCIÓN
# ============================================================

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
