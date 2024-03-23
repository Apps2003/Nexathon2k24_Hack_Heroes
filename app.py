from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, EmailField, StringField
from wtforms.validators import DataRequired, Length
from flask_sqlalchemy import SQLAlchemy
from flask_login import login_user, LoginManager, login_required, current_user, logout_user, UserMixin
from datetime import datetime
import bcrypt
import hashlib

app = Flask(__name__)
app.config['SECRET_KEY'] = "my-secrets"

# Define the predefined staff username and password
STAFF_USERNAME = "staff"
STAFF_PASSWORD = "staff"

# Database Configuration
db = SQLAlchemy()
app.config['SECRET_KEY'] = "my-secrets"

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///student.db"
app.config['SQLALCHEMY_BINDS'] = {
    'class': 'sqlite:///class.db'
}
db = SQLAlchemy(app)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

class Class(db.Model):
    __bind_key__ = 'class'
    id = db.Column(db.Integer, primary_key=True)
    className = db.Column(db.String(100), nullable=False)
    classTeacher = db.Column(db.String(100), nullable=False)



login_manager = LoginManager()
login_manager.login_view = "student_login"
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



class Register(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(50), unique=True, nullable=False)
    student_name = db.Column(db.String(50), nullable=False)
    class_name = db.Column(db.String(50), nullable=False)
    rollno = db.Column(db.String(4), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)

    def is_active(self):
        return True

    def get_id(self):
        return str(self.id)

    def is_authenticated(self):
        return True
    
    def set_password(self, password):
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8')) 

with app.app_context():
    db.create_all()


class RegistrationForm(FlaskForm):
    email = EmailField(label='Email', validators=[DataRequired()])
    student_name = StringField(label="Student Name", validators=[DataRequired()])
    class_name = StringField(label="Class", validators=[DataRequired()])
    rollno = StringField(label="Roll No", validators=[DataRequired(), Length(min=1, max=4)])
    password = PasswordField(label="Password", validators=[DataRequired(), Length(min=8, max=20)])


class LoginForm(FlaskForm):
    email = EmailField(label='Email', validators=[DataRequired()])
    password = PasswordField(label="Password", validators=[DataRequired()])

class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    status = db.Column(db.String(10), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/")
def home():
    return redirect(url_for("dashboard"))

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

@app.route("/staff_login", methods=["POST", "GET"])    
def staff_login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if username == STAFF_USERNAME and password == STAFF_PASSWORD:
            # Staff login successful, redirect to staff dashboard
            flash("Login successful!", "success")
            return redirect(url_for("staff_dashboard"))
        else:
            flash("Invalid username or password!", "danger")
    return render_template("staff_login.html")


@app.route("/class")
def class_page():
    return render_template("class.html")

@app.route('/class_details')
def class_details():
    classes = Class.query.all()
    return render_template('class.html', classes=classes)



@app.route('/add_class', methods=['POST'])
def add_class():
    if request.method == 'POST':
        className = request.form['className']
        classTeacher = request.form['classTeacher']

        new_class = Class(className=className, classTeacher=classTeacher)
        db.session.add(new_class)
        db.session.commit()

        # Return JSON response with className and classTeacher
        return jsonify({'className': className, 'classTeacher': classTeacher})

        flash('Class added successfully!', 'success')

        return redirect(url_for('class_details'))

    flash('Failed to add class!', 'danger')
    return redirect(url_for('class_details'))

@app.route("/student_login", methods=["POST", "GET"])
def student_login():
    form = LoginForm()
    if request.method == "POST" and form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = Register.query.filter_by(email=email, password=password).first()
        if user:
            login_user(user)
            return redirect(url_for("dashboard"))
    flash("Please enter correct details!", "info")
    return render_template("student_login.html", form=form)


@app.route("/logout", methods=["GET"])
@login_required
def logout():
    logout_user()
    flash("You have been logged out successfully!", "info")
    return redirect(url_for("dashboard"))


@app.route("/student_register", methods=["POST", "GET"])
def student_register():
    form = RegistrationForm()
    if request.method == "POST" and form.validate_on_submit():
        new_user = Register(
            email=form.email.data,
            student_name=form.student_name.data,
            class_name=form.class_name.data,
            rollno=form.rollno.data,
            password=form.password.data
        )
        db.session.add(new_user)
        db.session.commit()
        flash("Account created Successfully! <br>You can now log in.", "success")
        return redirect(url_for("student_login"))

    return render_template("student_register.html", form=form)

@app.route("/staff_dashboard")
def staff_dashboard():
    # Query the database to fetch student data
    students = Register.query.all()
    return render_template("staff_dashboard.html", students=students)


if __name__ == "__main__":
    app.run(debug=True)
