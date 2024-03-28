from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, EmailField
from wtforms.validators import DataRequired, Length
from flask_sqlalchemy import SQLAlchemy
from flask_login import login_user, LoginManager, login_required, current_user, logout_user, UserMixin
from datetime import datetime
import bcrypt
import hashlib
import qrcode
from io import BytesIO
import time
from datetime import datetime

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
    'class': 'sqlite:///classModel.db',
    'attendance': 'sqlite:///attendance.db'
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

class Attendance(db.Model):
    __bind_key__ = 'attendance'
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, nullable=False)
    class_id = db.Column(db.Integer, nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.now)
    status = db.Column(db.String(10), nullable=False)

    def __repr__(self):
        return f"<Attendance(student_id={self.student_id}, class_id={self.class_id}, date={self.date}, status={self.status})>"

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

        # Flash message indicating success
        flash('Class added successfully!', 'success')

        # Redirect to the class details page
        return redirect(url_for('class_details'))

    # Flash message indicating failure
    flash('Failed to add class!', 'danger')

    # Redirect to the class details page
    return redirect(url_for('class_details'))


from flask_login import login_required, current_user

@app.route('/mark_attendance', methods=['POST'])
@login_required
def mark_attendance():
    qr_code_data = request.json.get('qrCodeData')
    if qr_code_data:
        if is_valid_qr_code_data(qr_code_data):
            class_id = get_class_id_from_qr_data(qr_code_data)
            if class_id:
                email = current_user.email
                student = Register.query.filter_by(email=email).first()
                if student:
                    student_id = student.id
                    date = datetime.now()
                    status = 'Present'

                    # Create a new attendance record
                    new_attendance = Attendance(student_id=student_id, class_id=class_id, date=date, status=status)
                    db.session.add(new_attendance)
                    db.session.commit()
                    
                    return jsonify({'success': True, 'message': 'Attendance marked successfully'})
                else:
                    return jsonify({'success': False, 'message': 'Student not found'})
            else:
                return jsonify({'success': False, 'message': 'Failed to extract class ID from QR code'})
        else:
            return jsonify({'success': False, 'message': 'Invalid QR code data'})
    else:
        return jsonify({'success': False, 'message': 'No QR code data received'})





def is_valid_qr_code_data(qr_code_data):
    # Implement logic to validate the scanned QR code data
    # Example: Check if the QR code data matches a valid class ID
    return True  # Replace this with your validation logic
def get_class_id_from_qr_data(qr_code_data):
    # Implement logic to extract the class ID from the QR code data
    # Example: Parse the QR code data and extract the class ID
    return 1  # Replace this with your logic to get the class ID


@app.route("/student_login", methods=["POST", "GET"])
def student_login():
    form = LoginForm()
    if request.method == "POST" and form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = Register.query.filter_by(email=email, password=password).first()
        if user:
            login_user(user)
            flash("Correct details!", "info")
            return redirect(url_for("student_dashboard"))
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

@app.route("/student_dashboard")
def student_dashboard():
    return render_template("student_dashboard.html")

@app.route("/staff_dashboard")
def staff_dashboard():
    # Query the database to fetch student data
    students = Register.query.all()
    return render_template("staff_dashboard.html", students=students)

@app.route('/generate_qr_code')
def generate_qr_code():
    # Generate dynamic data (e.g., timestamp)
    dynamic_data = str(time.time())

    # Generate QR code based on dynamic data
    qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
    qr.add_data(dynamic_data)
    qr.make(fit=True)

    # Create a temporary file to store the QR code image
    temp_file = f'temp_qr_code.png'
    qr_img = qr.make_image(fill_color="black", back_color="white")
    qr_img.save(temp_file)

    # Return the QR code image file
    return send_file(temp_file, mimetype='image/png')

if __name__ == "__main__":
    app.run(debug=True)
