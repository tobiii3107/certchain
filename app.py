import csv
import hashlib
import io
import json
import os
import uuid
import qrcode
from datetime import datetime


from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    send_from_directory,
    session,
    url_for,
)
from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError
from werkzeug.security import (
    check_password_hash,
    generate_password_hash,
)
from werkzeug.utils import secure_filename

from config import Config
from models import BlockchainRecord, Certificate, Student, User, db
from blockchain import create_blockchain_record, validate_blockchain


# ---------------------------------------------------------
# FLASK APPLICATION CONFIGURATION
# ---------------------------------------------------------

app = Flask(__name__)
app.config.from_object(Config)

# Certificate PDF files are stored in this folder.
app.config["CERTIFICATE_UPLOAD_FOLDER"] = os.path.join(
    app.root_path,
    "certificates",
)

# Maximum uploaded file size: 10 MB.
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

# Only PDF certificates are allowed.
ALLOWED_CERTIFICATE_EXTENSIONS = {"pdf"}

db.init_app(app)


# ---------------------------------------------------------
# CREATE DEFAULT LOGIN ACCOUNTS
# ---------------------------------------------------------

def create_default_users():
    default_users = [
        {
            "name": "College Administrator",
            "email": "admin@certchain.com",
            "password": "admin123",
            "role": "admin",
        },
        {
            "name": "Demo Student",
            "email": "student@certchain.com",
            "password": "student123",
            "role": "student",
        },
        {
            "name": "Certificate Verifier",
            "email": "verifier@certchain.com",
            "password": "verifier123",
            "role": "verifier",
        },
    ]

    try:
        for user_data in default_users:
            existing_user = User.query.filter_by(
                email=user_data["email"]
            ).first()

            if existing_user is None:
                new_user = User(
                    name=user_data["name"],
                    email=user_data["email"],
                    password=generate_password_hash(
                        user_data["password"]
                    ),
                    role=user_data["role"],
                )

                db.session.add(new_user)

        db.session.commit()

    except Exception as error:
        db.session.rollback()

        print(
            f"Default user creation error: {error}"
        )


# ---------------------------------------------------------
# ROLE CHECKING FUNCTIONS
# ---------------------------------------------------------

def admin_required():
    return (
        session.get("user_id") is not None
        and session.get("user_role") == "admin"
    )


def student_required():
    return (
        session.get("user_id") is not None
        and session.get("user_role") == "student"
    )


def verifier_required():
    return (
        session.get("user_id") is not None
        and session.get("user_role") == "verifier"
    )


# ---------------------------------------------------------
# CERTIFICATE HELPER FUNCTIONS
# ---------------------------------------------------------

def allowed_certificate_file(filename):
    """
    Check whether the uploaded file has a permitted extension.
    Currently, CertChain accepts PDF files only.
    """

    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower()
        in ALLOWED_CERTIFICATE_EXTENSIONS
    )


def calculate_file_hash(file_path):
    """
    Generate a SHA-256 hash from the complete certificate file.
    Even a very small change in the PDF produces a different hash.
    """

    sha256_hash = hashlib.sha256()

    with open(file_path, "rb") as certificate_file:
        for file_block in iter(
            lambda: certificate_file.read(65536),
            b"",
        ):
            sha256_hash.update(file_block)

    return sha256_hash.hexdigest()


def generate_unique_file_name(original_filename):
    """
    Create a safe and unique filename so that two uploaded
    certificates never overwrite each other.
    """

    safe_filename = secure_filename(original_filename)

    extension = safe_filename.rsplit(
        ".",
        1,
    )[1].lower()

    unique_value = uuid.uuid4().hex

    return f"{unique_value}.{extension}"


def remove_certificate_file(file_name):
    """
    Remove a certificate file if a database save operation fails.
    """

    if not file_name:
        return

    file_path = os.path.join(
        app.config["CERTIFICATE_UPLOAD_FOLDER"],
        file_name,
    )

    if os.path.isfile(file_path):
        try:
            os.remove(file_path)

        except OSError as error:
            print(
                f"Unable to remove certificate file: {error}"
            )


# ---------------------------------------------------------
# ACTIVITY LOG HELPERS
# ---------------------------------------------------------

ACTIVITY_LOG_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "reports",
    "activity_logs.json",
)


def write_activity_log(action, details=""):
    """Persist a small audit trail in reports/activity_logs.json."""
    try:
        os.makedirs(os.path.dirname(ACTIVITY_LOG_FILE), exist_ok=True)

        try:
            with open(ACTIVITY_LOG_FILE, "r", encoding="utf-8") as log_file:
                logs = json.load(log_file)
                if not isinstance(logs, list):
                    logs = []
        except (FileNotFoundError, json.JSONDecodeError):
            logs = []

        logs.append({
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "user": session.get("user_name", "Guest"),
            "email": session.get("user_email", "-"),
            "role": session.get("user_role", "-"),
            "action": action,
            "details": details,
        })

        # Keep the most recent 1000 events.
        logs = logs[-1000:]

        with open(ACTIVITY_LOG_FILE, "w", encoding="utf-8") as log_file:
            json.dump(logs, log_file, indent=2)
    except Exception as error:
        print(f"Activity log error: {error}")


def read_activity_logs():
    try:
        with open(ACTIVITY_LOG_FILE, "r", encoding="utf-8") as log_file:
            logs = json.load(log_file)
            return logs if isinstance(logs, list) else []
    except (FileNotFoundError, json.JSONDecodeError):
        return []
    except Exception as error:
        print(f"Activity log read error: {error}")
        return []


# ---------------------------------------------------------
# BLOCKCHAIN SYNC HELPER
# ---------------------------------------------------------

def sync_existing_certificates_to_blockchain():
    """
    Add blockchain records for certificates that were created
    before the blockchain_records table/feature was introduced.
    Existing blockchain records are never duplicated.
    """

    certificates = Certificate.query.order_by(
        Certificate.id.asc()
    ).all()

    created_count = 0

    try:
        for certificate in certificates:
            existing_record = BlockchainRecord.query.filter_by(
                certificate_id=certificate.id
            ).first()

            if existing_record is None:
                create_blockchain_record(certificate)
                db.session.flush()
                created_count += 1

        db.session.commit()

        if created_count:
            print(
                f"Blockchain sync complete: "
                f"{created_count} certificate(s) added."
            )

    except Exception as error:
        db.session.rollback()
        print(f"Blockchain sync error: {error}")


# ---------------------------------------------------------
# HOME PAGE
# ---------------------------------------------------------

@app.route("/")
def home():
    return render_template("index.html")


# ---------------------------------------------------------
# LOGIN
# ---------------------------------------------------------

@app.route(
    "/login/<role>",
    methods=["GET", "POST"],
)
def login(role):
    allowed_roles = [
        "admin",
        "student",
        "verifier",
    ]

    if role not in allowed_roles:
        flash(
            "Invalid login role selected.",
            "danger",
        )

        return redirect(
            url_for("home")
        )

    if request.method == "POST":
        email = request.form.get(
            "email",
            "",
        ).strip().lower()

        password = request.form.get(
            "password",
            "",
        ).strip()

        if not email or not password:
            flash(
                "Please enter email and password.",
                "danger",
            )

            return render_template(
                "login.html",
                role=role,
            )

        user = User.query.filter_by(
            email=email,
            role=role,
        ).first()

        if user and check_password_hash(
            user.password,
            password,
        ):
            if user.role == "student":
                student = Student.query.filter_by(
                    email=user.email
                ).first()

                if student is None:
                    flash(
                        "Student profile was not found. "
                        "Please contact the administrator.",
                        "danger",
                    )

                    return render_template(
                        "login.html",
                        role=role,
                    )

                if student.status == "Inactive":
                    flash(
                        "Your student account is inactive. "
                        "Please contact the administrator.",
                        "danger",
                    )

                    return render_template(
                        "login.html",
                        role=role,
                    )

            session.clear()

            session["user_id"] = user.id
            session["user_name"] = user.name
            session["user_email"] = user.email
            session["user_role"] = user.role

            flash(
                f"Welcome, {user.name}!",
                "success",
            )

            write_activity_log(
                "Login",
                f"{user.role.title()} login successful",
            )

            if user.role == "admin":
                return redirect(
                    url_for("admin_dashboard")
                )

            if user.role == "student":
                return redirect(
                    url_for("student_dashboard")
                )

            return redirect(
                url_for("verifier_dashboard")
            )

        flash(
            "Invalid email, password or selected role.",
            "danger",
        )

    return render_template(
        "login.html",
        role=role,
    )


# ---------------------------------------------------------
# ADMIN DASHBOARD
# ---------------------------------------------------------

@app.route("/admin/dashboard")
def admin_dashboard():
    if not admin_required():
        flash(
            "Please login as Admin to continue.",
            "danger",
        )

        return redirect(
            url_for(
                "login",
                role="admin",
            )
        )

    total_students = Student.query.count()

    active_students = Student.query.filter_by(
        status="Active"
    ).count()

    inactive_students = Student.query.filter_by(
        status="Inactive"
    ).count()

    total_certificates = Certificate.query.count()

    recent_students = Student.query.order_by(
        Student.created_at.desc()
    ).limit(5).all()

    recent_certificates = Certificate.query.order_by(
        Certificate.created_at.desc()
    ).limit(5).all()

    total_blockchain_records = BlockchainRecord.query.count()
    activity_logs = read_activity_logs()
    total_verifications = sum(
        1 for item in activity_logs
        if "Verification" in str(item.get("action", ""))
    )
    recent_activity = list(reversed(activity_logs[-8:]))

    return render_template(
        "admin/dashboard.html",
        user_name=session.get("user_name"),
        total_students=total_students,
        active_students=active_students,
        inactive_students=inactive_students,
        total_certificates=total_certificates,
        total_blockchain_records=total_blockchain_records,
        total_verifications=total_verifications,
        recent_students=recent_students,
        recent_certificates=recent_certificates,
        recent_activity=recent_activity,
    )
    # ---------------------------------------------------------
# REGISTER STUDENT
# ---------------------------------------------------------

@app.route(
    "/admin/students/register",
    methods=["GET", "POST"],
)
def register_student():
    if not admin_required():
        flash(
            "Please login as Admin to continue.",
            "danger",
        )

        return redirect(
            url_for(
                "login",
                role="admin",
            )
        )

    if request.method == "POST":
        student_id = request.form.get(
            "student_id",
            "",
        ).strip().upper()

        full_name = request.form.get(
            "full_name",
            "",
        ).strip()

        email = request.form.get(
            "email",
            "",
        ).strip().lower()

        phone = request.form.get(
            "phone",
            "",
        ).strip()

        course = request.form.get(
            "course",
            "",
        ).strip()

        department = request.form.get(
            "department",
            "",
        ).strip()

        academic_year = request.form.get(
            "academic_year",
            "",
        ).strip()

        password = request.form.get(
            "password",
            "",
        ).strip()

        form_data = {
            "student_id": student_id,
            "full_name": full_name,
            "email": email,
            "phone": phone,
            "course": course,
            "department": department,
            "academic_year": academic_year,
        }

        if not all(
            [
                student_id,
                full_name,
                email,
                phone,
                course,
                department,
                academic_year,
                password,
            ]
        ):
            flash(
                "Please fill all required fields.",
                "danger",
            )

            return render_template(
                "admin/register_student.html",
                form_data=form_data,
            )

        if "@" not in email or "." not in email:
            flash(
                "Please enter a valid email address.",
                "danger",
            )

            return render_template(
                "admin/register_student.html",
                form_data=form_data,
            )

        if not phone.isdigit():
            flash(
                "Phone number must contain only numbers.",
                "danger",
            )

            return render_template(
                "admin/register_student.html",
                form_data=form_data,
            )

        if len(phone) != 10:
            flash(
                "Phone number must contain exactly 10 digits.",
                "danger",
            )

            return render_template(
                "admin/register_student.html",
                form_data=form_data,
            )

        if len(password) < 6:
            flash(
                "Password must contain at least 6 characters.",
                "danger",
            )

            return render_template(
                "admin/register_student.html",
                form_data=form_data,
            )

        existing_student_id = Student.query.filter_by(
            student_id=student_id
        ).first()

        if existing_student_id:
            flash(
                "Student ID already exists.",
                "danger",
            )

            return render_template(
                "admin/register_student.html",
                form_data=form_data,
            )

        existing_student_email = Student.query.filter_by(
            email=email
        ).first()

        existing_user_email = User.query.filter_by(
            email=email
        ).first()

        if existing_student_email or existing_user_email:
            flash(
                "Email address already exists.",
                "danger",
            )

            return render_template(
                "admin/register_student.html",
                form_data=form_data,
            )

        new_student = Student(
            student_id=student_id,
            full_name=full_name,
            email=email,
            phone=phone,
            course=course,
            department=department,
            academic_year=academic_year,
            status="Active",
        )

        new_student_user = User(
            name=full_name,
            email=email,
            password=generate_password_hash(
                password
            ),
            role="student",
        )

        try:
            db.session.add(new_student)
            db.session.add(new_student_user)
            db.session.commit()

            write_activity_log(
                "Student Registration",
                f"Registered {full_name} ({student_id})",
            )

            flash(
                f"Student {full_name} registered successfully.",
                "success",
            )

            return redirect(
                url_for("view_students")
            )

        except IntegrityError:
            db.session.rollback()

            flash(
                "Student ID or email already exists.",
                "danger",
            )

        except Exception as error:
            db.session.rollback()

            print(
                f"Student registration error: {error}"
            )

            flash(
                "Student registration failed. "
                "Please try again.",
                "danger",
            )

        return render_template(
            "admin/register_student.html",
            form_data=form_data,
        )

    return render_template(
        "admin/register_student.html",
        form_data={},
    )


# ---------------------------------------------------------
# VIEW AND SEARCH STUDENTS
# ---------------------------------------------------------

@app.route("/admin/students")
def view_students():
    if not admin_required():
        flash(
            "Please login as Admin to continue.",
            "danger",
        )

        return redirect(
            url_for(
                "login",
                role="admin",
            )
        )

    search = request.args.get(
        "search",
        "",
    ).strip()

    if search:
        students = Student.query.filter(
            or_(
                Student.student_id.ilike(
                    f"%{search}%"
                ),
                Student.full_name.ilike(
                    f"%{search}%"
                ),
                Student.email.ilike(
                    f"%{search}%"
                ),
                Student.course.ilike(
                    f"%{search}%"
                ),
                Student.department.ilike(
                    f"%{search}%"
                ),
                Student.academic_year.ilike(
                    f"%{search}%"
                ),
                Student.status.ilike(
                    f"%{search}%"
                ),
            )
        ).order_by(
            Student.created_at.desc()
        ).all()

    else:
        students = Student.query.order_by(
            Student.created_at.desc()
        ).all()

    return render_template(
        "admin/students.html",
        students=students,
        search=search,
    )


# ---------------------------------------------------------
# CHANGE STUDENT STATUS
# ---------------------------------------------------------

@app.route(
    "/admin/students/<int:student_id>/status",
    methods=["POST"],
)
def change_student_status(student_id):
    if not admin_required():
        flash(
            "Please login as Admin to continue.",
            "danger",
        )

        return redirect(
            url_for(
                "login",
                role="admin",
            )
        )

    student = Student.query.get_or_404(
        student_id
    )

    if student.status == "Active":
        student.status = "Inactive"
        status_message = "deactivated"

    else:
        student.status = "Active"
        status_message = "activated"

    try:
        db.session.commit()

        write_activity_log(
            "Student Status",
            f"Student #{student.id} {status_message}",
        )

        flash(
            f"Student account {status_message} successfully.",
            "success",
        )

    except Exception as error:
        db.session.rollback()

        print(
            f"Student status update error: {error}"
        )

        flash(
            "Unable to update student status.",
            "danger",
        )

    return redirect(
        url_for("view_students")
    )


# ---------------------------------------------------------
# UPLOAD CERTIFICATE
# ---------------------------------------------------------

@app.route(
    "/admin/certificates/upload",
    methods=["GET", "POST"],
)
def upload_certificate():
    if not admin_required():
        flash(
            "Please login as Admin to continue.",
            "danger",
        )

        return redirect(
            url_for(
                "login",
                role="admin",
            )
        )

    students = Student.query.filter_by(
        status="Active"
    ).order_by(
        Student.full_name.asc()
    ).all()

    if request.method == "POST":
        student_database_id = request.form.get(
            "student_id",
            "",
        ).strip()

        certificate_name = request.form.get(
            "certificate_name",
            "",
        ).strip()

        certificate_type = request.form.get(
            "certificate_type",
            "",
        ).strip()

        issue_date = request.form.get(
            "issue_date",
            "",
        ).strip()

        certificate_file = request.files.get(
            "certificate_file"
        )

        form_data = {
            "student_id": student_database_id,
            "certificate_name": certificate_name,
            "certificate_type": certificate_type,
            "issue_date": issue_date,
        }

        if not all(
            [
                student_database_id,
                certificate_name,
                certificate_type,
                issue_date,
            ]
        ):
            flash(
                "Please fill all certificate details.",
                "danger",
            )

            return render_template(
                "admin/upload_certificate.html",
                students=students,
                form_data=form_data,
            )

        if (
            certificate_file is None
            or certificate_file.filename == ""
        ):
            flash(
                "Please select a certificate PDF file.",
                "danger",
            )

            return render_template(
                "admin/upload_certificate.html",
                students=students,
                form_data=form_data,
            )

        if not allowed_certificate_file(
            certificate_file.filename
        ):
            flash(
                "Only PDF certificate files are allowed.",
                "danger",
            )

            return render_template(
                "admin/upload_certificate.html",
                students=students,
                form_data=form_data,
            )

        try:
            student_database_id = int(
                student_database_id
            )

        except ValueError:
            flash(
                "Invalid student selected.",
                "danger",
            )

            return render_template(
                "admin/upload_certificate.html",
                students=students,
                form_data=form_data,
            )

        student = Student.query.filter_by(
            id=student_database_id,
            status="Active",
        ).first()

        if student is None:
            flash(
                "Selected student was not found "
                "or the account is inactive.",
                "danger",
            )

            return render_template(
                "admin/upload_certificate.html",
                students=students,
                form_data=form_data,
            )

        try:
            parsed_issue_date = datetime.strptime(
                issue_date,
                "%Y-%m-%d",
            )

        except ValueError:
            flash(
                "Please enter a valid issue date.",
                "danger",
            )

            return render_template(
                "admin/upload_certificate.html",
                students=students,
                form_data=form_data,
            )

        if parsed_issue_date.date() > datetime.now().date():
            flash(
                "Issue date cannot be in the future.",
                "danger",
            )

            return render_template(
                "admin/upload_certificate.html",
                students=students,
                form_data=form_data,
            )

        unique_file_name = generate_unique_file_name(
            certificate_file.filename
        )

        file_path = os.path.join(
            app.config["CERTIFICATE_UPLOAD_FOLDER"],
            unique_file_name,
        )

        try:
            os.makedirs(
                app.config["CERTIFICATE_UPLOAD_FOLDER"],
                exist_ok=True,
            )

            certificate_file.save(file_path)

            blockchain_hash = calculate_file_hash(
                file_path
            )

            existing_certificate = Certificate.query.filter_by(
                blockchain_hash=blockchain_hash
            ).first()

            if existing_certificate:
                remove_certificate_file(
                    unique_file_name
                )

                flash(
                    "This exact certificate file "
                    "has already been uploaded.",
                    "danger",
                )

                return render_template(
                    "admin/upload_certificate.html",
                    students=students,
                    form_data=form_data,
                )

            new_certificate = Certificate(
                student_id=student.id,
                certificate_name=certificate_name,
                certificate_type=certificate_type,
                issue_date=issue_date,
                file_name=unique_file_name,
                blockchain_hash=blockchain_hash,
                status="Verified",
            )

            db.session.add(new_certificate)

            # Assign the certificate database ID before creating
            # the linked blockchain record.
            db.session.flush()

            # Store this certificate inside the tamper-evident
            # blockchain-style hash chain.
            create_blockchain_record(new_certificate)

            db.session.commit()

            write_activity_log(
                "Certificate Issued",
                f"{certificate_name} issued to {student.full_name}",
            )

            flash(
                f"Certificate issued successfully to "
                f"{student.full_name}.",
                "success",
            )

            return redirect(
                url_for("view_certificates")
            )

        except IntegrityError:
            db.session.rollback()

            remove_certificate_file(
                unique_file_name
            )

            flash(
                "This certificate already exists.",
                "danger",
            )

        except Exception as error:
            db.session.rollback()

            remove_certificate_file(
                unique_file_name
            )

            print(
                f"Certificate upload error: {error}"
            )

            flash(
                "Certificate upload failed. "
                "Please try again.",
                "danger",
            )

        return render_template(
            "admin/upload_certificate.html",
            students=students,
            form_data=form_data,
        )

    return render_template(
        "admin/upload_certificate.html",
        students=students,
        form_data={},
    )


# ---------------------------------------------------------
# VIEW AND SEARCH CERTIFICATES
# ---------------------------------------------------------

@app.route("/admin/certificates")
def view_certificates():
    if not admin_required():
        flash(
            "Please login as Admin to continue.",
            "danger",
        )

        return redirect(
            url_for(
                "login",
                role="admin",
            )
        )

    search = request.args.get(
        "search",
        "",
    ).strip()

    query = Certificate.query.join(
        Student,
        Certificate.student_id == Student.id,
    )

    if search:
        query = query.filter(
            or_(
                Certificate.certificate_name.ilike(
                    f"%{search}%"
                ),
                Certificate.certificate_type.ilike(
                    f"%{search}%"
                ),
                Certificate.blockchain_hash.ilike(
                    f"%{search}%"
                ),
                Certificate.status.ilike(
                    f"%{search}%"
                ),
                Student.student_id.ilike(
                    f"%{search}%"
                ),
                Student.full_name.ilike(
                    f"%{search}%"
                ),
                Student.email.ilike(
                    f"%{search}%"
                ),
            )
        )

    certificates = query.order_by(
        Certificate.created_at.desc()
    ).all()

    return render_template(
        "admin/certificates.html",
        certificates=certificates,
        search=search,
    )
# =========================================================
# DELETE CERTIFICATE
# =========================================================

import os

@app.route("/admin/certificate/delete/<int:certificate_id>")
def delete_certificate(certificate_id):

    if not admin_required():
        abort(403)

    certificate = Certificate.query.get_or_404(certificate_id)

    # Delete PDF file
    try:
        file_path = os.path.join("certificates", certificate.file_name)

        if os.path.exists(file_path):
            os.remove(file_path)

    except Exception as e:
        print("File delete error:", e)

    # Delete blockchain record
    blockchain = BlockchainRecord.query.filter_by(
        certificate_hash=certificate.blockchain_hash
    ).first()

    if blockchain:
        db.session.delete(blockchain)

    student_name = certificate.student.full_name

    db.session.delete(certificate)
    db.session.commit()

    write_activity_log(
        "Certificate Deleted",
        f"{student_name}'s certificate deleted by admin."
    )

    flash("Certificate deleted successfully.", "success")

    return redirect(url_for("view_certificates"))
# DOWNLOAD CERTIFICATE
# ---------------------------------------------------------

@app.route(
    "/certificates/download/<int:certificate_id>"
)
def download_certificate(certificate_id):
    user_role = session.get("user_role")

    if user_role not in {
        "admin",
        "student",
        "verifier",
    }:
        flash(
            "Please login to download the certificate.",
            "danger",
        )

        return redirect(
            url_for("home")
        )

    certificate = Certificate.query.get_or_404(
        certificate_id
    )

    if user_role == "student":
        student = Student.query.filter_by(
            email=session.get("user_email")
        ).first()

        if (
            student is None
            or certificate.student_id != student.id
        ):
            abort(403)

    file_path = os.path.join(
        app.config["CERTIFICATE_UPLOAD_FOLDER"],
        certificate.file_name,
    )

    if not os.path.isfile(file_path):
        flash(
            "Certificate file was not found.",
            "danger",
        )

        if user_role == "admin":
            return redirect(
                url_for("view_certificates")
            )

        return redirect(
            url_for("student_dashboard")
        )

    download_name = (
        f"{certificate.certificate_name}"
        f"_{certificate.student.student_id}.pdf"
    )

    write_activity_log(
        "Certificate Download",
        f"Downloaded certificate #{certificate.id}",
    )

    return send_from_directory(
        app.config["CERTIFICATE_UPLOAD_FOLDER"],
        certificate.file_name,
        as_attachment=True,
        download_name=download_name,
    )


 # ---------------------------------------------------------
# VERIFY CERTIFICATE USING HASH OR PDF
# ---------------------------------------------------------

@app.route(
    "/verify",
    methods=["GET", "POST"],
)
def verify_certificate():

    verification_result = None
    certificate = None
    submitted_hash = ""


    # -----------------------------------------------------
    # GET REQUEST
    # -----------------------------------------------------
    # Dashboard Verify button / QR can send:
    # /verify?hash=<certificate_sha256>
    # -----------------------------------------------------

    if request.method == "GET":

        submitted_hash = request.args.get(
            "hash",
            "",
        ).strip().lower()

        if submitted_hash:

            certificate = Certificate.query.filter_by(
                blockchain_hash=submitted_hash
            ).first()

            if certificate:

                verification_result = True

                write_activity_log(
                    "Certificate Verification",
                    "Valid certificate hash",
                )

            else:

                verification_result = False

                write_activity_log(
                    "Certificate Verification",
                    "Invalid certificate hash",
                )

    # -----------------------------------------------------
    # POST REQUEST
    # -----------------------------------------------------

    elif request.method == "POST":

        submitted_hash = request.form.get(
            "blockchain_hash",
            "",
        ).strip().lower()

        uploaded_file = request.files.get(
            "certificate_file"
        )

        # -------------------------------------------------
        # OPTION 1: VERIFY USING HASH
        # -------------------------------------------------

        if submitted_hash:

            certificate = Certificate.query.filter_by(
                blockchain_hash=submitted_hash
            ).first()

            if certificate:

                verification_result = True

                write_activity_log(
                    "Certificate Verification",
                    "Valid certificate hash",
                )

            else:

                verification_result = False

                write_activity_log(
                    "Certificate Verification",
                    "Invalid certificate hash",
                )

        # -------------------------------------------------
        # OPTION 2: VERIFY USING PDF
        # -------------------------------------------------

        elif (
            uploaded_file is not None
            and uploaded_file.filename != ""
        ):

            # ---------------------------------------------
            # Check PDF extension
            # ---------------------------------------------

            if not allowed_certificate_file(
                uploaded_file.filename
            ):

                flash(
                    "Only PDF certificate files are allowed.",
                    "danger",
                )

                return render_template(
                    "verify_certificate.html",
                    verification_result=None,
                    certificate=None,
                    submitted_hash="",
                )

            temporary_file_name = (
                f"verify_{uuid.uuid4().hex}.pdf"
            )

            temporary_file_path = os.path.join(
                app.config[
                    "CERTIFICATE_UPLOAD_FOLDER"
                ],
                temporary_file_name,
            )

            try:

                # -----------------------------------------
                # Make upload directory
                # -----------------------------------------

                os.makedirs(
                    app.config[
                        "CERTIFICATE_UPLOAD_FOLDER"
                    ],
                    exist_ok=True,
                )

                # -----------------------------------------
                # Save temporary PDF
                # -----------------------------------------

                uploaded_file.save(
                    temporary_file_path
                )

                # -----------------------------------------
                # Calculate SHA-256
                # -----------------------------------------

                submitted_hash = calculate_file_hash(
                    temporary_file_path
                ).strip().lower()

                print(
                    "Submitted PDF SHA-256:",
                    submitted_hash,
                )

                # -----------------------------------------
                # Compare with registered certificate hash
                # -----------------------------------------

                certificate = Certificate.query.filter_by(
                    blockchain_hash=submitted_hash
                ).first()

                if certificate:

                    verification_result = True

                    write_activity_log(
                        "Certificate Verification",
                        "Valid original certificate",
                    )

                else:

                    verification_result = False

                    write_activity_log(
                        "Certificate Verification",
                        "Tampered or invalid certificate",
                    )

            except Exception as error:

                print(
                    f"Certificate verification error: {error}"
                )

                verification_result = False
                certificate = None

                flash(
                    "Unable to verify the certificate.",
                    "danger",
                )

            finally:

                # -----------------------------------------
                # Delete temporary verification file
                # -----------------------------------------

                remove_certificate_file(
                    temporary_file_name
                )

        # -------------------------------------------------
        # NOTHING PROVIDED
        # -------------------------------------------------

        else:

            flash(
                "Enter a certificate hash or upload a PDF file.",
                "danger",
            )

            return render_template(
                "verify_certificate.html",
                verification_result=None,
                certificate=None,
                submitted_hash="",
            )

    # -----------------------------------------------------
    # RETURN VERIFICATION PAGE
    # -----------------------------------------------------

    return render_template(
        "verify_certificate.html",
        verification_result=verification_result,
        certificate=certificate,
        submitted_hash=submitted_hash,
    )
@app.route("/verification_history")
def verification_history():

    if not verifier_required():
        return redirect(url_for("verifier_login"))

    return render_template("verifier/verification_history.html")
# ---------------------------------------------------------
# QR VERIFICATION
# ---------------------------------------------------------

@app.route("/admin/qr-verification")
def qr_verification():
    if not admin_required():
        flash("Please login as Admin to continue.", "danger")
        return redirect(url_for("login", role="admin"))

    certificates = Certificate.query.join(
        Student, Certificate.student_id == Student.id
    ).order_by(Certificate.created_at.desc()).all()

    rows = ""
    for certificate in certificates:
        verify_url = url_for(
            "verify_certificate",
            hash=certificate.blockchain_hash,
            _external=True,
        )
        qr_url = url_for(
            "certificate_qr",
            certificate_id=certificate.id,
        )
        rows += f"""
        <tr>
          <td>{certificate.student.full_name}</td>
          <td>{certificate.student.student_id}</td>
          <td>{certificate.certificate_name}</td>
          <td><img src="{qr_url}" width="150" height="150" alt="Certificate QR"></td>
          <td>
            <a class="btn verify" href="{verify_url}" target="_blank">Verify</a>
            <a class="btn" href="{qr_url}" target="_blank">Open QR</a>
          </td>
        </tr>
        """

    if not rows:
        rows = "<tr><td colspan='5'>No certificates available. Issue a certificate first.</td></tr>"

    write_activity_log("QR Verification Page", "Admin opened QR verification page")

    return f"""
    <!doctype html>
    <html>
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width,initial-scale=1">
      <title>QR Verification - CertChain</title>
      <style>
        body{{margin:0;font-family:Segoe UI,Arial;background:linear-gradient(135deg,#081b33,#102d54);color:white;padding:30px;}}
        .wrap{{max-width:1200px;margin:auto;}}
        .box{{background:#142b4d;border:1px solid #315070;border-radius:18px;padding:25px;overflow:auto;}}
        h1{{color:#38bdf8;}}
        p{{color:#dbeafe;}}
        table{{width:100%;border-collapse:collapse;background:#1d3557;min-width:900px;}}
        th,td{{padding:14px;border-bottom:1px solid #41617f;text-align:left;vertical-align:middle;}}
        th{{background:#1d4ed8;}}
        img{{background:white;padding:8px;border-radius:8px;}}
        .btn{{display:inline-block;margin:4px;padding:9px 13px;border-radius:8px;background:#2563eb;color:white;text-decoration:none;font-weight:bold;}}
        .verify{{background:#16a34a;}}
        .back{{display:inline-block;margin-top:20px;color:#7dd3fc;text-decoration:none;}}
      </style>
    </head>
    <body>
      <div class="wrap">
        <h1>QR Verification</h1>
        <p>Each certificate has a QR code that opens its public hash verification page.</p>
        <div class="box">
          <table>
            <thead><tr>
              <th>Student</th><th>Student ID</th><th>Certificate</th><th>QR Code</th><th>Actions</th>
            </tr></thead>
            <tbody>{rows}</tbody>
          </table>
        </div>
        <a class="back" href="{url_for('admin_dashboard')}">← Back to Dashboard</a>
      </div>
    </body>
    </html>
    """


@app.route("/admin/qr/<int:certificate_id>")
def certificate_qr(certificate_id):
    if not admin_required():
        return redirect(url_for("login", role="admin"))

    certificate = Certificate.query.get_or_404(certificate_id)
    verify_url = url_for(
        "verify_certificate",
        hash=certificate.blockchain_hash,
        _external=True,
    )

    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(verify_url)
    qr.make(fit=True)
    image = qr.make_image()

    output = io.BytesIO()
    image.save(output, format="PNG")
    output.seek(0)

    write_activity_log(
        "QR Code Generated",
        f"Generated QR for certificate #{certificate.id}",
    )

    return send_file(output, mimetype="image/png")


@app.route("/qr/verify/<int:certificate_id>")
def qr_verify_certificate(certificate_id):
    certificate = Certificate.query.get_or_404(certificate_id)
    write_activity_log(
        "QR Certificate Verification",
        f"QR opened for certificate #{certificate.id}",
    )
    return redirect(url_for("verify_certificate", hash=certificate.blockchain_hash))


# ---------------------------------------------------------
# BLOCKCHAIN RECORDS
# ---------------------------------------------------------
# ---------------------------------------------------------
# BLOCKCHAIN RECORDS
# ---------------------------------------------------------

@app.route("/admin/blockchain")
def blockchain_records():

    if not admin_required():
        flash(
            "Please login as Admin to continue.",
            "danger"
        )

        return redirect(
            url_for(
                "login",
                role="admin"
            )
        )

    certificates = Certificate.query.join(
        Student,
        Certificate.student_id == Student.id
    ).order_by(
        Certificate.created_at.desc()
    ).all()

    return render_template(
        "admin/blockchain_records.html",
        certificates=certificates
    )

# ---------------------------------------------------------
# ADMIN FEATURE ROUTES / ALIASES
# ---------------------------------------------------------

@app.route("/admin/verify-stored-hash", methods=["GET", "POST"])
def verify_stored_hash():
    """Admin page for checking a stored SHA-256 certificate hash."""
    if not admin_required():
        flash("Please login as Admin to continue.", "danger")
        return redirect(url_for("login", role="admin"))

    submitted_hash = ""
    certificate = None
    record = None
    verified = None

    if request.method == "POST":
        submitted_hash = request.form.get("blockchain_hash", "").strip().lower()
        if not submitted_hash:
            flash("Please enter a SHA-256 hash.", "danger")
        else:
            certificate = Certificate.query.filter_by(
                blockchain_hash=submitted_hash
            ).first()
            if certificate is not None:
                record = BlockchainRecord.query.filter_by(
                    certificate_id=certificate.id
                ).first()
            verified = certificate is not None and record is not None

            write_activity_log(
                "Stored Hash Verification",
                "Valid stored hash" if verified else "Hash not found",
            )

    template_name = "admin/verify_stored_hash.html"
    if os.path.isfile(os.path.join(app.root_path, "templates", template_name)):
        return render_template(
            template_name,
            submitted_hash=submitted_hash,
            certificate=certificate,
            record=record,
            verified=verified,
        )

    # Fallback page keeps the feature working even before a template is created.
    result_html = ""
    if verified:
        result_html = (
            "<div style='padding:16px;background:#dcfce7;color:#166534;"
            "border-radius:10px;margin-top:20px;'>"
            "<b>VALID</b><br>Stored certificate and blockchain record match."
            f"<br>Certificate: {certificate.certificate_name}"
            f"<br>Student: {certificate.student.full_name}"
            "</div>"
        )
    elif verified is False:
        result_html = (
            "<div style='padding:16px;background:#fee2e2;color:#991b1b;"
            "border-radius:10px;margin-top:20px;'><b>NOT FOUND / INVALID</b>"
            "<br>No matching stored certificate record was found.</div>"
        )

    return f"""
    <!doctype html><html><head><title>Verify Stored Hash - CertChain</title>
    <style>body{{font-family:Arial;background:#081b33;color:white;padding:40px;}}
    .box{{max-width:800px;margin:auto;background:#142b4d;padding:30px;border-radius:16px;}}
    input{{width:100%;padding:14px;border-radius:8px;border:1px solid #60708a;box-sizing:border-box;}}
    button{{margin-top:14px;padding:12px 20px;border:0;border-radius:8px;background:#2563eb;color:white;font-weight:bold;}}
    a{{color:#7dd3fc;}}</style></head><body><div class='box'>
    <h1>Verify Stored Hash</h1><p>Enter the SHA-256 hash stored for a certificate.</p>
    <form method='post'><input name='blockchain_hash' value='{submitted_hash}' placeholder='SHA-256 hash'>
    <button type='submit'>Verify Hash</button></form>{result_html}
    <p style='margin-top:25px'><a href='{url_for("admin_dashboard")}'>Back to Dashboard</a></p>
    </div></body></html>
    """


# Extra endpoint aliases prevent BuildError in older admin templates.
@app.route("/admin/students/manage")
def admin_students():
    return redirect(url_for("view_students")) if admin_required() else redirect(url_for("login", role="admin"))


@app.route("/admin/certificates/manage")
def admin_certificates():
    return redirect(url_for("view_certificates")) if admin_required() else redirect(url_for("login", role="admin"))


@app.route("/admin/reports")
def reports():
    if not admin_required():
        flash("Please login as Admin to continue.", "danger")
        return redirect(url_for("login", role="admin"))

    total_students = Student.query.count()
    active_students = Student.query.filter_by(status="Active").count()
    total_certificates = Certificate.query.count()
    verified_certificates = Certificate.query.filter_by(status="Verified").count()
    total_blocks = BlockchainRecord.query.count()
    total_logs = len(read_activity_logs())

    template_name = "admin/reports.html"
    if os.path.isfile(os.path.join(app.root_path, "templates", template_name)):
        return render_template(
            template_name,
            total_students=total_students,
            active_students=active_students,
            total_certificates=total_certificates,
            verified_certificates=verified_certificates,
            total_blocks=total_blocks,
            total_logs=total_logs,
        )

    return f"""
    <!doctype html><html><head><title>Reports - CertChain</title>
    <style>body{{font-family:Arial;background:#eef3f9;padding:30px;color:#10233f;}}
    .wrap{{max-width:1000px;margin:auto;}}.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:18px;}}
    .card{{background:white;padding:24px;border-radius:14px;box-shadow:0 5px 20px #0001;}}
    .num{{font-size:32px;font-weight:bold;color:#1677d2;}}a{{color:#1677d2;}}</style></head>
    <body><div class='wrap'><h1>CertChain Reports</h1><p>System summary and certificate statistics.</p>
    <div class='cards'><div class='card'>Students<div class='num'>{total_students}</div></div>
    <div class='card'>Active Students<div class='num'>{active_students}</div></div>
    <div class='card'>Certificates<div class='num'>{total_certificates}</div></div>
    <div class='card'>Verified Certificates<div class='num'>{verified_certificates}</div></div>
    <div class='card'>Blockchain Blocks<div class='num'>{total_blocks}</div></div>
    <div class='card'>Activity Events<div class='num'>{total_logs}</div></div></div>
    <p style='margin-top:30px'><a href='{url_for("download_report")}'>Download CSV Report</a> | 
    <a href='{url_for("admin_dashboard")}'>Dashboard</a></p></div></body></html>
    """


@app.route("/admin/reports/download")
def download_report():
    if not admin_required():
        flash("Please login as Admin to continue.", "danger")
        return redirect(url_for("login", role="admin"))

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Metric", "Value"])
    writer.writerow(["Total Students", Student.query.count()])
    writer.writerow(["Active Students", Student.query.filter_by(status="Active").count()])
    writer.writerow(["Total Certificates", Certificate.query.count()])
    writer.writerow(["Verified Certificates", Certificate.query.filter_by(status="Verified").count()])
    writer.writerow(["Blockchain Blocks", BlockchainRecord.query.count()])
    writer.writerow(["Activity Events", len(read_activity_logs())])
    output.seek(0)

    write_activity_log("Report Download", "CSV system report downloaded")
    return send_file(
        io.BytesIO(output.getvalue().encode("utf-8")),
        mimetype="text/csv",
        as_attachment=True,
        download_name="certchain_report.csv",
    )


@app.route("/admin/activity-logs")
def activity_logs():
    if not admin_required():
        flash("Please login as Admin to continue.", "danger")
        return redirect(url_for("login", role="admin"))

    logs = list(reversed(read_activity_logs()))
    template_name = "admin/activity_logs.html"
    if os.path.isfile(os.path.join(app.root_path, "templates", template_name)):
        return render_template(template_name, logs=logs)

    rows = "".join(
        f"<tr><td>{item.get('timestamp','')}</td><td>{item.get('user','')}</td>"
        f"<td>{item.get('role','')}</td><td>{item.get('action','')}</td>"
        f"<td>{item.get('details','')}</td></tr>"
        for item in logs
    )
    if not rows:
        rows = "<tr><td colspan='5'>No activity recorded yet.</td></tr>"

    return f"""
    <!doctype html><html><head><title>Activity Logs - CertChain</title>
    <style>body{{font-family:Arial;background:#081b33;color:white;padding:30px;}}
    .wrap{{max-width:1200px;margin:auto;}}table{{width:100%;border-collapse:collapse;background:#142b4d;}}
    th,td{{padding:12px;border-bottom:1px solid #315070;text-align:left;}}th{{background:#1d4ed8;}}
    a{{color:#7dd3fc;}}</style></head><body><div class='wrap'><h1>Activity Logs</h1>
    <p>Recent CertChain administrative activity.</p><table><thead><tr><th>Time</th><th>User</th>
    <th>Role</th><th>Action</th><th>Details</th></tr></thead><tbody>{rows}</tbody></table>
    <p style='margin-top:25px'><a href='{url_for("admin_dashboard")}'>Back to Dashboard</a></p>
    </div></body></html>
    """


@app.route("/admin/activity-logs/download")
def download_activity_logs():
    """Download the complete activity log as CSV."""
    if not admin_required():
        flash("Please login as Admin to continue.", "danger")
        return redirect(url_for("login", role="admin"))

    logs = read_activity_logs()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Timestamp", "User", "Email", "Role", "Action", "Details"])

    for item in logs:
        writer.writerow([
            item.get("timestamp", ""),
            item.get("user", ""),
            item.get("email", ""),
            item.get("role", ""),
            item.get("action", ""),
            item.get("details", ""),
        ])

    write_activity_log("Activity Log Download", "CSV activity log downloaded")
    output.seek(0)

    return send_file(
        io.BytesIO(output.getvalue().encode("utf-8-sig")),
        mimetype="text/csv",
        as_attachment=True,
        download_name="certchain_activity_logs.csv",
    )


# Endpoint aliases used by different dashboard template versions.
app.add_url_rule("/admin/qr-verification", endpoint="admin_qr_verification", view_func=qr_verification)
app.add_url_rule("/admin/reports", endpoint="admin_reports", view_func=reports)
app.add_url_rule("/admin/activity-logs", endpoint="admin_activity_logs", view_func=activity_logs)
app.add_url_rule("/admin/activity-logs/download", endpoint="admin_activity_logs_download", view_func=download_activity_logs)
app.add_url_rule("/admin/verify-stored-hash", endpoint="admin_verify_stored_hash", view_func=verify_stored_hash, methods=["GET", "POST"])


# ---------------------------------------------------------
# STUDENT DASHBOARD
# ---------------------------------------------------------

@app.route("/student/dashboard")
def student_dashboard():
    if not student_required():
        flash(
            "Please login as Student to continue.",
            "danger",
        )

        return redirect(
            url_for(
                "login",
                role="student",
            )
        )

    student = Student.query.filter_by(
        email=session.get("user_email")
    ).first()

    if student is None:
        session.clear()

        flash(
            "Student profile was not found.",
            "danger",
        )

        return redirect(
            url_for(
                "login",
                role="student",
            )
        )

    if student.status == "Inactive":
        session.clear()

        flash(
            "Your student account is inactive. "
            "Please contact the administrator.",
            "danger",
        )

        return redirect(
            url_for(
                "login",
                role="student",
            )
        )

    certificates = Certificate.query.filter_by(
        student_id=student.id
    ).order_by(
        Certificate.created_at.desc()
    ).all()

    total_certificates = len(certificates)

    return render_template(
        "student/dashboard.html",
        user_name=session.get("user_name"),
        student=student,
        certificates=certificates,
        total_certificates=total_certificates,
    )
# ---------------------------------------------------------
# VERIFIER DASHBOARD
# ---------------------------------------------------------

@app.route("/verifier/dashboard")
def verifier_dashboard():

    if not verifier_required():

        flash(
            "Please login as Verifier to continue.",
            "danger",
        )

        return redirect(
            url_for(
                "login",
                role="verifier",
            )
        )

    total_certificates = Certificate.query.count()

    valid_certificates = Certificate.query.filter(
        Certificate.blockchain_hash != None
    ).count()

    return render_template(
        "verifier/dashboard.html",
        user_name=session.get("user_name"),
        total_certificates=total_certificates,
        valid_certificates=valid_certificates,
    )
# ---------------------------------------------------------
# LOGOUT
# ---------------------------------------------------------

@app.route("/logout")
def logout():
    write_activity_log("Logout", "User logged out")
    session.clear()

    flash(
        "You have been logged out successfully.",
        "success",
    )

    return redirect(
        url_for("home")
    )


# ---------------------------------------------------------
# ERROR HANDLERS
# ---------------------------------------------------------

@app.errorhandler(403)
def forbidden(error):
    return (
        "<h1>403 - Access Denied</h1>"
        "<p>You do not have permission "
        "to access this resource.</p>",
        403,
    )


@app.errorhandler(404)
def page_not_found(error):
    return (
        "<h1>404 - Page Not Found</h1>"
        "<p>The requested page does not exist.</p>",
        404,
    )


@app.errorhandler(413)
def file_too_large(error):
    flash(
        "Uploaded file is too large. "
        "Maximum allowed size is 10 MB.",
        "danger",
    )

    if admin_required():
        return redirect(
            url_for("upload_certificate")
        )

    return redirect(
        url_for("verify_certificate")
    )


@app.errorhandler(500)
def internal_server_error(error):
    db.session.rollback()

    return (
        "<h1>500 - Internal Server Error</h1>"
        "<p>Something went wrong. "
        "Please try again.</p>",
        500,
    )


# ---------------------------------------------------------
# CREATE REQUIRED PROJECT FOLDERS
# ---------------------------------------------------------

def create_project_folders():
    folders = [
        "database",
        "uploads",
        "certificates",
        "reports",
    ]

    for folder in folders:
        folder_path = os.path.join(
            app.root_path,
            folder,
        )

        os.makedirs(
            folder_path,
            exist_ok=True,
        )


# ---------------------------------------------------------
# RUN APPLICATION
# ---------------------------------------------------------

if __name__ == "__main__":
    create_project_folders()

    with app.app_context():
        db.create_all()
        create_default_users()
        sync_existing_certificates_to_blockchain()

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True,
    )