from datetime import datetime

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


# ---------------------------------------------------------
# USER MODEL
# ---------------------------------------------------------

class User(db.Model):
    __tablename__ = "users"

    id = db.Column(
        db.Integer,
        primary_key=True,
    )

    name = db.Column(
        db.String(100),
        nullable=False,
    )

    email = db.Column(
        db.String(120),
        unique=True,
        nullable=False,
    )

    password = db.Column(
        db.String(255),
        nullable=False,
    )

    role = db.Column(
        db.String(30),
        nullable=False,
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        nullable=False,
    )


# ---------------------------------------------------------
# STUDENT MODEL
# ---------------------------------------------------------

class Student(db.Model):
    __tablename__ = "students"

    id = db.Column(
        db.Integer,
        primary_key=True,
    )

    student_id = db.Column(
        db.String(50),
        unique=True,
        nullable=False,
    )

    full_name = db.Column(
        db.String(120),
        nullable=False,
    )

    email = db.Column(
        db.String(120),
        unique=True,
        nullable=False,
    )

    phone = db.Column(
        db.String(20),
        nullable=False,
    )

    course = db.Column(
        db.String(100),
        nullable=False,
    )

    department = db.Column(
        db.String(100),
        nullable=False,
    )

    academic_year = db.Column(
        db.String(20),
        nullable=False,
    )

    status = db.Column(
        db.String(20),
        default="Active",
        nullable=False,
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    certificates = db.relationship(
        "Certificate",
        back_populates="student",
        lazy=True,
        cascade="all, delete-orphan",
    )


# ---------------------------------------------------------
# CERTIFICATE MODEL
# ---------------------------------------------------------

class Certificate(db.Model):
    __tablename__ = "certificates"

    id = db.Column(
        db.Integer,
        primary_key=True,
    )

    student_id = db.Column(
        db.Integer,
        db.ForeignKey("students.id"),
        nullable=False,
    )

    certificate_name = db.Column(
        db.String(200),
        nullable=False,
    )

    certificate_type = db.Column(
        db.String(100),
        nullable=False,
    )

    issue_date = db.Column(
        db.String(30),
        nullable=False,
    )

    file_name = db.Column(
        db.String(255),
        nullable=False,
    )

    blockchain_hash = db.Column(
        db.String(255),
        unique=True,
        nullable=False,
    )

    status = db.Column(
        db.String(20),
        default="Verified",
        nullable=False,
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    student = db.relationship(
        "Student",
        back_populates="certificates",
    )

    blockchain_record = db.relationship(
        "BlockchainRecord",
        back_populates="certificate",
        uselist=False,
        cascade="all, delete-orphan",
    )


# ---------------------------------------------------------
# BLOCKCHAIN RECORD MODEL
# ---------------------------------------------------------

class BlockchainRecord(db.Model):
    __tablename__ = "blockchain_records"

    id = db.Column(
        db.Integer,
        primary_key=True,
    )

    block_index = db.Column(
        db.Integer,
        unique=True,
        nullable=False,
    )

    certificate_id = db.Column(
        db.Integer,
        db.ForeignKey("certificates.id"),
        unique=True,
        nullable=False,
    )

    certificate_hash = db.Column(
        db.String(255),
        nullable=False,
    )

    previous_hash = db.Column(
        db.String(255),
        nullable=False,
    )

    block_hash = db.Column(
        db.String(255),
        unique=True,
        nullable=False,
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    certificate = db.relationship(
        "Certificate",
        back_populates="blockchain_record",
    )