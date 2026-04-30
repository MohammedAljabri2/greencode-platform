"""
GreenCode Platform - Data Models
================================
SQLAlchemy ORM classes that mirror the UML Class Diagram from Phase 2.

Traceability:
- User                  -> FR-13 (RBAC), FR-14 (User Management)
- Project               -> FR-01 (Upload Project)
- ProjectVersion        -> FR-11 (Compare Versions)
- SourceFile            -> FR-02 (Static Analysis)
- AnalysisRun           -> FR-06, FR-07 (Scoring), FR-16 (Completion)
- EnergySmell           -> FR-03 (Detect Smells), FR-04 (Classify Severity)
- RefactoringSuggestion -> FR-05 (Recommendations)
- ComparisonResult      -> FR-11 (Version Comparison)
"""
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from app import db


class User(db.Model):
    """
    User entity - implements FR-13 (RBAC) and FR-14 (User Management).
    Passwords are stored as salted hashes to satisfy NFR-02 (Security).
    """
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False, unique=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="DEVELOPER")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    projects = db.relationship("Project", backref="owner", lazy=True)

    def set_password(self, password):
        """Hash and store the password using Werkzeug (NFR-02)."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Verify a plaintext password against the stored hash."""
        return check_password_hash(self.password_hash, password)

    def has_role(self, required_role):
        """RBAC hierarchy check: ADMIN > PROJECT_MANAGER > DEVELOPER."""
        hierarchy = {"DEVELOPER": 1, "PROJECT_MANAGER": 2, "ADMIN": 3}
        return hierarchy.get(self.role, 0) >= hierarchy.get(required_role, 0)


class Project(db.Model):
    __tablename__ = "project"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    versions = db.relationship(
        "ProjectVersion", backref="project", lazy=True,
        cascade="all, delete-orphan"
    )


class ProjectVersion(db.Model):
    __tablename__ = "project_version"

    id = db.Column(db.Integer, primary_key=True)
    version_label = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    project_id = db.Column(db.Integer, db.ForeignKey("project.id"), nullable=False)

    source_files = db.relationship(
        "SourceFile", backref="version", lazy=True,
        cascade="all, delete-orphan"
    )
    analysis_runs = db.relationship(
        "AnalysisRun", backref="version", lazy=True,
        cascade="all, delete-orphan"
    )


class SourceFile(db.Model):
    __tablename__ = "source_file"

    id = db.Column(db.Integer, primary_key=True)
    path = db.Column(db.String(300), nullable=False)
    language = db.Column(db.String(30), nullable=False)
    content = db.Column(db.Text, nullable=False)
    version_id = db.Column(db.Integer, db.ForeignKey("project_version.id"), nullable=False)


class AnalysisRun(db.Model):
    __tablename__ = "analysis_run"

    id = db.Column(db.Integer, primary_key=True)
    status = db.Column(db.String(20), nullable=False)
    overall_score = db.Column(db.Float)
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    finished_at = db.Column(db.DateTime, default=datetime.utcnow)
    version_id = db.Column(db.Integer, db.ForeignKey("project_version.id"), nullable=False)

    energy_smells = db.relationship(
        "EnergySmell", backref="analysis", lazy=True,
        cascade="all, delete-orphan"
    )
    suggestions = db.relationship(
        "RefactoringSuggestion", backref="analysis", lazy=True,
        cascade="all, delete-orphan"
    )


class EnergySmell(db.Model):
    __tablename__ = "energy_smell"

    id = db.Column(db.Integer, primary_key=True)
    smell_type = db.Column(db.String(100), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    file_path = db.Column(db.String(300), nullable=False)
    line_start = db.Column(db.Integer, nullable=False)
    line_end = db.Column(db.Integer, nullable=False)
    reason = db.Column(db.Text, nullable=False)
    analysis_id = db.Column(db.Integer, db.ForeignKey("analysis_run.id"), nullable=False)


class RefactoringSuggestion(db.Model):
    __tablename__ = "refactoring_suggestion"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    analysis_id = db.Column(db.Integer, db.ForeignKey("analysis_run.id"), nullable=False)


class ComparisonResult(db.Model):
    __tablename__ = "comparison_result"

    id = db.Column(db.Integer, primary_key=True)
    delta_score = db.Column(db.Float, nullable=False)
    smells_before = db.Column(db.Integer, nullable=False)
    smells_after = db.Column(db.Integer, nullable=False)
    before_analysis_id = db.Column(db.Integer, nullable=False)
    after_analysis_id = db.Column(db.Integer, nullable=False)


class ActivityLog(db.Model):
    """
    Persistent audit trail of user actions (FR-15).
    Admins can review all entries from the /admin/logs endpoint.
    """
    __tablename__ = "activity_log"

    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    user = db.relationship("User")
