"""
GreenCode Platform - Controller Layer
=====================================
Flask routes implementing the Use Cases documented in Phase 2.

Security (NFR-02):
- Werkzeug password hashing (never plaintext)
- Server-side signed sessions
- login_required / role_required decorators
- RBAC enforcement (FR-13)

Analysis:
- Uses app.analyzer.engine for Python/Java static analysis
"""
import os
from functools import wraps
from datetime import datetime
from flask import (Blueprint, render_template, request, redirect, url_for,
                   flash, current_app, session, abort)
from werkzeug.utils import secure_filename

from app import db
from app.models import (
    User, Project, ProjectVersion, SourceFile,
    AnalysisRun, EnergySmell, RefactoringSuggestion,
    ComparisonResult, ActivityLog
)
from app.analyzer import analyze_file

bp = Blueprint("main", __name__)


# =============================================================
# Authentication & Authorization Helpers (FR-13, NFR-02)
# =============================================================
def current_user():
    """Retrieve the currently authenticated user from the session."""
    uid = session.get("user_id")
    return User.query.get(uid) if uid else None


def login_required(view_fn):
    """Decorator: require an authenticated session."""
    @wraps(view_fn)
    def wrapped(*args, **kwargs):
        if not current_user():
            flash("Please log in to continue.", "danger")
            return redirect(url_for("main.login"))
        return view_fn(*args, **kwargs)
    return wrapped


def role_required(required_role):
    """Decorator: require a minimum role (DEVELOPER < PROJECT_MANAGER < ADMIN)."""
    def decorator(view_fn):
        @wraps(view_fn)
        def wrapped(*args, **kwargs):
            user = current_user()
            if not user:
                flash("Please log in to continue.", "danger")
                return redirect(url_for("main.login"))
            if not user.has_role(required_role):
                flash("You do not have permission to access this page.", "danger")
                return redirect(url_for("main.dashboard"))
            return view_fn(*args, **kwargs)
        return wrapped
    return decorator


def log_activity(action, details=""):
    """Persist an audit-trail entry for the current user (FR-15)."""
    user = current_user()
    if user:
        entry = ActivityLog(action=action, details=details, user_id=user.id)
        db.session.add(entry)
        db.session.commit()


@bp.app_context_processor
def inject_user():
    """Make the current user available in every template."""
    return {"current_user": current_user()}


# =============================================================
# File validation helpers
# =============================================================
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in {"py", "java", "txt"}


def detect_language(filename):
    ext = filename.rsplit(".", 1)[1].lower()
    if ext == "py":
        return "python"
    if ext == "java":
        return "java"
    return "text"


# =============================================================
# Authentication Routes (UC-06: Authenticate User)
# =============================================================
@bp.route("/register", methods=["GET", "POST"])
def register_user():
    """Register a new account (FR-14)."""
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        role = request.form.get("role") or "DEVELOPER"

        if not username or not password:
            flash("Username and password are required.", "danger")
            return redirect(url_for("main.register_user"))

        if User.query.filter_by(username=username).first():
            flash("Username already exists.", "danger")
            return redirect(url_for("main.register_user"))

        user = User(username=username, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash("Account created successfully. Please log in.", "success")
        return redirect(url_for("main.login"))

    return render_template("register.html")


@bp.route("/login", methods=["GET", "POST"])
def login():
    """Authenticate a user and create a server-side session (NFR-02)."""
    if current_user():
        return redirect(url_for("main.dashboard"))

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session.clear()
            session["user_id"] = user.id
            log_activity("login", f"User {user.username} signed in")
            flash(f"Welcome back, {user.username}!", "success")
            return redirect(url_for("main.dashboard"))

        flash("Invalid username or password.", "danger")

    return render_template("login.html")


@bp.route("/logout")
def logout():
    """End the current session."""
    log_activity("logout", "User signed out")
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("main.login"))


# =============================================================
# Dashboard (requires login)
# =============================================================
@bp.route("/")
@login_required
def dashboard():
    user = current_user()

    if user.has_role("PROJECT_MANAGER"):
        projects = Project.query.order_by(Project.created_at.desc()).all()
        analyses = AnalysisRun.query.order_by(AnalysisRun.started_at.desc()).limit(10).all()
    else:
        projects = Project.query.filter_by(owner_id=user.id)\
            .order_by(Project.created_at.desc()).all()
        version_ids = [v.id for p in projects for v in p.versions]
        if version_ids:
            analyses = AnalysisRun.query.filter(
                AnalysisRun.version_id.in_(version_ids)
            ).order_by(AnalysisRun.started_at.desc()).limit(10).all()
        else:
            analyses = []

    users = User.query.order_by(User.created_at.desc()).all() \
        if user.has_role("ADMIN") else []

    return render_template("dashboard.html",
                           projects=projects, analyses=analyses, users=users)


# =============================================================
# Project Upload & Analysis (UC-01)
# =============================================================
@bp.route("/upload", methods=["GET", "POST"])
@login_required
def upload_project():
    user = current_user()

    if request.method == "POST":
        project_name = (request.form.get("project_name") or "").strip()
        version_label = (request.form.get("version_label") or "").strip()
        uploaded_file = request.files.get("source_file")

        if not project_name or not version_label:
            flash("Project name and version label are required.", "danger")
            return redirect(url_for("main.upload_project"))

        if not uploaded_file or uploaded_file.filename == "":
            flash("Please choose a file.", "danger")
            return redirect(url_for("main.upload_project"))

        if not allowed_file(uploaded_file.filename):
            flash("Only .py, .java, .txt files are allowed.", "danger")
            return redirect(url_for("main.upload_project"))

        filename = secure_filename(uploaded_file.filename)
        save_path = os.path.join(current_app.config["UPLOAD_FOLDER"], filename)
        uploaded_file.save(save_path)

        with open(save_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        project = Project(name=project_name, owner_id=user.id)
        db.session.add(project)
        db.session.commit()

        version = ProjectVersion(version_label=version_label, project_id=project.id)
        db.session.add(version)
        db.session.commit()

        source_file = SourceFile(
            path=filename,
            language=detect_language(filename),
            content=content,
            version_id=version.id
        )
        db.session.add(source_file)
        db.session.commit()

        log_activity("upload_project",
                     f'Uploaded "{project_name}" version {version_label}')
        flash("Project uploaded successfully.", "success")
        return redirect(url_for("main.analyze_source_code", version_id=version.id))

    return render_template("upload.html")


@bp.route("/analyze/<int:version_id>")
@login_required
def analyze_source_code(version_id):
    user = current_user()
    version = ProjectVersion.query.get_or_404(version_id)

    if not user.has_role("PROJECT_MANAGER") and version.project.owner_id != user.id:
        abort(403)

    files = SourceFile.query.filter_by(version_id=version.id).all()

    analysis = AnalysisRun(status="Running", overall_score=0, version_id=version.id)
    db.session.add(analysis)
    db.session.commit()

    try:
        total_score = 0
        for file in files:
            score, smells, suggestions, _ = analyze_file(
                file.content, file.path, file.language
            )
            total_score += score

            for smell_type, severity, line_no, reason in smells:
                db.session.add(EnergySmell(
                    smell_type=smell_type,
                    severity=severity,
                    file_path=file.path,
                    line_start=line_no,
                    line_end=line_no,
                    reason=reason,
                    analysis_id=analysis.id
                ))

            for title, description in suggestions:
                db.session.add(RefactoringSuggestion(
                    title=title,
                    description=description,
                    analysis_id=analysis.id
                ))

        analysis.overall_score = round(total_score / len(files), 1) if files else 0
        analysis.status = "Completed"
        analysis.finished_at = datetime.utcnow()
        db.session.commit()

        log_activity("run_analysis",
                     f"Analysis #{analysis.id} completed "
                     f"(score: {analysis.overall_score})")
        flash("Analysis completed successfully.", "success")
    except Exception as exc:
        analysis.status = "Failed"
        analysis.finished_at = datetime.utcnow()
        db.session.commit()
        log_activity("run_analysis_failed", str(exc))
        flash(f"Analysis failed: {exc}", "danger")

    return redirect(url_for("main.view_report", analysis_id=analysis.id))


# =============================================================
# Report (UC-02)
# =============================================================
@bp.route("/report/<int:analysis_id>")
@login_required
def view_report(analysis_id):
    user = current_user()
    analysis = AnalysisRun.query.get_or_404(analysis_id)
    version = ProjectVersion.query.get_or_404(analysis.version_id)
    project = Project.query.get_or_404(version.project_id)

    if not user.has_role("PROJECT_MANAGER") and project.owner_id != user.id:
        abort(403)

    smells = EnergySmell.query.filter_by(analysis_id=analysis.id).all()
    suggestions = RefactoringSuggestion.query.filter_by(analysis_id=analysis.id).all()

    high_count = len([s for s in smells if s.severity == "High"])
    medium_count = len([s for s in smells if s.severity == "Medium"])
    low_count = len([s for s in smells if s.severity == "Low"])

    smells_by_severity = {
        "High":   [s for s in smells if s.severity == "High"],
        "Medium": [s for s in smells if s.severity == "Medium"],
        "Low":    [s for s in smells if s.severity == "Low"],
    }

    return render_template(
        "report.html",
        analysis=analysis, version=version, project=project,
        smells=smells, suggestions=suggestions,
        smells_by_severity=smells_by_severity,
        high_count=high_count, medium_count=medium_count, low_count=low_count
    )


# =============================================================
# Compare Versions (UC-03)
# =============================================================
@bp.route("/compare", methods=["GET", "POST"])
@login_required
def compare_versions():
    user = current_user()

    if user.has_role("PROJECT_MANAGER"):
        analyses = AnalysisRun.query.filter_by(status="Completed")\
            .order_by(AnalysisRun.started_at.desc()).all()
    else:
        project_ids = [p.id for p in Project.query.filter_by(owner_id=user.id).all()]
        if project_ids:
            version_ids = [v.id for v in ProjectVersion.query
                           .filter(ProjectVersion.project_id.in_(project_ids)).all()]
            analyses = AnalysisRun.query.filter(
                AnalysisRun.version_id.in_(version_ids),
                AnalysisRun.status == "Completed"
            ).order_by(AnalysisRun.started_at.desc()).all() if version_ids else []
        else:
            analyses = []

    if request.method == "POST":
        try:
            before_id = int(request.form.get("before_analysis_id"))
            after_id = int(request.form.get("after_analysis_id"))
        except (TypeError, ValueError):
            flash("Please select both analyses.", "danger")
            return redirect(url_for("main.compare_versions"))

        before_analysis = AnalysisRun.query.get_or_404(before_id)
        after_analysis = AnalysisRun.query.get_or_404(after_id)

        smells_before = EnergySmell.query.filter_by(analysis_id=before_analysis.id).count()
        smells_after = EnergySmell.query.filter_by(analysis_id=after_analysis.id).count()

        result = ComparisonResult(
            delta_score=(after_analysis.overall_score or 0) - (before_analysis.overall_score or 0),
            smells_before=smells_before,
            smells_after=smells_after,
            before_analysis_id=before_analysis.id,
            after_analysis_id=after_analysis.id
        )
        db.session.add(result)
        db.session.commit()

        log_activity("compare_versions",
                     f"Compared analyses #{before_id} and #{after_id}")

        return render_template(
            "compare.html", analyses=analyses, result=result,
            before_analysis=before_analysis, after_analysis=after_analysis
        )

    return render_template("compare.html", analyses=analyses)


# =============================================================
# User Management (UC-04) - Admin only (FR-14)
# =============================================================
@bp.route("/admin/users")
@login_required
@role_required("ADMIN")
def manage_users():
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template("manage_users.html", users=users)


@bp.route("/admin/users/<int:user_id>/role", methods=["POST"])
@login_required
@role_required("ADMIN")
def change_role(user_id):
    user = User.query.get_or_404(user_id)
    new_role = request.form.get("role")
    if new_role in ("DEVELOPER", "PROJECT_MANAGER", "ADMIN"):
        old_role = user.role
        user.role = new_role
        db.session.commit()
        log_activity("change_role",
                     f"Changed role of {user.username}: {old_role} -> {new_role}")
        flash(f"Role of {user.username} updated to {new_role}.", "success")
    return redirect(url_for("main.manage_users"))


# =============================================================
# Audit Log (UC-05) - Admin only (FR-15)
# =============================================================
@bp.route("/admin/logs")
@login_required
@role_required("ADMIN")
def view_logs():
    logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(200).all()
    return render_template("logs.html", logs=logs)
