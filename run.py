"""
GreenCode Platform - Entry Point
=================================
Usage:
    flask --app run init-db   # Create tables + 3 demo users
    python run.py             # Launch development server
"""
from app import create_app, db
from app.models import User

app = create_app()

from app import db

with app.app_context():
    db.create_all()

@app.cli.command("init-db")
def init_db():
    """Create tables and seed three demonstration accounts."""
    db.create_all()

    seeds = [
        ("admin", "admin123", "ADMIN"),
        ("developer", "dev123", "DEVELOPER"),
        ("manager", "manager123", "PROJECT_MANAGER"),
    ]

    created = []
    for username, password, role in seeds:
        if not User.query.filter_by(username=username).first():
            user = User(username=username, role=role)
            user.set_password(password)
            db.session.add(user)
            created.append(f"  {username:10} / {password:12} ({role})")

    db.session.commit()

    print("=" * 50)
    print("Database initialized successfully.")
    print("=" * 50)
    if created:
        print("Seed accounts created:")
        for line in created:
            print(line)
    else:
        print("Seed accounts already exist, skipped.")


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5001)
