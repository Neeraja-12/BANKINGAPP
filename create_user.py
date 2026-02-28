from app import app, db, User
from werkzeug.security import generate_password_hash

with app.app_context():
    hashed_pw = generate_password_hash("test123", method="pbkdf2:sha256")
    user = User(username="testuser", email="test@example.com", password=hashed_pw)
    db.session.add(user)
    db.session.commit()
    print("User created successfully!")
