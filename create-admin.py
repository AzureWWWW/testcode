from main import SessionLocal, User, hash_password

db = SessionLocal()
hashed_password = hash_password("admin")  # Replace with your secure password
admin_user = User(username="admin", email="admin@example.com", hashed_password=hashed_password, role="admin")
db.add(admin_user)
db.commit()
db.close()
