from main import app, db, User

with app.app_context():
    # Fetch the user with ID 1
    admin_user = User.query.get(1)

    if admin_user:
        # Update the user's email and set as admin
        admin_user.email = 'siris1.dev@gmail.com'
        admin_user.is_admin = True
        db.session.commit()
        print(f"User {admin_user.email} with ID 1 has been set as admin.")
    else:
        print("User with ID 1 not found.")
