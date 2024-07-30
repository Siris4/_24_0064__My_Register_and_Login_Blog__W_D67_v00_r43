from main import app, db, User

with app.app_context():
    # Fetch the user with ID 1
    admin_user = User.query.get(1)

    if admin_user:
        if admin_user.is_admin:
            print(f"User with ID 1 ({admin_user.email}) is an admin.")
        else:
            print(f"User with ID 1 ({admin_user.email}) is NOT an admin.")
    else:
        print("User with ID 1 not found.")
