from main import db, User, BlogPost

# Create all tables (if they don't exist)
db.create_all()

# Print all users
print("Users:")
for user in User.query.all():
    print(user.id, user.email, user.is_admin)

# Print all blog posts
print("\nBlog Posts:")
for post in BlogPost.query.all():
    print(post.id, post.title, post.author.email)
