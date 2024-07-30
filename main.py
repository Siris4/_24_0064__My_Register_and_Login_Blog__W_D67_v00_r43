import os
from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import declarative_base
from flask_ckeditor import CKEditor
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import date
import logging
from sqlalchemy.exc import IntegrityError
from functools import wraps
from flask_migrate import Migrate
from markupsafe import Markup

# Initialize Flask app and Bootstrap
app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
Bootstrap(app)

# Direct path to the new database
db_path = r'C:\Users\Siris\Desktop\D69 README FILE!!!!!!\r30-r39\r43_env_NWY\instance\posts.db'

# Ensure the instance folder exists
instance_folder = os.path.dirname(db_path)
if not os.path.exists(instance_folder):
    os.makedirs(instance_folder)

# Use the direct path to the database
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

ckeditor = CKEditor(app)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
migrate = Migrate(app, db)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Models
Base = declarative_base()


class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    # Relationship with BlogPost
    posts = db.relationship('BlogPost', back_populates='author')


class BlogPost(db.Model):
    __tablename__ = 'blog_post'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    # Relationship with User
    author = db.relationship('User', back_populates='posts')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


with app.app_context():
    db.create_all()

# Forms
from forms import CreatePostForm, UserRegisterForm, LoginForm


# Utility functions
def slugify(value):
    import re
    value = re.sub(r'[^\w\s-]', '', value).strip().lower()
    value = re.sub(r'[\s_-]+', '-', value)
    return value


app.jinja_env.filters['slugify'] = slugify


def fetch_posts(page, per_page):
    pagination = BlogPost.query.order_by(BlogPost.date.desc()).paginate(page=page, per_page=per_page)
    return pagination


def validate_input(name, email, phone, message):
    if not all([name, email, phone, message]):
        return False
    if "@" not in email or "." not in email:
        return False
    return True


def send_email(name, email, phone, message):
    import smtplib
    email_subject = "New Contact Form Submission for Siris's Blog"
    email_body = f"Subject:{email_subject}\n\nName: {name}\nEmail: {email}\nPhone: {phone}\nMessage: {message}"
    my_from_email1 = os.environ.get('MY_FROM_EMAIL1', 'Custom Message / Email does not exist')
    password = os.environ.get('PASSWORD', 'Custom Message / Password does not exist')
    their_email2 = os.environ.get('THEIR_EMAIL2', 'Custom Message / Email does not exist')

    try:
        with smtplib.SMTP("smtp.gmail.com", port=587) as connection:
            connection.starttls()
            connection.login(user=my_from_email1, password=password)
            connection.sendmail(
                from_addr=my_from_email1,
                to_addrs=their_email2,
                msg=email_body
            )
        logging.info("Email sent successfully")
    except smtplib.SMTPException as e:
        logging.error(f"Failed to send email: {e}")


# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)

    return decorated_function


# Routes
@app.route('/')
@app.route('/home')
def home():
    page = request.args.get('page', 1, type=int)
    per_page = 10
    pagination = fetch_posts(page, per_page)
    posts = pagination.items
    return render_template("index.html", posts=posts, pagination=pagination, page='home')


@app.route('/post/<slug>')
def post(slug):
    post = BlogPost.query.filter_by(title=slug).first_or_404()
    return render_template("post.html", post=post)


@app.route('/about')
def about():
    return render_template('about.html', page='about')


@app.route('/contact', methods=["GET", "POST"])
def contact():
    form_submitted = False
    if request.method == "POST":
        name = request.form.get('name')
        email = request.form.get('email')
        phone = request.form.get('phone')
        message = request.form.get('message')
        if validate_input(name, email, phone, message):
            send_email(name, email, phone, message)
            form_submitted = True
            logging.info(f"Contact form submitted: {name}, {email}")
        else:
            logging.warning("Validation failed for contact form submission.")
            return "Invalid input data", 400
    return render_template("contact.html", form_submitted=form_submitted)


@app.route('/new-post', methods=["GET", "POST"])
@login_required
@admin_required
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        # Check for duplicate titles
        existing_post = BlogPost.query.filter_by(title=form.title.data).first()
        if existing_post:
            flash("A post with this title already exists. Please choose a different title.", "danger")
        else:
            new_post = BlogPost(
                title=form.title.data,
                subtitle=form.subtitle.data,
                date=date.today().strftime("%B %d, %Y"),
                body=form.body.data,
                author_id=current_user.id
            )
            try:
                db.session.add(new_post)
                db.session.commit()
                flash("New post created successfully!", "success")
                return redirect(url_for("home"))
            except IntegrityError:
                db.session.rollback()
                flash("An error occurred while creating the post. Please try again.", "danger")
    return render_template("new_post.html", form=form, is_edit=False)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@login_required
@admin_required
def edit_post(post_id):
    post = BlogPost.query.get_or_404(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        flash("Post updated successfully!", "success")
        return redirect(url_for("post", slug=slugify(post.title)))
    return render_template("new_post.html", form=edit_form, is_edit=True, post=post)


@app.route("/delete/<int:post_id>")
@login_required
@admin_required
def delete_post(post_id):
    post_to_delete = BlogPost.query.get_or_404(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    flash("Post deleted successfully!", "success")
    return redirect(url_for("home"))


@app.route("/register", methods=["GET", "POST"])
def register():
    form = UserRegisterForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash("This email is already registered. Please log in.", "danger")
            return redirect(url_for('login'))

        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You can now log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                logging.info(f"User {user.email} logged in successfully.")
                return redirect(url_for('home'))
            else:
                logging.warning(f"Incorrect password for user {user.email}.")
        else:
            logging.warning(f"User with email {form.email.data} not found.")
        flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', form=form)


@app.route("/logout")
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for('home'))


@app.route('/view_users')
@login_required
@admin_required
def view_users():
    users = User.query.all()
    return render_template('view_users.html', users=users)


if __name__ == "__main__":
    app.run(debug=True)
