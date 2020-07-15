# --------------------------------------------------------------------------------------------------
#   PROJECT:        DSS assignment 1: Developing a secure application
#   FILE:           DSSForum.py
#   DESCRIPTION:    Flask server for "micro blogging website"
#   AUTHOR(S):      SSQ16SHU / 100166648
#                   JMM17EFU / 100215437
#                   YRK17AFU / 100204267
#   BRANCH:         XSS
#   SUBJECT:        Branch to work on cross-site-scripting prevention
#   HISTORY:        200211  v1.0    Initial implementation: naive implementation of escape function
#                                   and associated character substitution list.
#                   200211  v1.1    refined escape function to return from database queries.
#                                   successful test of reflected xss prevention:
#                                       +   search bar (index page)
#                                   successful test of embedded xss prevention:
#                                       +   message body
#                                       +   message title
#                   200220  v1.2    tidied code and added comments. added and tested embedded escaping for user history.
#                                   found and investigated single quote syntax error on search: have NOT rectified this
#                                   as seems to be solved by parameterised SQL queries (part of injection prevention).
#                                   investigated JS client-side prevention (not reliable) and DOM XSS -not currently
#                                   vulnerable, will discuss before implementing just in hopes of extra marks
#                   v1.3    200225  added (empty) def for signup (new user page): need to add database/email methods
#                   v1.3.1  200227  commented out db reset route (as this currently serves no purpose for us and
#                                   potentially used to test system on demo)
#                   v1.4    200228  installed and included requests. added recaptcha is_human method and in /signup/.
#                   v2.0    200229  manually merged email and html 1 branches, added debug prints throughout, debugged
#                                   a few issues, added more notifications to the user, addressed html and css for all
#                                   pages: tested and debugged (aside from noted exceptions)
#                   v2.1    200229  fixed bugs, tidied code, adjusted some
#                   v3.0    200307  Rewrote program with comments, logging and separating functions into helper files
# --------------------------------------------------------------------------------------------------
import re
import datetime
from flask import Flask, render_template, redirect, request, session, url_for, flash
from functools import wraps
from time import sleep

from helpers import event_log as log
from helpers import database as db
from helpers import security as sec
from helpers import email as eml
from helpers import captcha as cap

# DEFINITIONS ----------------------------
SITE_MODE = 'live'

app = Flask(__name__)
app.secret_key = '---REDACTED---'
if SITE_MODE == 'live':
    app.config.update(
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax'
    )
else:
    app.config.update(
        SESSION_COOKIE_SECURE=False,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax'
    )


# passed captcha sitekey (to prevent hard coding in html) and secret key to send
# captcha_site_key = "---REDACTED---"
# captcha_secret_key = "---REDACTED---"


# recaptcha response from google server (true if validated)
# def is_human(captcha_response):
#     secret = "---REDACTED---"
#     response = requests.post("https://www.google.com/recaptcha/api/siteverify",
#                              data={"secret": captcha_secret_key,
#                                    "response": request.form["g-recaptcha-response"]})
#     response_text = json.loads(response.text)
#     print(response_text)
#     return response_text['success']


def std_context(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        context = {}
        request.context = context
        if 'userid' in session:
            context['loggedin'] = True
            context['username'] = session['username']
        else:
            context['loggedin'] = False
        return f(*args, **kwargs)

    return wrapper


@app.teardown_appcontext
def close_app(exception):
    db.close_db()


@app.before_request
def set_session_timeout():
    session.permanent = 'True'
    app.permanent_session_lifetime = datetime.timedelta(minutes=10)
    session.modified = True


# HTML PAGES -----------------------------------------------------------------------------------------------------------

# LOGIN PAGE ---------------------------
@app.route("/login/", methods=['GET', 'POST'])
@std_context
def login():
    # render page if get request
    if request.method == 'GET':
        return render_template('login.html')

    # get username and password form fields
    username = request.form.get('username', '')
    password = request.form.get('password', '')

    # use field values to retrieve account
    account = db.user_exists_by_username(username)

    # check an account was returned (i.e. it exists) and passwords match
    if account and account['password'] == sec.hash_encrypt_password(password, account['salt']):

        # check account is verified
        if account['verified']:
            # clear and initialise session with account values
            session.clear()
            session['userid'] = account['userid']
            session['username'] = username

            # log login success and redirect to homepage
            log.log_info(f'User login successful: Username={username}')
            return redirect(url_for('index'))
        else:
            # log login failure due to account not verified, redirect to login page
            log.log_warning(f'User login failed: Reason="Account not verified", Username={username}')
            flash('Your account has not yet been verified, please check your email', 'warning')
            return render_template('login.html', username=username)

    else:
        # todo: maybe add a failed attempt counter to lock out user and/or notify server?
        # No user found or password incorrect, log login failure, render login page
        log.log_warning(
            f'User login failed: Username={username}, '
            f'Reason="{"Incorrect password" if account else "User does not exist"}"'
        )
        flash('Username or password is invalid', 'warning')
        return render_template('login.html', username=username)


# user log out -------------------------
@app.route("/logout/")
def logout():
    # check session exists
    if session.get('username') is not None:
        # log activity
        log.log_info(f'User logged out: Username:{session["username"]}')

        # remove session from server
        session.clear()

    # go to home page
    return redirect(url_for('index'))


# HOME PAGE ----------------------------
@app.route("/")
@std_context
def index():
    # get request context
    context = request.context

    # return posts from database
    context['posts'] = db.query_db(
        'SELECT posts.creator,posts.date,posts.title,posts.content,users.name,users.username '
        'FROM posts JOIN users ON posts.creator=users.userid '
        'ORDER BY date DESC '
        'LIMIT 10'
    )

    # format post created datetime string
    for post in context['posts']:
        post['date'] = datetime.datetime.fromtimestamp(post['date']).strftime('%Y-%m-%d %H:%M')

    return render_template('index.html', **context)


# SIGNUP NEW USER ----------------------
@app.route("/signup/", methods=['GET', 'POST'])
@std_context
def signup():
    if request.method == 'GET':
        return render_template('signup.html', captcha=cap.init_captcha())

    # get form fields from request
    name = request.form['name']
    username = request.form['username']
    password = request.form['password']
    email_address = request.form['email']

    # get captcha from form if selected
    captcha_response = request.form['captcha'] if 'captcha' in request.form else '0'
    # captcha_response = request.form['g-recaptcha-response']

    # check if captcha response is correct
    if not captcha_response == session['captcha']:
        log.log_warning(f'Invalid signup: Reason="Incorrect captcha choice"')
        flash('Incorrect captcha choice', 'warning')
        return render_template('signup.html', name=name, username=username, email_address=email_address,
                               captcha=cap.init_captcha())

    # check if account exists with that username, tell the user that username is taken
    if db.user_exists_by_username(username):
        log.log_warning(f'Signup attempt of existing username: Username={username}')
        flash('That username is taken', 'warning')
        return render_template('signup.html', name=name, username=username, email_address=email_address,
                               captcha=cap.init_captcha())

    # check that the email isn't in use, tell user email has been sent, warn email user of account setup attempt.
    # timing attacks should be mitigated as we are sending an email on successful signup too.
    if db.user_exists_by_email(sec.caesar_cipher("encrypt", email_address)):
        log.log_warning(f'Signup attempt of existing email: EmailAddress={email_address}')
        flash("We've sent you a confirmation email to verify your account", 'success')
        eml.send_suspicious_activity(email_address)
        return redirect(url_for('login'))

    # encrypted fields to insert to db
    encrypted_name = sec.caesar_cipher("encrypt", name)
    encrypted_email = sec.caesar_cipher("encrypt", email_address)

    # generate salt to hash with password and pepper, encrypt output
    account_salt = sec.generate_random_string(64)
    encrypted_password = sec.hash_encrypt_password(password, account_salt)

    # generate verification code for email
    verify_str = db.generate_verification_code()

    # create the account
    db.query_db(
        'INSERT INTO users (name, username, email, password, salt, verify_string) VALUES (?, ?, ?, ?, ?, ?)',
        [encrypted_name, username, encrypted_email, encrypted_password, account_salt, verify_str]
    )
    db.get_db().commit()

    # send email with unique link
    eml.send_verify_account(email_address, verify_str)

    # notify user and redirect to login page
    flash("We've sent you a confirmation email. Please follow the link to activate your account before logging in.",
          'success')
    return redirect(url_for('login'))


# USER POST HISTORY --------------------
@app.route("/users/<username>", methods=['GET'])
@std_context
def users_posts(username=None):
    # get request context
    context = request.context

    # get username from url parameter
    username = sec.html_decode(username)
    context['profile_username'] = username

    # check user exists
    if not db.user_exists_by_username(username):
        log.log_warning(f'Invalid user post access: Reason"User does not exist", Username={username}')

    # return posts from database for user.
    # no error if user doesn't exist, just no posts are returned (helps with account enumeration)
    posts = db.query_db(
        'SELECT p.postid, p.date, p.title, p.content '
        'FROM posts p '
        'JOIN users u ON u.userid = p.creator '
        'WHERE u.username=? '
        'ORDER BY p.date DESC',
        [username]
    )

    # format post created datetime string
    for post in posts:
        post['date'] = datetime.datetime.fromtimestamp(post['date']).strftime('%Y-%m-%d %H:%M')

    return render_template('user_posts.html', posts=posts, csrf_token=sec.generate_csrf(), **context)


# post new message ---------------------
@app.route("/post/", methods=['GET', 'POST'])
@std_context
def new_post():
    # get request context
    context = request.context

    # not logged in: redirect to login page
    if 'userid' not in session:
        log.log_warning(f"Unauthorised page access: Page=\"{url_for('new_post')}\"")
        flash('Please log in before submitting a post.', 'warning')
        return redirect(url_for('login'))

    # show new post page on get request, generate csrf token to store with session and pass to html page
    if request.method == 'GET':
        return render_template('new_post.html', csrf_token=sec.generate_csrf(), captcha=cap.init_captcha(), **context)

    # csrf token invalid, log activity and refresh page to generate new token:
    if session['csrf_token'] != request.form['csrf_token']:
        log.log_warning(f"Invalid request: Reason=\"Invalid CSRF token on form POST\", Page=\"{url_for('new_post')}\"")
        flash('Invalid form submit, please log in again.', 'error')
        return redirect(url_for('new_post'))

    # set post values
    user_id = session['userid']
    date = datetime.datetime.now().timestamp()
    title = request.form.get('title')
    content = request.form.get('content')

    # get captcha from form if selected
    captcha_response = request.form['captcha'] if 'captcha' in request.form else '0'

    # check if captcha response is correct
    if not captcha_response == session['captcha']:
        log.log_warning(f'Invalid new post: Reason="Incorrect captcha choice"')
        flash('Incorrect captcha choice', 'warning')
        return render_template('new_post.html', csrf_token=sec.generate_csrf(), title=title, content=content,
                               captcha=cap.init_captcha(), **context)

    # Finds any URLs in the post and removes the link
    content = re.sub("(http[s]?://)?([a-zA-Z0-9]*[.])+([a-zA-Z0-9]+)([/]?S*)*", "<link removed>", content)

    # insert new post
    db.query_db(
        'INSERT INTO posts (creator, date, title, content) VALUES (?, ?, ?, ?)',
        [user_id, date, title, content]
    )
    db.get_db().commit()

    # log event, notify user and redirect to homepage
    log.log_info(f'User inserted a new post: Title="{title}"')
    flash('Thanks for your post.', 'success')
    return redirect(url_for('index'))


# edit post ---------------------
@app.route("/post/<post_id>", methods=['GET', 'POST'])
@std_context
def edit_post(post_id):
    # get request context
    context = request.context

    # not logged in: redirect to login page
    if 'userid' not in session:
        log.log_warning(f"Unauthorised page access: Page=\"{url_for('delete_post')}\"")
        flash('Please log in before editing a post.', 'warning')
        return redirect(url_for('login'))

    # retrieve post from database (if exists)
    post = db.query_db('SELECT * FROM posts WHERE postid=?', [post_id], False, True)

    # if post doesn't exist, log event, notify user and redirect to previous page
    if len(post) == 0:
        log.log_warning(
            f"Invalid edit request: Reason=\"Record does not exist\", Page=\"{url_for('delete_post')}\"")
        flash('Unable to edit post because it doesn\'t exist', 'error')
        return redirect(request.referrer)

    # show new post page on get request, generate csrf token to store with session and pass to html page
    if request.method == 'GET':
        return render_template('edit_post.html', post=post, csrf_token=sec.generate_csrf(), **context)


# delete post ---------------------
@app.route("/post/delete/<post_id>", methods=['POST'])
@std_context
def delete_post(post_id):
    # not logged in: redirect to login page
    if 'userid' not in session:
        log.log_warning(f"Unauthorised page access: Page=\"{url_for('delete_post')}\"")
        flash('Please log in before deleting a post.', 'warning')
        return redirect(url_for('login'))

    # csrf token invalid, log activity and refresh page to generate new token:
    if session['csrf_token'] != request.form['csrf_token']:
        log.log_warning(
            f"Invalid delete request: Reason=\"Invalid CSRF token on form POST\", Page=\"{url_for('delete_post')}\"")
        flash('Unable to delete post due to an invalid form submission, please log in again.', 'error')
        return redirect(url_for('new_post'))

    # retrieve post from database (if exists)
    post = db.query_db('SELECT * FROM posts WHERE postid=?', [post_id], False, True)

    # if post doesn't exist, log event, notify user and redirect to previous page
    if len(post) == 0:
        log.log_warning(f"Invalid delete request: Reason=\"Record does not exist\", Page=\"{url_for('delete_post')}\"")
        flash('Unable to delete post because it doesn\'t exist', 'error')
        return redirect(request.referrer)

    # if current user isn't post creator, log event, notify user and redirect to previous page
    if post['creator'] != session['userid']:
        log.log_warning(f"Invalid delete request: Reason=\"Insufficient permissions\", Page=\"{url_for('delete_post')}\"")
        flash('Unable to delete post because you do not have the required permissions', 'error')
        return redirect(request.referrer)

    # delete post from database
    db.query_db('DELETE FROM posts WHERE postid=? AND creator=?', [post_id, session['userid']])
    db.get_db().commit()

    # log event, notify and redirect user back to their posts
    log.log_info(f'Post deleted: PostID={post_id}')
    flash('Post successfully deleted.', 'success')
    return redirect(url_for('users_posts', username=session['username']))


# search results -----------------------
@app.route("/search/", methods=['GET', 'POST'])
@std_context
def search_page():
    # get request context
    context = request.context

    # get search query from request
    search = request.args.get('s', '')

    # get posts from database that match query
    posts = db.query_db(
        'SELECT posts.creator, '
        '   posts.title, '
        '   posts.content, '
        '   users.name '
        'FROM posts '
        'JOIN users ON posts.creator = users.userid '
        'WHERE title LIKE (?) '
        'ORDER BY posts.date DESC '
        'LIMIT 10;',
        [search]
    )

    # limit post content to 50 characters and append ...
    for post in posts:
        post['content'] = '%s...' % (post['content'][:50])

    # render page with posts
    return render_template('search_results.html', posts=posts, query=sec.html_encode(search), **context)


# password reset request page ----------
@app.route("/reset/", methods=['GET', 'POST'])
@std_context
def reset():
    # get request context
    context = request.context

    if request.method == 'GET':
        return render_template('reset_request.html', captcha=cap.init_captcha(), **context)

    # get email address from form
    email_addr = request.form.get('email', '')

    # check email address isn't empty
    if email_addr == '':
        log.log_warning('Invalid password reset request: Reason="Empty email address field"')
        flash('Please provide the email address for the account you want to reset the password for.', 'warning')
        return render_template('reset_request.html', captcha=cap.init_captcha(), **context)

    # get captcha from form if selected
    captcha_response = request.form['captcha'] if 'captcha' in request.form else '0'

    # check if captcha response is correct
    if not captcha_response == session['captcha']:
        log.log_warning(f'Invalid password reset: Reason="Incorrect captcha choice"')
        flash('Incorrect captcha choice', 'warning')
        return render_template('reset_request.html', email=email_addr, captcha=cap.init_captcha(), **context)

    # return account using email address
    account = db.user_exists_by_email(email_addr)

    if account:
        # if account exists, generate a reset token and send it via email
        reset_token = db.generate_reset_token(account)
        eml.send_password_reset(email_addr, reset_token)
        log.log_info(f'Successful password reset request: Email={email_addr}, ResetToken={reset_token}')
    else:
        # if account doesn't exist, sleep for 0.5s to simulate an email sent (mitigates timing attacks)
        log.log_info(f'Invalid password reset request: Reason="Email doesn\'t exist", Email={email_addr}')
        sleep(500)

    # notify user an email was sent, even if one wasn't (mitigates account enumeration)
    flash('An email with a reset password link has been send to the address provided.', 'success')
    return redirect(url_for('index'))


# password reset link landing ----------
@app.route("/reset-password/<url_token_id>/", methods=['GET', 'POST'])
@std_context
def reset_password(url_token_id=None):
    if request.method == 'GET':
        user = db.user_exists_by_field('reset_token_id', url_token_id)

        # check if no user with password reset token, remove if token is in reset_tokens, log and redirect
        if not user:
            db.query_db('DELETE FROM reset_tokens WHERE token_id=?', [url_token_id])
            db.get_db().commit()
            log.log_error('Invalid password reset token: No user found with reset_token_id=' + url_token_id)
            flash("Invalid reset password link", "error")
            return redirect('/login/')

        reset_token = db.query_db('SELECT expiry_date FROM reset_tokens WHERE token_id=?', [url_token_id], False)

        # check if no token with reset_token_id, update user if has reset token, log and redirect
        if len(reset_token) == 0:
            db.query_db('UPDATE users SET reset_token_id = NULL WHERE reset_token_id=?', [url_token_id])
            db.get_db().commit()
            log.log_error(f'Invalid password reset token: No reset token found with reset_token_id={url_token_id}')
            flash("Invalid reset password link", "error")
            return redirect('/login/')

        expire_time = datetime.datetime.strptime(reset_token[0]['expiry_date'], "%Y-%m-%d %H:%M:%S.%f")

        # check if token is expired, remove token, update user, log and redirect
        if expire_time < datetime.datetime.now():
            db.query_db('UPDATE users SET reset_token_id = NULL WHERE reset_token_id=?', [url_token_id])
            db.query_db('DELETE FROM reset_tokens WHERE token_id=?', [url_token_id])
            db.get_db().commit()
            log.log_error(f'Invalid password reset token, token expired: reset_token_id={url_token_id}')
            flash('Invalid reset password link, token expired', 'error')
            return redirect('/login/')

        return render_template('new-password.html', path=url_token_id, substring_name=user['name'],
                               substring_username=user['username'])
    else:
        # get the passwords from the form
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirmpassword', '')

        # check to see if passwords match
        if confirm_password != password:
            flash("Passwords don't match", 'warning')
            log.log_error('Invalid password reset:  Reason="Password and password confirmation do not match"')
            return render_template('new-password.html')

        # generate new salt, hash and encrypt password
        account_salt = sec.generate_random_string(64)
        encrypted_password = sec.hash_encrypt_password(password, account_salt)

        # modify the database
        db.query_db('UPDATE users SET password=?, salt = ?, reset_token_id = NULL WHERE reset_token_id=?',
                    [encrypted_password, account_salt, url_token_id])
        db.query_db('DELETE FROM reset_tokens WHERE token_id=?', [url_token_id])
        db.get_db().commit()

        # notify user and redirect to login
        flash('Password successfully changed', 'success')
        return redirect(url_for('login'))


# VERIFY EMAIL ACCOUNT -----------------
@app.route("/verify/<verification_string>/")
@std_context
def verify_account(verification_string=None):
    # check user exists with specified verification string
    user = db.user_exists_by_field('verify_string', verification_string)

    if not user:
        # on failure, log and notify user
        log.log_info(f'Account verification failed: Reason="No user exists with string": {verification_string}')
        flash('Failed to verify account, invalid link', 'error')
    else:
        # on success, verify user, log and notify
        db.query_db('UPDATE users SET verified=1, verify_string=NULL WHERE verify_string=?;', [verification_string])
        db.get_db().commit()
        log.log_info(f"Account verified")
        flash("Your account has been validated!", "info")

    # go to login no matter what happens
    return redirect('/login/')


# RUN APPLICATION --------------------------------------------------------------
if __name__ == '__main__':
    if SITE_MODE == 'live':
        app.run('127.0.0.1', debug=True, port=5000, ssl_context=('cert.pem', 'key.pem'))
    else:
        app.run()
