import sqlite3
from flask import g
import winreg
import string
import datetime
from helpers import security as sec

DATABASE = 'database.sqlite'
PEPPER_REG_PATH = r"SOFTWARE\dss-forum"
PEPPER_REG_NAME = 'database_pepper'


# return the database password pepper string which is stored in the windows registry
def get_password_pepper():
    try:
        # open registry key
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, PEPPER_REG_PATH, 0,
                                      winreg.KEY_READ)
        # read the registry pepper value
        value, regtype = winreg.QueryValueEx(registry_key, PEPPER_REG_NAME)

        # close registry key and return value
        winreg.CloseKey(registry_key)
        return value
    except WindowsError:
        # return nothing on error
        return None


# DATABASE CONNECTION
def get_db():
    # check global flask database exists, create if not
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)

    def make_dicts(cursor, row):
        return dict((cursor.description[idx][0], value)
                    for idx, value in enumerate(row))
    db.row_factory = make_dicts

    # return database object
    return db


def close_db():
    # close global database connection if exists
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


# SQL QUERY FUNCTION
def query_db(query, args=(), xss_escape=True, one=False):
    # execute SQL query with arguments
    cur = get_db().execute(query, args)

    # fetch results and close query
    rv = cur.fetchall()
    cur.close()

    # escape special characters
    if xss_escape:
        sec.escape_db(rv)

    # return results array (or first result as object)
    return (rv[0] if rv else None) if one else rv


# User account functions
def user_exists_by_field(field_name, value):
    # return single user record by checking specified field name with value
    user = query_db(
        f"SELECT * FROM users WHERE {field_name}=?;",
        [value],
        False,  # xss_escape
        True  # one record
    )

    # return user object or false if not exists
    return user if user else False


# wrapper function for user_exists_by_field, predefine email as field_name
def user_exists_by_email(email):
    return user_exists_by_field('email', sec.caesar_cipher('encrypt', email))


# wrapper function for user_exists_by_field, predefine username as field_name
def user_exists_by_username(username):
    return user_exists_by_field('username', username)


# generate random + unique account verification code
def generate_verification_code():
    while True:
        # generate random string
        random_string = sec.generate_random_string(64, [string.ascii_letters, string.digits])

        # check if verification string already assigned (very very unlikely but low cost to check)
        if not user_exists_by_field('verify_string', random_string):
            return random_string


# generate random + unique password reset token
def generate_reset_token(user_account):
    while True:
        # generate reset token
        reset_token = sec.generate_random_string(64, [string.ascii_letters, string.digits])

        # check if token doesn't exist
        if len(query_db('SELECT token_id FROM reset_tokens WHERE token_id=?;', [reset_token])) == 0:
            break

    # define expiry time for T+15 minutes
    expire_time = datetime.datetime.now() + datetime.timedelta(minutes=15)

    # delete any existing tokens for user
    if user_account['reset_token_id'] is not None:
        query_db('DELETE FROM reset_tokens WHERE token_id=?', [user_account['reset_token_id']])

    # insert reset token and link to user account
    query_db('INSERT INTO reset_tokens (token_id, expiry_date) VALUES (?,?)', [reset_token, expire_time])
    query_db('UPDATE users SET reset_token_id=? WHERE userid=?', [reset_token, user_account['userid']])
    get_db().commit()

    # return token string
    return reset_token
