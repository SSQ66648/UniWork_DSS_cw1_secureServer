from flask import session
from helpers import database as db


def __create_log(log_type, event_description):
    # get userid if logged in, otherwise set to 0
    user_id = session['userid'] if 'userid' in session else 0

    # insert event into database
    db.query_db(
        'INSERT INTO event_log (event_log_type_id, event_description, user_id)'
        'VALUES (?, ?, ?);',
        [log_type, event_description, user_id]
    )

    # commit database changes
    db.get_db().commit()


def log_info(event):
    # function to create information events
    __create_log('Information', event)


def log_warning(event):
    # function to create warning events
    __create_log('Warning', event)


def log_error(event):
    # function to create error events
    __create_log('Error', event)