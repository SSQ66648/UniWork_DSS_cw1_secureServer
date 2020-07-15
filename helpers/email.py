import smtplib
from flask import url_for
import helpers.security as sec


def send_email(recipiant, subject, message):
    # might want to put that in a try catch statement
    server = smtplib.SMTP('smtp.gmail.com', 587)

    # create message
    mess = "From: Donotreply  <DSS_donotreply@gmail.com>\nTo: "
    # add contense of message
    mess = mess + recipiant + "\nSubject: " + subject + "\n\n" + message

    # Next, log in to the server
    server.ehlo()
    server.starttls()
    server.login("DSSCW12020@gmail.com", "9a&1E6T3dU%&NBdo")

    # Send the mail
    # msg = "Subject{}\n\n{}".format("test Subject", "test message")
    server.sendmail("DSS_donotreply@gmail.com", recipiant, mess)
    server.quit()


def send_suspicious_activity(email_address):
    send_email(
        email_address,
        f'Suspicious activity',
        'Someone has tried to create an account with your email.'
        '\nIf this was you don\'t worry but you might want to change your password.'
        f"\nFollow this link to reset your password: {url_for('reset', _external=True)}"
    )


def send_verify_account(email_address, verify_string):
    send_email(
        email_address,
        'Please verify your account',
        f"Please click the link to verify your account: {url_for('verify_account', verification_string=verify_string, _external=True)}"
    )


def send_password_reset(email_address, reset_token):
    send_email(
        email_address,
        "Password Reset",
        f"Click the link to reset your password: {url_for('reset_password', url_token_id=reset_token, _external=True)}"
        f"\nNote: this link will only work for 15 minutes after this email is sent."
    )