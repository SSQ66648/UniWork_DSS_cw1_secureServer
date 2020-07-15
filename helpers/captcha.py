import string
import random
from flask import session
import helpers.security as sec


def init_captcha():
    boxes = [["one", "1"], ["two", "2"], ["three", "3"]]
    for box in boxes:
        box[0] = sec.generate_random_string(64, string.ascii_letters + string.digits)

    selected_pic = random.randint(0, 2)
    session['captcha'] = boxes[selected_pic][0]

    random.shuffle(boxes)

    return [boxes, f"Select number {selected_pic + 1}"]