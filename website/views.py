from flask import Blueprint, render_template, request, flash, redirect, url_for
import random
import re  # Import the regular expression module for password strength check

views = Blueprint("views", __name__)

def generate_password(num_passwords, pwlength, categories, keyword=None, keyword_position=None):
    alphabet = ''
    if categories.get('text', False):
        alphabet += 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
    if categories.get('number', False):
        alphabet += '0123456789'
    if categories.get('special', False):
        alphabet += '!@#$%^&*()_+-=[]{}|;:,.<>?/'

    # If none of the categories are selected, include all of them by default
    if not any(categories.values()):
        alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?/'

    passwords = []

    for _ in range(num_passwords):
        remaining_length = pwlength

        if keyword:
            remaining_length -= len(keyword)
        
        if remaining_length <= 0:
            password = keyword if keyword else ''
        else:
            random_chars = ''.join(random.choice(alphabet) for _ in range(remaining_length))

            if keyword and keyword_position:
                if keyword_position == 'front':
                    password = keyword + random_chars
                elif keyword_position == 'behind':
                    password = random_chars + keyword
                elif keyword_position == 'between':
                    index = random.randrange(remaining_length)
                    password = random_chars[:index] + keyword + random_chars[index:]
                else:
                    raise ValueError("Invalid keyword position")
            else:
                password = random_chars

        passwords.append(password)

    return passwords

def check_password_strength(password):
    # Define criteria for a strong password
    length_criteria = 8
    uppercase_criteria = r'[A-Z]'
    lowercase_criteria = r'[a-z]'
    number_criteria = r'\d'
    special_char_criteria = r'[!@#$%^&*()_+-=[]{}|;:,.<>?/]'

    # Check length
    if len(password) < length_criteria:
        return "Weak: Password should be at least {} characters long.".format(length_criteria)

    # Check uppercase letters
    if not re.search(uppercase_criteria, password):
        return "Weak: Password should contain at least one uppercase letter."

    # Check lowercase letters
    if not re.search(lowercase_criteria, password):
        return "Weak: Password should contain at least one lowercase letter."

    # Check numbers
    if not re.search(number_criteria, password):
        return "Weak: Password should contain at least one number."

    # Check special characters
    if not re.search(special_char_criteria, password):
        return "Weak: Password should contain at least one special character."

    # If all criteria are met, consider the password strong
    return "Strong: Password meets all criteria."

@views.route("/", methods=["GET", "POST"])
def genpass():
    if request.method == "POST":
        pwnums = request.form.get("pwnums")
        pwlength = request.form.get("pwlength")
        keyword = request.form.get("keyword")
        keyword_position = request.form.get("keyword_position")

        include_text = request.form.get("text") == "on"
        include_number = request.form.get("number") == "on"
        include_special = request.form.get("special") == "on"

        # Include all character sets by default if none are selected
        if not any([include_text, include_number, include_special]):
            include_text = include_number = include_special = True

        if not pwnums or not pwlength:
            flash("Please fill out all required fields.", category="error")
        elif not pwnums.isdigit() or not pwlength.isdigit():
            flash("Please enter valid positive integers for Numbers of Passwords and Password Length.", category="error")
        elif int(pwlength) <= 0 or int(pwnums) <= 0:
            flash("Please enter valid positive integers for Numbers of Passwords and Password Length.", category="error")
        else:
            flash("Passwords generated", category="success")

            categories = {
                'text': include_text,
                'number': include_number,
                'special': include_special,
            }

            passwords = generate_password(int(pwnums), int(pwlength), categories, keyword, keyword_position)

            # Check the strength of each password
            strength_messages = [check_password_strength(password) for password in passwords]

            return render_template('generatedpw.html', passwords=passwords, strength_messages=strength_messages)

    return render_template("genpass.html")

@views.route("/generatedpw", methods=["GET", "POST"])
def generatedpw():
    passwords = request.args.getlist("passwords")

    # Ensure each password is a string
    passwords = [''.join(password) for password in passwords]

    if request.method == "POST":
        # Clear the form by redirecting back to the genpass route
        return redirect(url_for('views.genpass'))

    return render_template("generatedpw.html", passwords=passwords)
