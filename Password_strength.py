import string

def evaluate_password_strength(password):
    """
    Evaluates the strength of a password.

    Args:
        password (str): Password to evaluate.

    Returns:
        str: Strength of the password ("Weak", "Moderate", "Strong", "Very Strong").
    """
    if not password:
        raise ValueError("Password cannot be empty.")

    criteria = {
        "length": len(password) >= 8,
        "uppercase": any(c.isupper() for c in password),
        "digit": any(c.isdigit() for c in password),
        "symbol": any(c in string.punctuation for c in password),
    }

    strength_score = sum(criteria.values())
    if strength_score == 4 and len(password) >= 12:
        return "Very Strong"
    elif strength_score == 4:
        return "Strong"
    elif strength_score == 3:
        return "Moderate"
    else:
        return "Weak"

def provide_feedback(criteria):
    """
    Provides feedback for weak passwords.

    Args:
        criteria (dict): Criteria for password strength.

    Returns:
        list: Suggestions for improving the password.
    """
    feedback = []
    if not criteria["length"]:
        feedback.append("Password should be at least 8 characters long.")
    if not criteria["uppercase"]:
        feedback.append("Include at least one uppercase letter.")
    if not criteria["digit"]:
        feedback.append("Include at least one digit.")
    if not criteria["symbol"]:
        feedback.append("Include at least one symbol.")
    return feedback
