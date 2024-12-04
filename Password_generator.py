import secrets
import string

def generate_password(length=12, include_upper=True, include_digits=True, include_symbols=True):
    
    if length < 1:
        raise ValueError("Password length must be at least 1.")

    character_pool = string.ascii_lowercase
    required_characters = []

    if include_upper:
        character_pool += string.ascii_uppercase
        required_characters.append(secrets.choice(string.ascii_uppercase))

    if include_digits:
        character_pool += string.digits
        required_characters.append(secrets.choice(string.digits))

    if include_symbols:
        character_pool += string.punctuation
        required_characters.append(secrets.choice(string.punctuation))

    if length < len(required_characters):
        raise ValueError("Password length is too short to include the required character types.")

    remaining_length = length - len(required_characters)
    password = required_characters + [secrets.choice(character_pool) for _ in range(remaining_length)]
    secrets.SystemRandom().shuffle(password)

    return ''.join(password)

def generate_multiple_passwords(count=5, length=12, **kwargs):
    if count < 1:
        raise ValueError("The number of passwords must be at least 1.")
    return [generate_password(length, **kwargs) for _ in range(count)]
