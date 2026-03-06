import pwnedpasswords
import math
import string
import sys
import secrets
import urllib
import argparse

def main():

    parser = argparse.ArgumentParser (
        description = "A tool that generates passwords or audits the strength of existing ones")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--generate", action="store_true", help="Generate a new password")
    group.add_argument("--audit", action="store_true", help="Audit a passwords strength")

    args = parser.parse_args()

    if args.generate:

        generated_pass, generated_strength = generate_password(input("Target score: "))
        print(f"Generated password: {generated_pass}\nPassword strength: {generated_strength}%")

    elif args.audit:

        password, pwnd = get_password()
        print(f"Password strength: {round(calculate_score(password)) * int(not pwnd)}%")

    return


def get_password():

    while True:
        password = input("Password (8 to 32 characters): ")
        if len(password) < 8:
            print("Password too short")

        elif len(password) > 32:
            print("Password too long")

        else:
            break

    try:
        validate_character_set(password)

    except ValueError:
        sys.exit()

    try:
        if pwnd := pwnedpasswords.check(password):
            print("WARNING: Password found in database breach")

    except urllib.error.URLError:
        sys.exit("Network error")

    return password, pwnd


def validate_character_set(password):

    allowed = string.printable

    for c in password:
        if c not in allowed:
            print(f"Invalid character detected --> {c} <--")
            raise ValueError

    return


def get_entropy(password):

    # Max possible entropy is 32 * log(2) of 94 which is roughly 209, min is 2
    l = len(password)
    pool = 0
    if any(c in string.digits for c in password):
        pool += 10
    if any(c in string.ascii_lowercase for c in password):
        pool += 26
    if any(c in string.ascii_uppercase for c in password):
        pool += 26
    if any(c in string.punctuation for c in password):
        pool += 32

    # Normalizing to 0 - 100
    return round(100 * ((l * math.log(pool, 2)) / 209.0))


def scan_patterns(password):

    match_count = 0
    try:
        with open("passwords.txt", "r") as file:
            common_passwords = [line.strip() for line in file]

    except FileNotFoundError:
        sys.exit("Common passwords file missing")

    p = password.lower()
    for word in common_passwords:
        if p in word or word in p:
            match_count += 1

    return match_count


def scan_uniqueness(password):

    unique_chars = len(set(password))
    total_chars = len(password)

    ratio = float(unique_chars / total_chars)
    # Remapping the linear range to a hyberbolic tangent one for more accurate rating
    uniqueness = (math.tanh(5 * (ratio - 0.25)) + 1) / 2

    return uniqueness


def calculate_score(password):

    entropy = get_entropy(password)
    pattern = scan_patterns(password)
    uniqueness = scan_uniqueness(password)

    # Formula derived by trial and error, follows KeePassXC password strength checker closely
    return max(0, (entropy - 5 * pattern) * uniqueness)


def generate_password(target_score: float):

    # Generates random password with strength within 10% of the target score, will not generate below 20%
    try:
        target_score = float(target_score.strip().replace("%", ""))

    except ValueError:
        sys.exit("Invalid input, target must be int or float")

    if target_score < 25 or target_score > 100:
        sys.exit("Invalid input, target score max is 100%, min is 25%")

    if target_score <= 35:
        characters = string.ascii_letters

    elif 35 < target_score < 55:
        characters = string.ascii_letters + string.digits

    # If target score is equal to or greater than 55 include all allowed characters
    else:
        characters = string.ascii_letters + string.digits + string.punctuation


    while True:
        # Introduces minimum generatable length of 3, from which it scales linearly to
        # 32 based on target score, in practice will never generate a 3 character password
        # because target score is limited to 20% minimum
        length = int(29 * target_score/100) + 3

        candidate = ""
        for _ in range(length):
            candidate += secrets.choice(characters)

        score = calculate_score(candidate)
        if (0.9 * target_score) <= score <= min(1.1 * target_score, 100):
            try:
                if not pwnedpasswords.check(candidate):
                    return candidate, round(score)
            except urllib.error.URLError:
                sys.exit("Network error")


if __name__ == "__main__":
    main()
