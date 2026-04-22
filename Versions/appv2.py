# configuration
import re
import math
import string
from zxcvbn import zxcvbn
from getpass import getpass

common_passwords = {"password", "123456", "password123", "qwerty", "admin"} ## common passwords

## 1 user password input
def get_password():
    password = getpass("Enter your password: ")
    return password

## 2 Check password length
def check_length(password):          ## checks the length
    return len(password) >= 8         ## if it is less than 8

## checks if password has symbols
def has_symbol(password):
    return any(ch in string.punctuation for ch in password)
## 3 Checks password character variety(lower & upper case, numbers, symbols)
def check_characters(password):
    checks = {
        "lower": bool(re.search(r"[a-z]", password)), ## checks for atleast 1 lower case letter
        "upper": bool(re.search(r"[A-Z]", password)), ## checks for atleast 1 upper case letter
        "digit": bool(re.search(r"\d", password)),    ## checks for at least 1 numerical digit(0-9)
        "symbol": has_symbol(password) ## checks for any of the listed symbols
    }
    return checks

## 4 Detect common patterns (for catching commonly used weak stuff like: "123, abc")
def check_patterns(password):
    patterns = []

    if "123" in password:
        patterns.append("Contains sequence 123") ## checks for presence of 123

    if "abc" in password.lower():
        patterns.append("Contains sequence abc") ## checks for presence of abc *lowercase
        
    if re.search(r"(.)\1{2}", password):
        patterns.append("Contains repeated characters") ## checks for repeated characters using a regular expression

    return patterns ## returns identified weak patterns

## 5 check common passwords


def check_common(password):
    return password.lower() in common_passwords ## changes password to lower case and checks if it is in the common passwords list
        
## 6 add entropy
def calculate_entropy(password):
    pool = 0
    
    chars = check_characters(password)
    if chars["lower"]:
        pool += 26
    if chars["upper"]:
        pool += 26
    if chars["digit"]:
        pool += 10
    if chars["symbol"]:
        pool += len(string.punctuation)

    if pool == 0:
        return 0
    
    entropy = len(password) * math.log2(pool)
    return round(entropy, 2)

## 7 Combines everything into a score
def evaluate_password(password):
    score = 0
    feedback = []


    # Length
    if check_length(password):
        score += 1
    else:
        feedback.append("Password is too short")

    # Character variety
    chars = check_characters(password)
    score += sum(chars.values())
    
    # Patterns
    patterns = check_patterns(password)
    if patterns:
        feedback.extend(patterns)
        score -= len(patterns)

    # Common password
    if check_common(password):
        feedback.append("Common password detected")
        score -= 2

    return score, feedback

def main():
    password = get_password()

    entropy = calculate_entropy(password)
    score, feedback = evaluate_password(password)

    print("\n--- Results ---")
    print("Entropy:", entropy)
    print("Score:", score)

    if score <= 2:
        print("Strength: Weak")
    elif score <= 4:
        print("Strength: Medium")
    else:
        print("Strength: Strong")

    if feedback:
        print("\nIssues:")
        for f in feedback:
            print("-", f)

    result = zxcvbn(password)
    print("\n--- zxcvbn Analysis ---")
    print("Score (0-4):", result["score"])
    print("Feedback:", result["feedback"]["warning"])

    for suggestion in result["feedback"]["suggestions"]:
        print("-", suggestion)

if __name__ == "__main__":
    main()
