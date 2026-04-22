# configuration
import re
import math

## 1 user password input
def get_password():
    password = input("Enter your password: ")
    return password

## 2 Check password length
def check_length(password):          ## checks the length
    if len(password) < 8:            ## if it is less than 8
        return "Too short"
    return "Good length"

## 3 Checks password character variety(lower & upper case, numbers, symbols)
def check_characters(password):
    checks = {
        "lower": bool(re.search(r"[a-z]", password)), ## checks for atleast 1 lower case letter
        "upper": bool(re.search(r"[A-Z]", password)), ## checks for atleast 1 upper case letter
        "digit": bool(re.search(r"\d", password)),    ## checks for at least 1 numerical digit(0-9)
        "symbol": bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)) ## checks for any of the listed symbols
    }
    return checks

## 4 Detect common patterns (for catching commonly used weak stuff like: "123, abc")
def check_patterns(password):
    patterns = []

    if "123" in password:
        patterns.append("Cntains sequence 123") ## checks for presence of 123

    if "abc" in password.lower():
        patterns.append("Contains sequence abc") ## checks for presence of abc *lowercase
        
    if re.search(r"(.)\1{2}", password):
        patterns.append("repeated characters") ## checks for repeated characters using a regular expression

    return patterns ## returns identified weak patterns

## 5 check common passwords
common_passwords = ["password", "123456", "password123", "qwerty", "admin"] ## common passwords

def check_common(password):
    if password.lower() in common_passwords: ## changes password to lower case and checks if it is in the common passwords list
        return "common password"
    return "unique"

## 6 add entropy
def calculate_entropy(password):
    pool = 0

    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"\d", password):
        pool += 10
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        pool += 32

    if pool == 0:
        return 0
    
    entropy = len(password) * math.log2(pool)
    return round(entropy, 2)

## 7 Combines everything into a score
def evaluate_password(password):
    score = 0
    feedback = []

    # Length
    if len(password) >= 8:
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

    

if __name__ == "__main__":
    main()

# Main code
#if __name__ == "__main__": 
    ## @1 displays entered password
#    pwd = get_password()             ## entered password is saved val pwd
#    print("Password entered: ", pwd) ## entered password is displayed

## @2 checks password length  
#print (check_length(pwd))

## @3 checks character variety
#print (check_characters(pwd))

## @4 checks common patterns
# print (check_patterns(pwd))  dont need to include because it will return [] for false

## @5 checks common passwords
#print (check_common(pwd))

## @6 
