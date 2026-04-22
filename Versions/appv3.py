# ================================
# PWD – Password Weakness Detector
# Backend (Flask API)
# ================================

# ----------- Imports ------------
# Flask: web framework
from flask import Flask, request, jsonify, render_template

# zxcvbn: password strength estimation
from zxcvbn import zxcvbn

# Levenshtein: similarity comparison between strings
import Levenshtein

# Cryptographic & security utilities
import hashlib
import secrets
import string
import requests

# NLP for dictionary word detection
import spacy


# ----------- App Setup -----------
# Initialize Flask application
app = Flask(__name__)

# Load spaCy English language model
# Used to detect dictionary-like words inside passwords
nlp = spacy.load("en_core_web_sm")


# =========================================================
# 1. Breach Detection (Have I Been Pwned – k-anonymity)
# =========================================================
def pwned_count(password):
    """
    Checks whether a password has appeared in known data breaches.
    Uses the Have I Been Pwned API with k-anonymity.
    Returns:
        - number of times found in breaches
        - 0 if never found
        - -1 if API error
    """
    try:
        # SHA1 hash of password (required by HIBP API)
        sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]

        # Query only by prefix (privacy-preserving)
        response = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}"
        )

        if response.status_code != 200:
            return -1

        # Search for matching suffix
        for line in response.text.splitlines():
            hash_suffix, count = line.split(":")
            if hash_suffix == suffix:
                return int(count)

        return 0

    except Exception:
        return -1


# =========================================================
# 2. Dictionary / NLP Detection
# =========================================================
def detect_dictionary_words(password):
    """
    Uses spaCy NLP to detect alphabetic words
    that look like real dictionary terms.
    """
    words = []
    doc = nlp(password.lower())

    for token in doc:
        if token.is_alpha and len(token.text) >= 3:
            words.append(token.text)

    return list(set(words))


# =========================================================
# 3. AI-style Suggestions (Rule-Based Intelligence)
# =========================================================
def ai_suggestions(score, similarity, breach_count, dict_words):
    """
    Generates human-readable suggestions
    explaining why a password is weak and how to improve it.
    """
    suggestions = []

    if score < 3:
        suggestions.append("Increase password length and randomness.")

    if similarity > 0.6:
        suggestions.append("Avoid reusing or slightly modifying old passwords.")

    if breach_count > 0:
        suggestions.append("This password has appeared in known data breaches.")

    if dict_words:
        suggestions.append(
            "Avoid common dictionary words: " + ", ".join(dict_words)
        )

    if not suggestions:
        suggestions.append("This password is strong. No major issues detected.")

    return suggestions


# =========================================================
# 4. Secure Password Generator
# =========================================================
def generate_password(length=16):
    """
    Generates a cryptographically secure password
    using letters, numbers, and symbols.
    """
    characters = (
        string.ascii_letters +
        string.digits +
        "!@#$%^&*()-_=+[]{}"
    )

    return "".join(secrets.choice(characters) for _ in range(length))

# =========================================================
# 4.5 Strength Label Helper
# =========================================================
def strength_label(score):
    """
    Converts zxcvbn score (0–4) into a human-readable label
    used by the frontend for visual display.
    """
    labels = {
        0: "Very Weak",
        1: "Weak",
        2: "Fair",
        3: "Strong",
        4: "Very Strong"
    }
    return labels.get(score, "Unknown")


# =========================================================
# 4.6 Entropy Explanation Helper
# =========================================================
def entropy_explanation(entropy):
    """
    Explains password entropy (log10 guesses) in plain English
    so non-technical users understand the risk.
    """
    if entropy < 5:
        return "Can be cracked almost instantly."
    elif entropy < 8:
        return "Can be cracked in seconds or minutes."
    elif entropy < 10:
        return "Can be cracked within hours."
    elif entropy < 12:
        return "Would take days to crack."
    elif entropy < 14:
        return "Would take months to crack."
    else:
        return "Would take years to crack with modern hardware."

# =========================================================
# 5. Routes
# =========================================================

# ---------- Home Route ----------
@app.route("/")
def home():
    """
    Basic sanity check endpoint.
    """
    return render_template("index.html")
    
    


# ---------- Analyze Password ----------
@app.route("/analyze", methods=["POST"])
def analyze():
    """
    Core analysis endpoint.
    Accepts:
        {
            "password": "...",
            "previous": "..." (optional)
        }
    Returns full PWD analysis.
    """
    data = request.get_json()

    password = data.get("password")
    previous = data.get("previous", "")

    if not password:
        return jsonify({"error": "Password is required"}), 400

    # --- zxcvbn analysis ---
    analysis = zxcvbn(password)
    score = analysis["score"]
    entropy = analysis["guesses_log10"]
    strength = strength_label(score)
    entropy_text = entropy_explanation(entropy)

    # --- Similarity to previous password ---
    similarity = 0
    if previous:
        similarity = round(Levenshtein.ratio(password, previous), 2)

    # --- Breach detection ---
    breach_count = pwned_count(password)

    # --- Dictionary word detection ---
    dict_words = detect_dictionary_words(password)

    # --- AI-style recommendations ---
    suggestions = ai_suggestions(
        score,
        similarity,
        breach_count,
        dict_words
    )

    # --- Final response ---
    return jsonify({
        "score": score,
        "strength_label": strength,
        "entropy": entropy,
        "entropy_explanation": entropy_text,
        "similarity": similarity,
        "breach_count": breach_count,
        "dictionary_warnings": dict_words,
        "ai_suggestions": suggestions
    })


# ---------- Generate Password ----------
@app.route("/generate", methods=["GET"])
def generate():
    """
    Generates a strong password automatically.
    """
    length = int(request.args.get("length", 16))
    password = generate_password(length)

    return jsonify({
        "generated_password": password
    })


# =========================================================
# 6. App Entry Point
# =========================================================
if __name__ == "__main__":
    # Debug enabled for development only
    app.run(debug=False)
