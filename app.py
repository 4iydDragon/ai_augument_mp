# ================================
# PWD – Password Weakness Detector
# Backend (Flask API)
# ================================

# ----------- Imports ------------
from flask import Flask, request, jsonify, render_template
from zxcvbn import zxcvbn
import Levenshtein
import hashlib
import secrets
import string
import requests
import re

# Rate limiting  (FIX #5)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


# ----------- App Setup -----------
app = Flask(__name__)

# =========================================================
# Rate Limiter Setup  (FIX #5)
# =========================================================
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# =========================================================
# Simple word set for dictionary detection  (FIX #2)
# Replaces spaCy — far more reliable for password strings
# =========================================================
COMMON_WORDS = {
    "password", "pass", "word", "admin", "user", "login", "welcome",
    "hello", "monkey", "dragon", "master", "shadow", "sunshine", "princess",
    "football", "baseball", "soccer", "hockey", "batman", "superman",
    "qwerty", "letmein", "iloveyou", "trustno", "starwars",
    "michael", "jessica", "charlie", "donald", "thomas", "george",
    "summer", "winter", "spring", "autumn", "flower", "music", "secret",
    "cheese", "butter", "cookie", "coffee", "hunter", "silver", "golden",
    "black", "white", "green", "blue", "purple", "orange", "yellow", "red",
}


# =========================================================
# 1. Breach Detection (Have I Been Pwned – k-anonymity)
# =========================================================
def pwned_count(password):
    """
    Checks whether a password has appeared in known data breaches.
    Uses k-anonymity: only the first 5 SHA1 chars are sent.
    Returns count of breach appearances, 0 if clean, -1 on error.
    """
    try:
        sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]

        response = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            timeout=5
        )

        if response.status_code != 200:
            return -1

        for line in response.text.splitlines():
            hash_suffix, count = line.split(":")
            if hash_suffix == suffix:
                return int(count)

        return 0

    except Exception:
        return -1


# =========================================================
# 2. Dictionary Word Detection  (FIX #2)
# =========================================================
def detect_dictionary_words(password):
    """
    Detects common dictionary words embedded in the password.
    Checks both the raw password and a stripped (alpha-only) version
    to catch substitutions like p@ssword -> pssword.
    spaCy removed: it tokenises poorly on non-prose strings.
    """
    password_lower = password.lower()
    stripped = re.sub(r"[^a-z]", "", password_lower)
    found = []

    for word in COMMON_WORDS:
        if word in password_lower or word in stripped:
            found.append(word)

    return list(set(found))


# =========================================================
# 3. Rule-Based Suggestions
# =========================================================
def build_suggestions(score, similarity, breach_count, dict_words):
    """
    Returns human-readable improvement suggestions.
    Rule-based (not AI-powered — name preserved for API compatibility).
    """
    suggestions = []

    if score < 3:
        suggestions.append("Increase password length and add more varied characters.")

    if similarity is not None and similarity > 0.6:
        suggestions.append("Avoid reusing or slightly modifying old passwords.")

    if breach_count > 0:
        suggestions.append(
            f"This password appeared in {breach_count:,} known breach(es) — change it immediately."
        )

    if dict_words:
        suggestions.append(
            "Avoid common dictionary words: " + ", ".join(dict_words)
        )

    if not suggestions:
        suggestions.append("This password is strong. No major issues detected.")

    return suggestions


# =========================================================
# 4. Secure Password Generator  (FIX #1 — mode support)
# =========================================================
def generate_password(mode="balanced"):
    """
    Generates a cryptographically secure password.

    Modes:
        balanced   – 16 chars, letters + digits + light symbols
        memorable  – 20 chars, letters + digits only (easier to type)
        strong     – 24 chars, full character set (maximum entropy)
    """
    if mode == "memorable":
        characters = string.ascii_letters + string.digits
        length = 20
    elif mode == "strong":
        characters = (
            string.ascii_letters
            + string.digits
            + "!@#$%^&*()-_=+[]{}|;:,.<>?"
        )
        length = 24
    else:  # balanced
        characters = (
            string.ascii_letters
            + string.digits
            + "!@#$%^&*()-_=+[]{}"
        )
        length = 16

    return "".join(secrets.choice(characters) for _ in range(length))


# =========================================================
# 5. Strength Label Helper
# =========================================================
def strength_label(score):
    labels = {0: "Very Weak", 1: "Weak", 2: "Fair", 3: "Strong", 4: "Very Strong"}
    return labels.get(score, "Unknown")


# =========================================================
# 6. Entropy Explanation Helper  (FIX #4)
# =========================================================
def entropy_explanation(guesses_log10):
    """
    Converts zxcvbn's guesses_log10 into a plain-English crack-time estimate.

    Calibrated for offline attacks at ~10^10 guesses/sec:
        < 6   → instant           (< 1 million guesses)
        < 8   → seconds           (< 100 million)
        < 10  → minutes/hours     (< 10 billion)
        < 13  → days/weeks        (< 10 trillion)
        < 16  → months/years
        >= 16 → practically uncrackable
    """
    if guesses_log10 < 6:
        return "Can be cracked almost instantly."
    elif guesses_log10 < 8:
        return "Can be cracked in seconds."
    elif guesses_log10 < 10:
        return "Could be cracked within minutes to hours."
    elif guesses_log10 < 13:
        return "Would take days to weeks to crack."
    elif guesses_log10 < 16:
        return "Would take months to years to crack."
    else:
        return "Practically uncrackable with modern hardware."


# =========================================================
# 7. Routes
# =========================================================

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
@limiter.limit("30 per minute")  # FIX #5
def analyze():
    """
    Core analysis endpoint.
    Body: { "password": "...", "previous": "..." (optional) }
    """
    data = request.get_json()
    password = data.get("password", "")
    previous = data.get("previous", "")

    if not password:
        return jsonify({"error": "Password is required"}), 400

    # FIX #6 — cap input length to prevent abuse
    if len(password) > 256:
        return jsonify({"error": "Password must be 256 characters or fewer"}), 400

    # zxcvbn analysis
    analysis = zxcvbn(password)
    score = analysis["score"]
    entropy = analysis["guesses_log10"]

    # FIX #3 — return null when no previous password so frontend
    # can distinguish "no comparison" from "0% similar"
    similarity = None
    if previous:
        similarity = round(Levenshtein.ratio(password, previous), 2)

    breach_count = pwned_count(password)
    dict_words = detect_dictionary_words(password)

    suggestions = build_suggestions(
        score,
        similarity,
        breach_count,
        dict_words
    )

    return jsonify({
        "score": score,
        "strength_label": strength_label(score),
        "entropy": entropy,
        "entropy_explanation": entropy_explanation(entropy),
        "similarity": similarity,        # null when no previous supplied
        "breach_count": breach_count,
        "dictionary_warnings": dict_words,
        "ai_suggestions": suggestions
    })


@app.route("/generate", methods=["GET"])
@limiter.limit("20 per minute")  # FIX #5
def generate():
    """
    Generates a secure password.
    Param: mode = balanced | memorable | strong  (FIX #1)
    """
    mode = request.args.get("mode", "balanced")
    if mode not in ("balanced", "memorable", "strong"):
        mode = "balanced"

    return jsonify({"generated_password": generate_password(mode)})


# =========================================================
# 8. Entry Point
# =========================================================
if __name__ == "__main__":
    app.run(debug=False)