# ai_augument_mp
files
app.py              # main applicaltion file
launch.txt          # creation of env and requirements and launch
run_amp.bat         # starts the application in windows
git_push            # github commits and pushing
README.md           # info about the project

# AI-Augumented Password Manager (APM)

A web-based password analysis and generation tool designed to evaluate password strength using industry-standard techniques, breach intelligence, and human-readable feedback.

This project was developed as part of an academic dissertation focused on **usable security**, **password hygiene**, and **human-centred security design**.

---

## Project Overview

The AI-Augumented Password Manager (APM) is a Flask-based web application that allows users to:

- Analyse the strength of a password
- Detect similarity to a previously used password
- Check whether a password has appeared in known data breaches
- Receive clear, actionable improvement suggestions
- Generate secure passwords using multiple strength modes

The system prioritises clarity for non-technical users while maintaining cryptographic correctness.

---

## Key Features

### Password Strength Analysis
- Uses the **zxcvbn** password strength estimator
- Provides a numeric score (0–4) and descriptive label:
  - Very Weak
  - Weak
  - Fair
  - Strong
  - Very Strong

### Breach Detection (k-Anonymity)
- Integrates with the *Have I Been Pwned* API
- Uses SHA-1 prefix hashing (k-anonymity model)
- The plaintext password is never transmitted or stored

### Dictionary Word Detection
- Detects common embedded words such as:
  - password
  - admin
  - qwerty
- Handles basic substitutions (e.g. `p@ssword` → `pssword`)
- Uses a lightweight custom word list rather than NLP models

### Password Similarity Detection
- Uses **Levenshtein distance**
- Warns users if new passwords closely resemble previous ones

### Secure Password Generation
Three generation modes are supported:

- **Balanced** – good security with usability
- **Memorable** – longer, easier to remember
- **Strong** – maximum length and symbol usage

### Human-Readable Security Feedback
- Internal security metrics are translated into plain-English crack-resistance explanations
- Prevents exposure of unnecessary technical values such as logarithmic units

### Rate Limiting and Abuse Protection
- Implemented using **Flask-Limiter**
- Protects sensitive endpoints from brute-force and automated abuse

---

## Technology Stack

### Backend
- Python 3
- Flask
- zxcvbn
- Have I Been Pwned API
- Flask-Limiter

### Frontend
- HTML
- CSS
- JavaScript (Fetch API)
- Client-side usability features (visibility toggle, clipboard copy)

---

## Project Structure

├── app.py
├── templates/
│   └── index.html
├── requirements.txt
└── README.md

---

## Installation and Setup

### 1. Create and activate a virtual environment

python -m venv .venv
.venv\Scripts\activate

### 2. Install dependencies
python -m pip install --upgrade pip
python -m pip install flask zxcvbn-python python-Levenshtein requests flask-limiter

Alternatively:

pip install -r requirements.txt

---

## Running the Application

1 launching  run_amp.bat on windows or running python app.py on terminal
2 Open a browser and navigate to: http://127.0.0.1:5000

---

## API Endpoints

### POST /analyze

Analyses a password and returns security feedback.

Request body:
{
"password": "ExamplePassword123!",
"previous": "OptionalOldPassword"
}

Response includes:
- Strength score and label
- Breach appearance count
- Similarity to previous password
- Crack-resistance explanation
- Improvement suggestions

---

### GET /generate

Generates a secure password.

Query parameter:

mode=balanced | memorable | strong

---

## Security and Privacy Considerations

- Passwords are never stored
- Breach checking uses k-anonymity
- Rate limiting protects against abuse
- No user accounts or tracking
- Intended for analysis and education, not authentication

---

## Academic Rationale

This project follows modern password and usability guidance:

- Avoids exposing raw cryptographic metrics to users
- Translates complex security data into understandable language
- Encourages secure behaviour through explanation and feedback
- Aligns with usability-focused security research

---

## Future Enhancements

- Password manager integration
- Expanded international dictionary support
- Accessibility improvements
- Visual strength indicators
- Optional account system with Argon2 hashing

---

## License

This software is provided for **educational and research purposes only**.  
No warranty is provided.