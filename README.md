# Canary Gate

### A Tested Two-Way AI Firewall That Hides Private Data, Blocks Prompt Injection, and Catches Leaks

Canary Gate is a Python-based AI security gateway designed to add a security layer between users and a generative AI model.

It checks incoming prompts before they reach the AI model and scans generated responses before returning them to users.

## Key Features

- **PII Detection and Redaction:** Detects and masks email addresses, Indian phone numbers, Aadhaar-like numbers, and payment-card-like numbers.
- **Prompt Injection Detection:** Uses rule-based detection to identify suspicious instructions and potential prompt injection attempts.
- **Risk Scoring and Policy Engine:** Classifies requests into ALLOW, WARN, or BLOCK decisions.
- **Secure AI Integration:** Sends permitted, sanitized prompts to the Gemini API.
- **Output Security Scanning:** Checks AI-generated responses for sensitive information, credentials, and internal instruction markers.
- **Canary Token Detection:** Uses a unique canary token to detect exact-token leaks in AI responses.
- **Security Audit Logging:** Records security metadata in JSONL format without storing original prompts, responses, or detected secret values.
- **Automated Testing:** Uses pytest and mocked AI responses to test security components without unnecessary API calls.

## Architecture

```text
                USER PROMPT
                     |
                     v
           +-------------------+
           |   PII DETECTION    |
           |   AND REDACTION   |
           +-------------------+
                     |
                     v
           +-------------------+
           | PROMPT INJECTION  |
           |    DETECTION      |
           +-------------------+
                     |
                     v
           +-------------------+
           |   POLICY ENGINE   |
           | ALLOW / WARN /    |
           |      BLOCK        |
           +-------------------+
                     |
              BLOCK? | 
               YES   |   NO
                |    v
                |  +----------------+
                |  |  CANARY TOKEN  |
                |  |   GENERATION   |
                |  +----------------+
                |          |
                |          v
                |  +----------------+
                |  |  GEMINI API    |
                |  +----------------+
                |          |
                |          v
                |  +----------------+
                |  | OUTPUT SCANNER |
                |  +----------------+
                |          |
                |          v
                |  +----------------+
                |  | CANARY LEAK    |
                |  |   DETECTION    |
                |  +----------------+
                |          |
                v          v
             BLOCK     SECURE RESPONSE
                           |
                           v
                       USER

             SECURITY AUDIT LOGGING
```

## Technology Stack

| Component | Technology |
|---|---|
| Programming language | Python |
| API framework | FastAPI |
| AI model | Google Gemini |
| AI SDK | google-genai |
| Input security | Python regex and validation |
| Output security | Rule-based scanning |
| Audit logging | JSONL |
| Testing | pytest |
| API documentation | Swagger UI |

## Project Structure

```text
canarygate/
├── app/
│   ├── __init__.py
│   ├── main.py
│   ├── ai_client.py
│   ├── gateway.py
│   └── security/
│       ├── __init__.py
│       ├── pii_detector.py
│       ├── injection_detector.py
│       ├── policy_engine.py
│       ├── output_scanner.py
│       ├── canary_detector.py
│       └── audit_logger.py
│
├── tests/
│   ├── test_api.py
│   ├── test_ai_client.py
│   ├── test_audit_logger.py
│   ├── test_canary_detector.py
│   ├── test_gateway.py
│   ├── test_gateway_audit.py
│   ├── test_injection_detector.py
│   ├── test_output_scanner.py
│   ├── test_pii_detector.py
│   └── test_policy_engine.py
│
├── .env.example
├── .gitignore
├── requirements.txt
└── README.md
```

## Installation and Setup

### 1. Clone the repository

```bash
git clone https://github.com/harshitha-ai-tech/canarygate.git
cd canarygate
```

### 2. Create a virtual environment

Windows PowerShell:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment variables

Create a `.env` file in the project root:

```env
GEMINI_API_KEY=your_gemini_api_key
GEMINI_MODEL=gemini-3.8-flash
```

Obtain an API key from Google AI Studio.

Never upload your actual `.env` file or API key to GitHub.

### 5. Start the application

```bash
uvicorn app.main:app --reload
```

## API Usage

Once the application is running, open:

- Swagger UI: `http://127.0.0.1:8000/docs`
- Health endpoint: `http://127.0.0.1:8000/health`

### Chat endpoint

**POST** `/chat`

Example request:

```json
{
  "prompt": "Explain artificial intelligence in simple words."
}
```

The API processes the prompt through the security gateway and returns the security decision, risk score, response, and relevant detection information.

## Testing

Run the automated test suite:

```bash
pytest -v
```

**Previously recorded test result: 83 passed.**

The test suite includes mocked AI interactions to validate application behavior without consuming Gemini API quota.

## Security Design and Limitations

Canary Gate is a proof-of-concept security gateway, not a complete security guarantee.

- PII detection uses pattern matching and validation rules; false positives and false negatives are possible.
- Aadhaar-like detection checks number patterns, not official Aadhaar validity.
- Card-like detection uses checksum validation, not verification of an active payment card.
- Prompt injection detection is heuristic and cannot identify every attack.
- Output scanning uses defined patterns and cannot guarantee detection of every possible secret.
- Canary detection identifies exact token matches and does not detect every form of indirect information leakage.
- The canary token is included in the model context for leak-detection testing.

## Future Improvements

- More comprehensive prompt injection detection.
- Advanced PII recognition.
- Improved secret and sensitive-output detection.
- Expanded security evaluation with additional attack scenarios.
- More detailed security metrics and reporting.

## Author

**Lakshmi Harshitha Karlapati**

GitHub: https://github.com/harshitha-ai-tech

Project: https://github.com/harshitha-ai-tech/canarygate