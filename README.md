
# Canary Gate
### A Tested Two-Way AI Firewall That Hides Private Data, Blocks Prompt Injection, and Catches Leaks

Canary Gate is a lightweight AI security gateway built with Python and FastAPI. It protects both sides of an AI interaction:

- **Before AI processing:** Detects and redacts supported personally identifiable information (PII), identifies suspicious prompt injection patterns, and applies security policies.
- **After AI processing:** Scans AI-generated responses for supported PII, credentials, internal instruction markers, and canary token leaks.

The gateway uses the Gemini API for AI response generation.

## Key Features

### 1. PII Detection and Redaction
- Detects email addresses.
- Detects supported Indian mobile number formats.
- Detects Aadhaar-like number patterns.
- Checks card-like numbers using the Luhn checksum.
- Redacts detected values before sending prompts to Gemini.

### 2. Prompt Injection Detection
- Detects common instruction override attempts.
- Identifies system prompt extraction patterns.
- Checks for jailbreak and role manipulation patterns.
- Calculates a heuristic risk score.
- Classifies requests as ALLOW, WARN, or BLOCK.

### 3. Security Policy Engine
- Combines PII and injection detection results.
- Blocks high-risk requests before model invocation.
- Allows or warns on requests according to configured rules.
- Ensures PII is redacted before model processing.

### 4. AI Output Scanner
- Scans generated responses for supported PII.
- Detects selected API-key and credential patterns.
- Identifies internal instruction markers.
- Redacts detected sensitive content before returning the response.

### 5. Canary Token Detection
- Generates a unique unpredictable token for each request.
- Checks AI output for the token.
- Blocks responses when a canary token leak is detected.

### 6. Sanitized Security Audit Logging
- Records request IDs and timestamps.
- Stores security actions and risk scores.
- Records detection categories and canary leak status.
- Does not intentionally store prompts, AI responses, PII values, API keys, or canary token values.

### 7. Automated Testing
- Uses pytest for automated tests.
- Uses mocked Gemini responses for gateway and API testing.
- Tests detection, redaction, blocking, output scanning, and audit logging.

## Architecture

```text
             USER PROMPT
                  |
                  v
          PII DETECTION
                  |
           PII REDACTION
                  |
                  v
       PROMPT INJECTION DETECTOR
                  |
                  v
           POLICY ENGINE
                  |
           +------+------+
           |             |
         BLOCK         ALLOW/WARN
           |             |
           v             v
        REJECT       CANARY TOKEN
                         |
                         v
                  GEMINI API
                         |
                         v
                   AI RESPONSE
                         |
                         v
                  OUTPUT SCANNER
                         |
                         v
                  CANARY CHECK
                         |
                 +-------+-------+
                 |               |
               LEAK           NO LEAK
                 |               |
                 v               v
               BLOCK       SANITIZED OUTPUT
                                 |
                                 v
                                USER

          SECURITY DECISIONS
                  |
                  v
             AUDIT LOGGER
```

## Technology Stack

| Component | Technology |
|---|---|
| Programming language | Python |
| API framework | FastAPI |
| AI model API | Google Gemini API |
| PII detection | Python Regular Expressions |
| Injection detection | Rule-based pattern matching |
| Secret scanning | Python Regular Expressions |
| Canary tokens | Python secrets module |
| Audit logging | JSON Lines |
| Testing | pytest |
| API documentation | Swagger UI |

## Project Structure

```text
canarygate/
|
├── app/
│   ├── __init__.py
│   ├── main.py
│   ├── ai_client.py
│   ├── gateway.py
│   │
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

```bash
python -m venv venv
```

Activate it on Windows PowerShell:

```powershell
.\venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```bash
python -m pip install -r requirements.txt
```

### 4. Configure environment variables

Create a `.env` file in the project root:

```env
GEMINI_API_KEY=your_gemini_api_key
GEMINI_MODEL=gemini-3.8-flash
```

Never commit your actual `.env` file or API key.

### 5. Run the application

```bash
python -m uvicorn app.main:app --reload
```

Open the API documentation:

http://127.0.0.1:8000/docs

Health check:

http://127.0.0.1:8000/health

## API Usage

### POST /chat

Example request:

```json
{
  "prompt": "Explain artificial intelligence in simple words."
}
```

Example response:

```json
{
  "action": "ALLOW",
  "risk_score": 0,
  "response": "Artificial intelligence enables machines to perform tasks that typically require human intelligence.",
  "reasons": [
    "No significant security risks detected."
  ],
  "output_detections": {},
  "canary_leak_detected": false
}
```

The response above is an illustrative example.

## Running Tests

Run the complete automated test suite:

```bash
python -m pytest -v
```

Current development result: **83 automated tests passed**.

The automated suite uses mocked Gemini responses where appropriate. A successful live Gemini API request was also tested separately.

## Security Design and Limitations

Canary Gate is a lightweight prototype and demonstration of layered AI security controls.

Important limitations:

- Pattern-based detection cannot identify every possible prompt injection.
- PII patterns may produce false positives or miss unusual formats.
- Aadhaar-like detection checks formatting, not authenticity.
- The Luhn checksum does not establish whether a payment card is active or genuine.
- Canary token detection identifies exact token occurrences; it is not a complete data-loss prevention system.
- Audit logging is metadata-focused but still requires access control, retention policies, and operational monitoring.
- The gateway does not guarantee complete protection against all AI security attacks.

## Future Improvements

- Broader prompt injection evaluation.
- Improved detection against obfuscated inputs.
- More comprehensive secret detection.
- Configurable security policies.
- Audit log integrity and retention controls.
- Expanded security benchmarks and evaluation reports.

## Author

**Lakshmi Harshitha Karlapati**

GitHub: https://github.com/harshitha-ai-tech

## Project

**Canary Gate — A Tested Two-Way AI Firewall That Hides Private Data, Blocks Prompt Injection, and Catches Leaks.**
