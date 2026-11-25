# LinkShield

**A Local-First Cybersecurity Platform for URL and File Threat Analysis**

LinkShield is a cybersecurity analysis platform designed to identify potentially suspicious URLs and files through static analysis. It evaluates security indicators, detects potentially harmful patterns, calculates risk scores, and generates structured PDF investigation reports.

The platform focuses on transparency and explainability, helping users understand *why* a URL or file may be considered suspicious.

---

## Key Features

### URL Security Analysis
- Detects suspicious URL patterns and keywords.
- Identifies potential brand impersonation.
- Checks for URL obfuscation and percent encoding.
- Identifies insecure HTTP connections.
- Evaluates suspicious domain patterns.

### File Security Analysis

Supports static analysis of the following file formats:

| File Format | Analysis |
|---|---|
| PDF | Suspicious text, encryption, missing metadata, empty documents |
| DOCX | Suspicious text and external relationships |
| ZIP | File count, uncompressed size, compression ratio |
| EXE | Executable headers, PE signature, file size |
| APK | ZIP structure, AndroidManifest.xml and DEX presence |

**Note:** LinkShield performs static analysis. Uploaded files are not executed.

### Risk Assessment
- Centralized risk-scoring engine.
- Severity-based scoring system.
- Risk classification:
  - Low Risk
  - Suspicious
  - High Risk
  - Inconclusive
- Evidence-based security findings.

### Security Investigation Reports
- Downloadable PDF reports.
- Consistent report design for URL and file analysis.
- Investigation details and assessment summary.
- Detailed security findings and severity levels.
- Assessment conclusions and scope limitations.

### Scan History and User Authentication
- User registration and login.
- Password hashing.
- Session-based authentication.
- User-specific scan history.
- Access control for individual scan results and reports.

---

## Technology Stack

| Component | Technology |
|---|---|
| Programming Language | Python |
| Backend Framework | FastAPI |
| Frontend | HTML, CSS, JavaScript, Bootstrap 5 |
| Template Engine | Jinja2 |
| Database | SQLite |
| ORM | SQLAlchemy |
| Data Validation | Pydantic |
| PDF Generation | ReportLab |
| Server | Uvicorn |
| Version Control | Git and GitHub |

---

## Project Structure

```text
LinkShield/
│
├── app/
│   ├── core/
│   ├── models/
│   ├── routers/
│   ├── schemas/
│   ├── services/
│   ├── database.py
│   └── main.py
│
├── static/
│   ├── css/
│   └── js/
│
├── templates/
│
├── requirements.txt
├── requirements-lock.txt
├── .gitignore
└── README.md
```

---

## Installation and Setup

### 1. Clone the repository

```bash
git clone https://github.com/adi-dev04/LinkShield.git
```

### 2. Navigate to the project directory

```bash
cd LinkShield
```

### 3. Create a virtual environment

```bash
python -m venv .venv
```

### 4. Activate the virtual environment

**Windows PowerShell:**

```powershell
.venv\Scripts\Activate.ps1
```

### 5. Install dependencies

```bash
pip install -r requirements.txt
```

### 6. Run the application

```bash
python -m uvicorn app.main:app --reload
```

### 7. Open the application

Visit:

- Application: http://127.0.0.1:8000
- API Documentation: http://127.0.0.1:8000/docs

---

## How LinkShield Works

1. **Input:** The user submits a URL or uploads a supported file.
2. **Analysis:** LinkShield performs static security checks.
3. **Detection:** The system identifies suspicious indicators and security findings.
4. **Risk Assessment:** Findings are evaluated using a centralized risk-scoring engine.
5. **Results:** The user receives an assessment with findings and risk classification.
6. **Reporting:** A structured PDF investigation report can be generated and downloaded.

---

## Security Approach

LinkShield follows a local-first analysis approach.

- Uploaded executable files are never run.
- Analysis relies on static inspection and identifiable security indicators.
- Findings are presented with severity levels.
- Unknown or incomplete analysis is not automatically treated as safe.
- Low-risk results do not guarantee that a URL or file is completely safe.

---

## Current Limitations

- No dynamic malware execution or sandbox analysis.
- No live webpage content inspection.
- APK analysis currently focuses on basic structural indicators rather than complete Android permission analysis.
- Static indicators alone cannot establish that a file or URL is malicious.

---

## Future Improvements

- Advanced URL reputation analysis.
- Deeper APK manifest and permission inspection.
- Expanded file-format support.
- Improved threat intelligence integration.
- More comprehensive security analysis and detection capabilities.

---

## Project Information

**Project:** LinkShield  
**Category:** Cybersecurity / Threat Analysis  
**Architecture:** Local-First  
**Repository:** https://github.com/adi-dev04/LinkShield

