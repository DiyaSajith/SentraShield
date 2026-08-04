# SentraShield
SentraShield is an AI-powered multi-modal phishing detection system that analyzes URLs, domains, emails, SMS, phone numbers, screenshots, and QR codes using heuristic analysis, threat intelligence, OCR, LLM-based reasoning, and safety-first risk evaluation.
<div align="center">

# 🛡️ SentraShield

### Guarding Your Digital Frontiers with Precision

**An AI-powered, multi-modal phishing detection system that combines heuristic analysis, cyber threat intelligence, OCR, QR-code analysis, and LLM-based contextual reasoning.**

[![Python](https://img.shields.io/badge/Python-3.x-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-Web%20Framework-black.svg)](https://flask.palletsprojects.com/)
[![AI](https://img.shields.io/badge/AI-LLM%20Powered-purple.svg)]()
[![License](https://img.shields.io/badge/License-MIT-green.svg)]()

</div>

---

## 📌 Overview

Phishing attacks have evolved beyond traditional email scams and now exploit URLs, domains, SMS messages, phone numbers, screenshots, and QR codes. Many existing detection systems focus on only one type of input or rely on static detection methods that may struggle with context-aware and evolving attacks.

**SentraShield** is a hybrid, AI-powered phishing detection platform designed to analyze multiple phishing vectors through a unified system. It combines deterministic heuristic analysis, external threat intelligence, image-based text extraction, and Large Language Model (LLM) reasoning to provide an explainable and security-focused risk assessment.

The system processes suspicious content through multiple intelligence layers and generates a final verdict along with a risk score, detected indicators, technical findings, and a user-friendly explanation.

---

## ✨ Key Features

* 🔗 **URL Analysis**
  Detects suspicious URL patterns, shortened links, deceptive structures, unusual formatting, and other phishing indicators.

* 🌐 **Domain Intelligence**
  Analyzes domain reputation, registration information, DNS-related details, and infrastructure-based risk indicators.

* 📧 **Email Phishing Detection**
  Identifies impersonation attempts, credential requests, urgency cues, deceptive language, and social-engineering techniques.

* 💬 **SMS and Text Analysis**
  Evaluates suspicious messages using heuristic indicators and contextual AI reasoning.

* 📞 **Phone Number Analysis**
  Uses search intelligence and available spam-related information to assess potentially fraudulent phone numbers.

* 🖼️ **Screenshot-Based Phishing Detection**
  Extracts text and URLs from uploaded screenshots using Optical Character Recognition (OCR) and analyzes the extracted content.

* 📱 **QR-Code Analysis**
  Detects and decodes QR codes, then evaluates their embedded destinations for potential security risks.

* 🧠 **LLM-Based Contextual Reasoning**
  Uses Large Language Models to understand semantic context, deceptive intent, psychological manipulation, and phishing tactics.

* 🛡️ **Safety-First Verdict Enforcement**
  Prevents strong deterministic evidence of malicious activity from being incorrectly downgraded by probabilistic AI reasoning.

* 📊 **Explainable Results**
  Provides risk categories, risk scores, detected indicators, domain intelligence, technical findings, and human-readable explanations.

---

## 🏗️ System Architecture

SentraShield follows a layered hybrid architecture:

```text
User Input
    │
    ▼
Input Classification
    │
    ├── URL / Domain
    ├── Email / SMS / Text
    ├── Phone Number
    └── Screenshot / QR Code
    │
    ▼
Intelligence Processing Layer
    │
    ├── Heuristic Feature Extraction
    ├── OCR Text Extraction
    ├── QR-Code Decoding
    └── Suspicious Indicator Detection
    │
    ▼
External Threat Intelligence
    │
    ├── Reputation Analysis
    ├── Domain Information
    └── Infrastructure Validation
    │
    ▼
LLM-Based Contextual Reasoning
    │
    ▼
Safety-First Decision Enforcement
    │
    ▼
Final Risk Assessment
```

---

## 🔄 Detection Workflow

1. The user submits a URL, domain, email, SMS, phone number, or image.
2. SentraShield identifies the input type.
3. The input is routed to the appropriate processing pipeline.
4. Heuristic analysis extracts suspicious indicators and generates a preliminary risk score.
5. External threat-intelligence services provide additional reputation and validation information where applicable.
6. Images are processed using OCR, while QR codes are detected and decoded.
7. The LLM evaluates semantic context, phishing intent, and social-engineering patterns.
8. The Safety Shield validates the combined evidence and prevents unsafe verdict downgrades.
9. The system generates an explainable final result.

---

## 🧰 Technology Stack

### Backend

* Python
* Flask

### Artificial Intelligence

* Large Language Models (LLMs)
* OpenRouter API
* Prompt Engineering
* Contextual and Semantic Analysis

### Cyber Threat Intelligence

* VirusTotal API
* Domain and reputation intelligence services
* DNS and domain-information analysis

### Image Processing

* OCR
* QR-Code Detection and Decoding
* Image Preprocessing

### Frontend

* HTML
* CSS
* JavaScript

---

## 📂 Project Structure

```text
SentraShield/
│
├── app.py
├── requirements.txt
├── .env.example
├── .gitignore
│
├── static/
│   ├── css/
│   ├── js/
│   └── images/
│
├── templates/
│   ├── index.html
│   └── results.html
│
├── modules/
│   ├── input_handler.py
│   ├── heuristic_analyzer.py
│   ├── url_analyzer.py
│   ├── domain_analyzer.py
│   ├── text_analyzer.py
│   ├── phone_analyzer.py
│   ├── image_processor.py
│   ├── ocr_processor.py
│   ├── qr_processor.py
│   ├── threat_intelligence.py
│   ├── llm_analyzer.py
│   └── safety_shield.py
│
└── README.md
```

> **Note:** Update this structure if your actual folder or file names are different.

---

## ⚙️ Installation and Setup

### 1. Clone the repository

```bash
git clone https://github.com/YOUR-USERNAME/SentraShield.git
```

### 2. Navigate to the project directory

```bash
cd SentraShield
```

### 3. Create a virtual environment

```bash
python -m venv venv
```

### 4. Activate the virtual environment

**Windows**

```bash
venv\Scripts\activate
```

**macOS/Linux**

```bash
source venv/bin/activate
```

### 5. Install dependencies

```bash
pip install -r requirements.txt
```

### 6. Configure environment variables

Create a `.env` file in the project root:

```env
OPENROUTER_API_KEY=your_openrouter_api_key
VIRUSTOTAL_API_KEY=your_virustotal_api_key
```

Add any other API keys required by your implementation.

> ⚠️ Never upload your `.env` file or API keys to GitHub.

### 7. Run the application

```bash
python app.py
```

Open the application in your browser:

```text
http://127.0.0.1:5000/
```

---

## 📊 Output

For each submitted input, SentraShield provides:

* Final risk category
* Risk score
* Detected phishing indicators
* Domain or reputation information
* LLM-based contextual analysis
* Technical findings
* Plain-language explanation
* Security recommendations

---

## 🔐 Security and Privacy

* User-submitted content is processed for analysis and is not intended for permanent storage.
* API keys are loaded through environment variables.
* Sensitive credentials are not embedded directly in the source code.
* External API communication is performed through secure HTTPS requests.
* Input validation and error handling are used to improve system reliability.

---

## 🧪 Evaluation

SentraShield was evaluated using curated malicious and legitimate samples across multiple detection modules, including:

* URL detection
* Email analysis
* SMS analysis
* Phone-number analysis
* Screenshot-based OCR analysis
* Image-based phishing detection

The hybrid architecture combines deterministic security indicators with contextual AI reasoning to improve explainability and reduce the risk of missed threats.

---

## 🚀 Future Enhancements

* Browser extension for real-time phishing detection
* Email-client integration
* Real-time URL monitoring
* Multilingual phishing analysis
* Advanced visual phishing detection
* User feedback and threat-reporting mechanisms
* Expanded threat-intelligence integrations
* Mobile application support
* Continuous model evaluation and improvement

---

## 📄 Research Publication

The research work associated with SentraShield has been published through **IEEE Xplore**.

> Add the paper title, DOI, and IEEE Xplore link here.

---

## 👥 Team

* **Anjithkrishnan K**
* **Diya K Sajith**
* **Riya S**
* **S Thejaswini**

---

## 🎓 Academic Information

**Department of Computer Science and Engineering**
**N.S.S. College of Engineering, Palakkad**
APJ Abdul Kalam Technological University, Kerala

---

## 📜 License

This project is licensed under the **MIT License**.

The MIT License applies to the original source code and project materials contained in this repository. The associated IEEE-published research paper is subject to its respective publication and copyright terms and is not covered by the MIT License.

---

## 🙏 Acknowledgements

We sincerely thank our project guide, faculty members, institution, and everyone who supported the development and evaluation of SentraShield.

We also acknowledge the open-source community and the external services, frameworks, and tools that contributed to the development of this project.

---

<div align="center">

### 🛡️ SentraShield — Guarding Your Digital Frontiers with Precision

</div>
