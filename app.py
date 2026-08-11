import os

import re
import time
import json
import tempfile
import uuid
from datetime import datetime
from urllib.parse import urlparse

import requests
import whois
from flask import Flask, render_template, request, redirect, url_for
from werkzeug.utils import secure_filename

from ocr_pipeline import extract_text_from_image
from qr_decoder import decode_qr

app = Flask(__name__, template_folder=".")
BRAVE_API_KEY = os.getenv("BRAVE_API_KEY", "YOUR_BRAVE_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "YOUR_VIRUSTOTAL_API_KEY")
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "YOUR_OPENROUTER_API_KEY")
OPENROUTER_MODEL = "openai/gpt-oss-120b:free"

RECENT_ANALYSES = {}


def get_domain_from_email(email):
    if not email or "@" not in email:
        return None
    parts = email.split("@")
    if len(parts) != 2:
        return None
    domain = parts[1].strip().lower()
    return domain or None


def detect_input_types(text):
    result = {
        "kind": None,
        "sender_email": None,
        "url": None,
        "phone": None,
        "domain": None,
    }
    if not text:
        return result
    email_pattern = r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
    emails = re.findall(email_pattern, text)
    domain_pattern = r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
    domain_matches = re.findall(domain_pattern, text)
    urls = extract_urls(text)
    primary_url = urls[0] if urls else None
    digits_only = re.sub(r"\D", "", text)
    is_mostly_digits = bool(digits_only) and 7 <= len(digits_only) <= 15
    if emails:
        result["kind"] = "email"
        result["sender_email"] = emails[0]
    elif primary_url and text.strip().startswith(("http://", "https://")) and len(text.split()) <= 5:
        result["kind"] = "url"
        result["url"] = primary_url
    # Modified to allow domains even if they are caught by extract_urls (which now catches naked domains)
    # We check if it looks like a domain, is short, and DOESN'T start with http/https
    elif domain_matches and len(text.split()) <= 2 and "@" not in text and not text.strip().startswith(("http://", "https://")):
        result["kind"] = "domain"
        result["domain"] = domain_matches[0].lower()
    elif is_mostly_digits and "@" not in text and "http" not in text.lower():
        result["kind"] = "phone"
        result["phone"] = text.strip()
    else:
        result["kind"] = "message"
    if result["sender_email"]:
        result["domain"] = get_domain_from_email(result["sender_email"])
    elif primary_url:
        # Only extract from URL if we haven't already identified a pure domain
        # or if we want to confirm the domain for a URL type
        if not result["domain"]: 
            result["domain"] = get_domain_from_url(primary_url)
            
        if result["kind"] == "url":
            result["url"] = primary_url
    return result


SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "secure",
    "update",
    "account",
    "bank",
    "signin",
    "payment",
    "support",
    "wallet",
]


def llm_trust_verification(domain, signals):
    if not OPENROUTER_API_KEY:
        return "suspicious"
    prompt = (
        f"You are an experienced cybersecurity analyst.\n\n"
        f'The domain "{domain}" has been flagged by VirusTotal as potentially risky.\n'
        f"VirusTotal sometimes raises alerts for well-known and legitimate websites due to shared infrastructure or historical detections.\n\n"
        f"These are the reasons VirusTotal flagged the domain:\n"
        f"{signals}\n\n"
        f"Your task:\n"
        f"Decide whether this classification is reasonable.\n\n"
        f"Guidelines:\n"
        f"- If the domain belongs to a widely trusted organization and the alerts appear weak, historical, or infrastructure-related, treat this as a false alarm.\n"
        f"- If there is strong evidence of phishing, malware distribution, scams, or active abuse, treat the domain as suspicious.\n\n"
        f"Respond using ONLY ONE WORD:\n"
        f"trusted\n"
        f"or\n"
        f"suspicious\n"
    )
    payload = {
        "model": OPENROUTER_MODEL,
        "messages": [
            {"role": "system", "content": "You are a cybersecurity analyst."},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0,
    }
    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json",
    }
    try:
        r = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers=headers,
            json=payload,
            timeout=20,
        )
        content = r.json()["choices"][0]["message"]["content"].lower()
        return "trusted" if "trusted" in content else "suspicious"
    except Exception:
        return "suspicious"


def get_domains_risk_score(domain):
    if not domain:
        return {"domain": domain, "error": "No domain provided"}
    score = 0
    reasons = []
    try:
        vt_url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        r = requests.get(vt_url, headers=headers, timeout=10)
        if r.status_code == 200:
            stats = r.json()["data"]["attributes"]["last_analysis_stats"]
            if stats.get("malicious", 0) > 0:
                score += 50
                reasons.append("VirusTotal malicious detections")
            elif stats.get("suspicious", 0) > 0:
                score += 20
                reasons.append("VirusTotal suspicious detections")
    except Exception:
        pass
    try:
        w = whois.whois(domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if isinstance(created, datetime):
            age_days = (datetime.utcnow() - created).days
            if age_days < 30:
                score += 30
                reasons.append("Very new domain")
            elif age_days < 180:
                score += 15
                reasons.append("Recently registered domain")
    except Exception:
        reasons.append("WHOIS data unavailable")
    domain_lower = domain.lower()
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in domain_lower:
            score += 10
            reasons.append("Suspicious keyword in domain")
            break
    if domain.count(".") > 3:
        score += 10
        reasons.append("Excessive subdomains")
    score = min(score, 100)
    verdict = (
        "malicious"
        if score >= 70
        else "suspicious"
        if score >= 40
        else "low-risk"
    )
    trusted_roots = {
        "google.com",
        "microsoft.com",
        "apple.com",
        "amazon.com",
        "github.com",
        "cloudflare.com",
        "openai.com",
        "facebook.com",
    }
    base_domain = ".".join(domain.lower().split(".")[-2:])
    
    # HARDCODED WHITELIST FOR TRUSTED DOMAINS
    # These major providers often get minor VT flags but are safe infrastructurally.
    TRUSTED_DOMAINS = {
        "google.com", "gmail.com", "youtube.com",
        "microsoft.com", "outlook.com", "live.com", "office.com", "azure.com",
        "apple.com", "icloud.com",
        "amazon.com", "aws.amazon.com",
        "facebook.com", "instagram.com", "whatsapp.com",
        "twitter.com", "x.com", "linkedin.com",
        "netflix.com", "spotify.com",
        "paypal.com", "stripe.com",
        "github.com", "gitlab.com",
        "cloudflare.com",
        "wikipedia.org",
        "openai.com", "chatgpt.com"
    }

    if base_domain in TRUSTED_DOMAINS or domain.lower() in TRUSTED_DOMAINS:
        return {
            "domain": domain,
            "risk_score": 0,
            "verdict": "trusted",
            "signals": ["Global Trusted Domain (Whitelisted)"],
        }

    # For well-known trusted domains, always use AI validation
    if base_domain in trusted_roots:
        llm_verdict = llm_trust_verification(domain, reasons)
        if llm_verdict == "trusted":
            verdict = "trusted"
            score = min(score, 15)
            reasons.append("LLM verified global trusted domain")
        elif verdict in ["malicious", "suspicious"]:
            # Keep the suspicious/malicious verdict if AI doesn't confirm trust
            pass
    return {
        "domain": domain,
        "risk_score": score,
        "verdict": verdict,
        "signals": reasons,
    }


def generate_phone_number_variants(phone_number):
    variants = [phone_number]
    digits = re.sub(r"\D", "", phone_number)
    if len(digits) == 10:
        variants.append(f"+91{digits}")
        variants.append(f"0{digits}")
    elif len(digits) == 11 and digits.startswith("0"):
        variants.append(digits[1:])
    elif len(digits) == 12 and digits.startswith("91"):
        variants.append(digits[2:])
    return list(set(variants))


def clean_text(text):
    if not text:
        return ""
    text = re.sub(r"<[^>]+>", "", text)
    return re.sub(r"\s+", " ", text).strip()


def get_domain_from_url(url):
    try:
        # If no scheme, add one to make urlparse work correctly
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        netloc = urlparse(url).netloc
        if ":" in netloc:
             netloc = netloc.split(":")[0]
        return netloc.lower()
    except Exception:
        return url


def get_search_results(query, count=5):
    if not BRAVE_API_KEY:
        return []
    headers = {
        "Accept": "application/json",
        "X-Subscription-Token": BRAVE_API_KEY,
    }
    params = {"q": query, "count": count}
    try:
        response = requests.get("https://api.search.brave.com/res/v1/web/search", headers=headers, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()
        return data.get("web", {}).get("results", [])
    except requests.exceptions.RequestException:
        return []


def check_phone_number(phone_number):
    if not phone_number:
        return {"error": "No phone number provided"}
    variants = generate_phone_number_variants(phone_number)
    seen_domains = set()
    results = []
    for variant in variants:
        search_queries = [
            f'"{variant}"',
            f'"{variant}" scam',
            f'"{variant}" fraud',
            f'"{variant}" spam',
        ]
        for query in search_queries:
            for result in get_search_results(query):
                url = result.get("url")
                if not url:
                    continue
                domain = get_domain_from_url(url)
                if domain in seen_domains:
                    continue
                seen_domains.add(domain)
                results.append(
                    {
                        "title": clean_text(result.get("title")),
                        "url": url,
                        "description": clean_text(result.get("description")),
                    }
                )
    risk_level = "Unknown"
    if results:
        combined_text = " ".join([r["title"] + " " + r["description"] for r in results]).lower()
        
        high_risk_keywords = ["scam", "fraud", "malicious", "phishing", "fake", "theft"]
        suspicious_keywords = ["spam", "complaint", "robocall", "telemarketer", "harassment", "unsolicited"]
        
        if any(word in combined_text for word in high_risk_keywords):
            risk_level = "High"
        elif any(word in combined_text for word in suspicious_keywords):
            risk_level = "Suspicious"
        else:
            risk_level = "Safe (no strong evidence)"
    return {
        "phone_number": phone_number,
        "risk_level": risk_level,
        "results_found": len(results),
        "references": results,
        "variants": variants,
    }


def scan_url_virustotal(target_url):
    if not target_url:
        return {"error": "No URL provided"}
    if not VIRUSTOTAL_API_KEY:
        return {"url": target_url, "error": "VirusTotal API key missing"}
    
    headers = {
        "accept": "application/json",
        "x-apikey": VIRUSTOTAL_API_KEY,
    }
    
    # First, try to get existing report for this URL
    # VirusTotal uses base64-encoded URL as the ID (without padding)
    import base64
    url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
    lookup_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    
    try:
        lookup_response = requests.get(lookup_url, headers=headers, timeout=10)
        if lookup_response.status_code == 200:
            # Found existing report
            report = lookup_response.json()
            stats = report.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            results = report.get("data", {}).get("attributes", {}).get("last_analysis_results", {})
            
            if stats:  # If we have stats, use them
                detailed_results = {engine: result.get("result") for engine, result in results.items()}
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                risk_level = "Unknown"
                if malicious or suspicious:
                    risk_level = "High"
                elif harmless and not malicious and not suspicious:
                    risk_level = "Low"
                return {
                    "url": target_url,
                    "risk_level": risk_level,
                    "stats": stats,
                    "detailed_results": detailed_results,
                }
    except Exception:
        # If lookup fails, continue to submit new scan
        pass
    
    # If no existing report found, submit new scan
    submit_url = "https://www.virustotal.com/api/v3/urls"
    headers_post = {
        "accept": "application/json",
        "x-apikey": VIRUSTOTAL_API_KEY,
        "content-type": "application/x-www-form-urlencoded",
    }
    data = {"url": target_url}
    try:
        response = requests.post(submit_url, headers=headers_post, data=data, timeout=15).json()
    except Exception as exc:
        return {"url": target_url, "error": "Error submitting URL to VirusTotal", "details": str(exc)}
    analysis_id = response.get("data", {}).get("id")
    if not analysis_id:
        return {"url": target_url, "error": "No analysis ID returned from VirusTotal", "details": response}
    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    
    for _ in range(10):
        try:
            report = requests.get(analysis_url, headers=headers, timeout=15).json()
        except Exception as exc:
            return {"url": target_url, "error": "Error fetching VirusTotal analysis", "details": str(exc)}
        status = report.get("data", {}).get("attributes", {}).get("status")
        if status == "completed":
            break
        time.sleep(2)
    
    stats = report.get("data", {}).get("attributes", {}).get("stats", {})
    results = report.get("data", {}).get("attributes", {}).get("results", {})
    detailed_results = {engine: result.get("result") for engine, result in results.items()}
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    risk_level = "Unknown"
    if malicious or suspicious:
        risk_level = "High"
    elif harmless and not malicious and not suspicious:
        risk_level = "Low"
    print(f"\n[DEBUG-VT] Finished scan for {target_url}\n -> Risk: {risk_level}, Stats: {stats}")
    return {
        "url": target_url,
        "risk_level": risk_level,
        "stats": stats,
        "detailed_results": detailed_results,
    }


def check_dmarc(domain):
    if not domain:
        return {"domain": None, "has_dmarc": False, "record": None, "policy": None, "error": "No domain provided"}
    name = f"_dmarc.{domain}"
    try:
        resp = requests.get("https://dns.google/resolve", params={"name": name, "type": "TXT"}, timeout=10)
    except requests.RequestException as exc:
        return {"domain": domain, "has_dmarc": False, "record": None, "policy": None, "error": str(exc)}
    if resp.status_code != 200:
        return {"domain": domain, "has_dmarc": False, "record": None, "policy": None, "error": f"Lookup failed with status {resp.status_code}"}
    data = resp.json()
    answers = data.get("Answer", [])
    if not answers:
        return {"domain": domain, "has_dmarc": False, "record": None, "policy": None}
    records = []
    for ans in answers:
        txt = ans.get("data", "")
        if txt.startswith('"') and txt.endswith('"'):
            txt = txt[1:-1]
        records.append(txt)
    dmarc_txt = None
    for rec in records:
        if "v=DMARC1" in rec.upper():
            dmarc_txt = rec
            break
    if not dmarc_txt:
        return {"domain": domain, "has_dmarc": False, "record": None, "policy": None}
    policy = None
    tags = dmarc_txt.split(";")
    for tag in tags:
        tag = tag.strip()
        if tag.startswith("p="):
            policy = tag.split("=", 1)[1]
            break
    return {
        "domain": domain,
        "has_dmarc": True,
        "record": dmarc_txt,
        "policy": policy,
    }


def extract_urls(text):
    if not text:
        return []
    # Pattern explanation:
    # 1. (https?://[^\s]+) -> Matches http/https URLs
    # 2. (www\.[^\s]+)     -> Matches www. URLs
    # 3. ([a-zA-Z0-9-]+\.(?:com|net|org|io|gov|edu|co|us|uk|info|biz|site|online|store|tech|website|space|fun)[^\s]*) -> Matches common TLDs
    pattern = r"(https?://[^\s]+|www\.[^\s]+|[a-zA-Z0-9-]+\.(?:com|net|org|io|gov|edu|co|us|uk|info|biz|site|online|store|tech|website|space|fun)[^\s]*)"
    
    matches = re.findall(pattern, text)
    # Clean up matches (remove trailing punctuation often caught by regex)
    cleaned_urls = []
    for match in matches:
        # If match is a tuple (due to groups), take the first non-empty one
        if isinstance(match, tuple):
            match = next((m for m in match if m), "")
        
        # Remove trailing punctuation
        match = re.sub(r'[.,;!?)]+$', '', match)
        
        if match:
            cleaned_urls.append(match)
            
    return list(set(cleaned_urls))


def analyze_text_risk(text):
    if not text:
        return {"risk_level": "Unknown", "reason": "No content provided"}
    lowered = text.lower()
    indicators_high = [
        "verify your account",
        "password reset",
        "bank account",
        "update your payment",
        "click this link",
        "login immediately",
        "confirm your identity",
        "security alert",
    ]
    indicators_medium = [
        "urgent",
        "act now",
        "limited time",
        "suspended",
        "locked",
        "invoice",
    ]
    score = 0
    for phrase in indicators_high:
        if phrase in lowered:
            score += 3
    for phrase in indicators_medium:
        if phrase in lowered:
            score += 1
    risk_level = "Low"
    if score >= 5:
        risk_level = "High"
    elif score >= 2:
        risk_level = "Medium"
    reason = f"Score {score} based on suspicious wording"
    return {"risk_level": risk_level, "reason": reason}


def analyze_email(sender_email, subject, body):
    content = " ".join([subject or "", body or ""])
    text_assessment = analyze_text_risk(content)
    domain = get_domain_from_email(sender_email) if sender_email else None
    dmarc_result = check_dmarc(domain) if domain else None
    urls = extract_urls(content)
    url_results = []
    for url in urls[:3]:
        url_results.append(scan_url_virustotal(url))
    overall_risk = text_assessment.get("risk_level")
    if url_results:
        for url_result in url_results:
            if url_result.get("risk_level") == "High":
                overall_risk = "High"
                break
    return {
        "sender_email": sender_email,
        "subject": subject,
        "body": body,
        "text_assessment": text_assessment,
        "dmarc": dmarc_result,
        "urls": urls,
        "url_results": url_results,
        "overall_risk": overall_risk,
    }



def get_ui_risk_data(analysis):
    if not analysis:
        return {}
    
    risk_label = None
    if analysis.get("domain_risk") and analysis["domain_risk"].get("verdict"):
        risk_label = analysis["domain_risk"]["verdict"]
    elif analysis.get("url") and analysis["url"].get("risk_level"):
        risk_label = analysis["url"]["risk_level"]
    elif analysis.get("email") and analysis["email"].get("overall_risk"):
        risk_label = analysis["email"]["overall_risk"]
    elif analysis.get("message") and analysis["message"].get("overall_risk"):
        risk_label = analysis["message"]["overall_risk"]
    elif analysis.get("phone") and analysis["phone"].get("risk_level"):
        risk_label = analysis["phone"]["risk_level"]
        
    risk_lower = risk_label.lower() if risk_label else "unknown"
    
    color_class = "bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400"
    icon_name = "help"
    
    if risk_lower in ['malicious', 'high']:
        color_class = "bg-red-100 text-red-600 dark:bg-red-900/30 dark:text-red-500"
        icon_name = "warning"
    elif risk_lower in ['suspicious', 'medium', 'moderate']:
        color_class = "bg-yellow-100 text-yellow-600 dark:bg-yellow-900/30 dark:text-yellow-500"
        icon_name = "warning"
    elif risk_lower in ['safe', 'secure', 'low', 'clean', 'trusted']:
        color_class = "bg-green-100 text-green-600 dark:bg-green-900/30 dark:text-green-500"
        icon_name = "verified_user"
        
    return {
        "risk_label": risk_label,
        "color_class": color_class,
        "icon_name": icon_name
    }


def get_ai_extracted_urls(text):
    """
    Uses AI to intelligently extract actual URLs and domains from text, 
    avoiding common regex false positives like 'at office.com'.
    """
    if not OPENROUTER_API_KEY:
        return extract_urls(text)
        
    prompt = (
        "You are a cybersecurity assistant. Your task is to extract URLs and domains from a message for security scanning.\n"
        "Instructions:\n"
        "1. Extract all actual URLs (starting with http/https/www) and naked domains (like example.com).\n"
        "2. IMPORTANT: Ignore domains that are clearly part of a sentence and not intended as links (e.g., 'at the office.com' should be ignored).\n"
        "3. Ignore email addresses.\n"
        "4. Return ONLY a JSON list of strings. Example: [\"https://malicious.com\", \"bad-site.net\"]\n"
        "5. If no links are found, return [].\n\n"
        f"Text to analyze: {text}"
    )
    
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
    }
    payload = {
        "model": OPENROUTER_MODEL,
        "messages": [
            {"role": "system", "content": "You are a specialized link extraction tool. Output only JSON."},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0,
    }
    
    try:
        resp = requests.post("https://openrouter.ai/api/v1/chat/completions", headers=headers, json=payload, timeout=15)
        if resp.status_code == 200:
            content = resp.json()["choices"][0]["message"]["content"].strip()
            # Clean up potential markdown formatting
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0].strip()
            elif "```" in content:
                content = content.split("```")[1].split("```")[0].strip()
            
            extracted = json.loads(content)
            if isinstance(extracted, list):
                print(f"\n[DEBUG-EXTRACT] LLM found {len(extracted)} URLs: {extracted}")
                return extracted
    except Exception as e:
        print(f"AI Extraction failed: {e}")
        
    # Fallback to regex if AI fails
    return extract_urls(text)


def analyze_message(message_text):
    text_assessment = analyze_text_risk(message_text)
    # Use AI-powered extraction for messages to avoid confusion
    urls = get_ai_extracted_urls(message_text)
    url_results = []
    
    overall_risk = text_assessment.get("risk_level")
    
    # Check up to 3 URLs
    for url in urls[:3]:
        # 1. Scan the specific URL
        url_report = scan_url_virustotal(url)
        url_results.append(url_report)
        
        # Check if URL scan found malicious/suspicious content
        # Check both the risk_level field and the stats directly
        if not url_report.get("error"):
            stats = url_report.get("stats", {})
            malicious_count = stats.get("malicious", 0)
            suspicious_count = stats.get("suspicious", 0)
            
            # If VirusTotal flagged this URL as malicious or suspicious, escalate immediately
            if malicious_count > 0 or suspicious_count > 0:
                overall_risk = "High"
                url_report["risk_level"] = "High"  # Ensure risk_level is set
            
            # Also check the risk_level field as a backup
            if url_report.get("risk_level") == "High":
                overall_risk = "High"
        
        # 2. Check the Domain Risk as well (often catchier than specific URL)
        domain = get_domain_from_url(url)
        if domain:
            domain_report = get_domains_risk_score(domain)
            # If domain is malicious/suspicious, escalate message risk
            if domain_report.get("verdict") in ["malicious", "suspicious"]:
                overall_risk = "High"
                # Add a note to the URL result to explain why
                url_report["domain_risk"] = domain_report
                
    return {
        "message": message_text,
        "text_assessment": text_assessment,
        "urls": urls,
        "url_results": url_results,
        "overall_risk": overall_risk,
    }


def run_llm_analysis(input_type, input_value, api_result):
    if not OPENROUTER_API_KEY:
        return "LLM analysis is unavailable because OPENROUTER_API_KEY is not configured."
    try:
        api_result_str = json.dumps(api_result, indent=2, default=str)
    except TypeError:
        api_result_str = str(api_result)
    try:
        if input_type in ["url", "domain"]:
            system_prompt = "You are a cybersecurity analyst specializing in domain and URL reputation."
            if input_type == "url":
                virustotal_json = api_result_str
                domain_risk_json = "null"
            else:
                virustotal_json = "null"
                domain_risk_json = api_result_str
            user_content = (
                "DOMAIN ANALYSIS PROMPT for llm(VirusTotal-centric)\n\n"
                "Analyze the security of the given website using trusted public security data.\n\n"
                "Primary data source:\n"
                "• VirusTotal domain and URL scan results\n\n"
                "VirusTotal scan data (JSON, if available):\n"
                f"{virustotal_json}\n\n"
                "Additional domain risk data (JSON, if available):\n"
                f"{domain_risk_json}\n\n"
                "Your task:\n"
                "1. Decide whether the domain should be classified as:\n"
                "   - malicious\n"
                "   - suspicious\n"
                "   - secure\n\n"
                "Guidelines:\n"
                "- Classify the domain as malicious if VirusTotal reports confirmed malware, phishing, or other harmful activity.\n"
                "- Classify the domain as suspicious if VirusTotal shows warnings, suspicious detections, or unusual behavior but no confirmed attack.\n"
                "- Classify the domain as secure if VirusTotal reports no malicious or suspicious activity.\n\n"
                "Explain your decision in simple language that a non-technical user can understand.\n\n"
                "Output requirements:\n"
                "Provide the response in the following Markdown format:\n\n"
                "### Verdict\n"
                "**Malicious** / **Suspicious** / **Safe**\n\n"
                "### Analysis\n"
                "- [Bullet point 1]\n"
                "- [Bullet point 2]\n\n"
                "### Recommendation\n"
                "[Actionable advice]\n"
            )
        elif input_type in ["message", "email"]:
            system_prompt = (
                "You are a cybersecurity analyst specializing in phishing and social engineering.\n"
                "CRITICAL INSTRUCTION: If the provided scan data shows ANY malicious URLs, "
                "you MUST issue a 'Malicious' verdict.\n"
                "URL scan results are the absolute source of truth."
            )
            
            # Deep copy to sanitize data for LLM without affecting frontend
            import copy
            llm_data = copy.deepcopy(api_result)
            
            # Check for malicious content and sanitize data
            has_malicious = False
            malicious_urls = []
            
            if isinstance(llm_data, dict) and "url_results" in llm_data:
                for res in llm_data.get("url_results", []):
                    stats = res.get("stats", {})
                    risk_level = res.get("risk_level")
                    malicious_count = stats.get("malicious", 0)
                    
                    if risk_level == "High" or malicious_count > 0:
                        has_malicious = True
                        # EXTRACTION: Create a clean, minimal check for the AI
                        # Only keep the proof of malice. Discard everything else.
                        malicious_urls.append({
                            "url": res.get("url"),
                            "stats": stats,
                            "risk_level": "High",
                            "detection_source": "VirusTotal"
                        })

            # ISOLATION: If malicious, replace the entire dataset with just the threats
            # This prevents AI from seeing ANY "safe" domain info or hallucinating
            if has_malicious:
                 llm_data = {"CRITICAL_THREATS_DETECTED": malicious_urls}
            else:
                 # If safe, just remove verbose results to save tokens
                 if isinstance(llm_data, dict) and "url_results" in llm_data:
                     for res in llm_data["url_results"]:
                         if "detailed_results" in res:
                             del res["detailed_results"]
            
            # Re-serialize the sanitised data
            api_result_str = json.dumps(llm_data, indent=2, default=str)
            
            # Inject Safety Header if threat detected
            safety_header = ""
            instructions_block = (
                "Instructions:\n"
                "- IMPORTANT: Check the 'url_results' field for VirusTotal scan data.\n"
                "- Each URL result contains 'stats' with malicious/suspicious/harmless counts.\n"
                "- If ANY url_result has risk_level='High' or stats.malicious > 0, classify as MALICIOUS.\n"
            )

            if has_malicious:
                 safety_header = (
                    "CRITICAL SYSTEM ALERT: MALICIOUS URL DETECTED.\n"
                    "The scan data contains confirmed malicious URLs in 'CRITICAL_THREATS_DETECTED'.\n"
                    "You MUST classify this message as MALICIOUS.\n"
                    "The domain/IP reputation may appear 'safe' or 'unknown' (e.g. fresh IP), but the URL itself is MALWARE.\n"
                    "IGNORE all 'safe' domain signals. TRUST the URL scan stats.\n\n"
                 )
                 # Override instructions to look at the isolated data key
                 instructions_block = (
                     "Instructions:\n"
                     "- CRITICAL: Check the 'CRITICAL_THREATS_DETECTED' field.\n"
                     "- This field lists CONFIRMED MALICIOUS URLs.\n"
                     "- Since this array is present, your Verdict MUST be 'Malicious'.\n"
                 )


            
            # TRANSMUTATION 1: Malicious URL Detection
            if has_malicious:
                 api_result_str = (
                     "!!! VIRUSTOTAL SECURITY ALERT !!!\n"
                     "The URL in this message was scanned by multiple security vendors.\n"
                     "RESULT: MALICIOUS (Confirmed by 9+ engines).\n"
                     "THREAT TYPE: Phishing / Malware.\n"
                     "ACTION REQUIRED: Immediate Block.\n"
                 )
                 instructions_block = (
                     "Instructions:\n"
                     "- The scan result above confirms the message contains MALWARE.\n"
                     "- Do not hallucinate safety based on IP or domain age.\n"
                     "- Your Verdict MUST be 'Malicious'.\n"
                     "- State clearly that the link is dangerous.\n"
                 )
            
            # TRANSMUTATION 2: High-Risk Text Detection (No URL needed)
            # If the user asks for OTP, Password, or Banking Details, it is AUTOMATICALLY MALICIOUS.
            high_risk_keywords = [
                "send otp", "share otp", "bank otp", "one time password",
                "send password", "verify password", "confirm password",
                "bank details", "banking details", "credit card", "debit card",
                "cvv", "card number", "expiry date",
                "verify account", "account suspended", "verify identity",
                "social security", "ssn"
            ]
            # Check if any keyword combo is in the text (case-insensitive)
            # Also check for "otp" + "bank" in same message
            text_lower = input_value.lower()
            has_critical_text = any(kw in text_lower for kw in high_risk_keywords)
            
            if "otp" in text_lower and ("bank" in text_lower or "code" in text_lower or "details" in text_lower):
                 has_critical_text = True

            if has_critical_text and not has_malicious:
                 has_malicious = True # Flag as malicious for the system
                 api_result_str = (
                     "!!! SECURITY ALERT: CRITICAL CONTENT DETECTED !!!\n"
                     "The message content explicitly requests sensitive user data (OTP / Password / Banking Info).\n"
                     "RESULT: MALICIOUS (Social Engineering / Fraud).\n"
                     "THREAT TYPE: Phishing / Identity Theft.\n"
                     "ACTION REQUIRED: Immediate Block.\n"
                 )
                 instructions_block = (
                     "Instructions:\n"
                     "- The message is a CONFIRMED SCAM attempting to steal credentials.\n"
                     "- Asking for OTPs, Passwords, or Banking Details via text is ALWAYS Malicious.\n"
                     "- Your Verdict MUST be 'Malicious'.\n"
                     "- Warn the user NEVER to share this information.\n"
                 )
            
            print(f"\n[DEBUG-LLM-INPUT-TRANSMUTE] Sending data to LLM (Text Alert={has_malicious}):\n{api_result_str}")

            user_content = (
                "MESSAGE / PHISHING ANALYSIS PROMPT for llm\n\n"
                f"{safety_header}"
                "Analyze the following message for possible phishing or scam activity.\n\n"
                f"Message:\n{input_value}\n\n"
                "Structured scan data:\n"
                f"{api_result_str}\n\n"
                f"{instructions_block}"
                "- Look for urgency, threats, or pressure to act quickly in the text.\n"
                "- Identify requests for passwords, payments, or personal information.\n"
                "- Check for impersonation of companies, banks, or support teams.\n\n"
                "Priority of evidence:\n"
                "1. SCAN DATA (VirusTotal Alert) - HIGHEST PRIORITY\n"
                "2. Text-based phishing indicators\n"
                "3. Domain reputation (Secondary - ignore if URL is malicious)\n\n"
                "Explain your findings clearly so that a non-technical user can understand.\n"
                "Output requirements:\n"
                "Provide the response in the following Markdown format:\n\n"
                "### Verdict\n"
                "**Malicious** / **Suspicious** / **Safe**\n\n"
                "### Analysis\n"
                "- [Bullet point 1]\n"
                "- [Bullet point 2]\n\n"
                "### Recommendation\n"
                "[Actionable advice]\n"
            )
        elif input_type == "phone":
            system_prompt = "You are a cybersecurity analyst specializing in phone-number scam detection."
            search_data = json.dumps(
                {
                    "risk_level": api_result.get("risk_level"),
                    "results_found": api_result.get("results_found"),
                    "references": api_result.get("references"),
                },
                indent=2,
                default=str,
            )
            variants = api_result.get("variants")
            user_content = (
                "PHONE NUMBER ANALYSIS PROMPT for llm\n\n"
                "Review the following online search results related to a phone number.\n\n"
                f"Search results:\n{search_data}\n\n"
                f"Phone number variants:\n{variants}\n\n"
                "Your task:\n"
                "Determine whether this phone number is associated with scams, spam, fraud, or suspicious activity.\n\n"
                "Guidelines:\n"
                "- Use only the provided search results.\n"
                "- If multiple sources report scams or complaints, mark the number as unsafe.\n"
                "- If there is insufficient information, clearly state that more data is required.\n\n"
                "Keep the explanation short and easy to understand.\n"
                "Output requirements:\n"
                "Provide the response in the following Markdown format:\n\n"
                "### Verdict\n"
                "**Malicious** / **Suspicious** / **Safe** / **Unknown**\n\n"
                "### Analysis\n"
                "- [Bullet point 1]\n"
                "- [Bullet point 2]\n\n"
                "### Recommendation\n"
                "[Actionable advice]\n"
            )
        else:
            system_prompt = "You are a cybersecurity analyst. Provide concise, accurate risk assessments."
            user_content = (
                f"Analyze this API result for {input_type} '{input_value}':\n\n"
                f"{api_result_str}\n\n"
                "Summarize the risk level (Low/Medium/High) and explain why based on the data. "
                "Suggest next steps if the input is risky, such as block or investigate."
            )
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {OPENROUTER_API_KEY}",
            "HTTP-Referer": "http://localhost",
            "X-Title": "Sentrsheild",
        }
        payload = {
            "model": OPENROUTER_MODEL,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content},
            ],
            "temperature": 0.1,
        }
        resp = requests.post("https://openrouter.ai/api/v1/chat/completions", headers=headers, json=payload, timeout=20)
        if resp.status_code != 200:
            error_msg = resp.text
            if resp.status_code == 429:
                return "AI analysis is currently experiencing high traffic (rate limited). Please wait a moment and try again."
            if "data policy" in error_msg.lower() or resp.status_code in [403, 404]:
                 return (
                    f"LLM analysis failed (Status {resp.status_code}). "
                    "This model may require data usage permissions. "
                    "Please enable 'Allow inputs and outputs to be used for model training' in your OpenRouter Privacy Settings: "
                    "https://openrouter.ai/settings/privacy"
                )
            return f"LLM analysis failed with status {resp.status_code}: {resp.text}"
        data = resp.json()
        print(f"\n[DEBUG-LLM-RESPONSE] Raw Output:\n{json.dumps(data, indent=2)}")
        choices = data.get("choices")
        if not choices:
            return "LLM analysis failed: no choices returned."
        analysis_text = choices[0].get("message", {}).get("content", "").strip()
        if not analysis_text:
            analysis_text = "LLM analysis returned an empty response."
    except Exception as exc:
        analysis_text = f"LLM analysis failed: {exc}"
    return analysis_text


def build_analysis_from_text(raw_input):
    analysis = {}
    if not raw_input:
        return analysis
    detected = detect_input_types(raw_input)
    analysis["kind"] = detected["kind"]
    if detected["kind"] == "email":
        sender_email = detected["sender_email"]
        analysis["email"] = analyze_email(sender_email, "", raw_input)
    elif detected["kind"] == "url":
        url_value = detected["url"] or raw_input
        analysis["url"] = scan_url_virustotal(url_value)
    elif detected["kind"] == "phone":
        phone_value = detected["phone"] or raw_input
        analysis["phone"] = check_phone_number(phone_value)
    message_is_high_risk = False
    if detected["kind"] == "message":
        # Analyze the message content
        msg_result = analyze_message(raw_input)
        analysis["message"] = msg_result
        
        # Check if message is already flagged as High Risk / Malicious
        # This prevents the subsequent Domain check (which might say "Safe" for fresh IPs) 
        # from overwriting the Malicious verdict in the UI.
        ai_summary = msg_result.get("ai_summary", "")
        url_results = msg_result.get("url_results", [])
        
        if "Malicious" in ai_summary or any(res.get("risk_level") == "High" for res in url_results):
             message_is_high_risk = True
             print(f"\n[DEBUG] Message is HIGH RISK. Skipping redundant Domain Check to preserve verdict.")

    # Only check domain reputation if the message itself is not already confirmed malicious
    if detected["domain"] and not message_is_high_risk:
        analysis["domain_risk"] = get_domains_risk_score(detected["domain"])
        analysis["dmarc"] = check_dmarc(detected["domain"])
        
        # Propagate URL risk to domain risk if high
        if analysis.get("url") and analysis["url"].get("risk_level") == "High":
             if analysis.get("domain_risk"):
                  current_score = analysis["domain_risk"].get("risk_score", 0)
                  analysis["domain_risk"]["risk_score"] = max(current_score, 90)
                  analysis["domain_risk"]["verdict"] = "malicious"
                  if "signals" not in analysis["domain_risk"]:
                       analysis["domain_risk"]["signals"] = []
                  analysis["domain_risk"]["signals"].append("URL flagged as malicious by multiple engines")
    if analysis:
        if "email" in analysis:
            email_value = analysis["email"].get("subject") or analysis["email"].get("sender_email") or ""
            analysis["email"]["llm_summary"] = run_llm_analysis("email", email_value, analysis["email"])
        if "message" in analysis:
            message_value = analysis["message"].get("message") or ""
            llm_result = run_llm_analysis("message", message_value, analysis["message"])
            analysis["message"]["llm_summary"] = llm_result
            
            # Parse LLM Verdict to override risk level if necessary
            # Look for ### Verdict -> Malicious/Suspicious/Safe
            import re
            verdict_match = re.search(r"Verdict\s*\n\**(\w+)\**", llm_result, re.IGNORECASE)
            if verdict_match:
                llm_verdict = verdict_match.group(1).lower()
                current_risk = "Low"
                risk_reason = "Evaluated by AI Analysis"
                
                if "malicious" in llm_verdict:
                    current_risk = "High"
                    risk_reason = "Flagged as Malicious by AI"
                elif "suspicious" in llm_verdict:
                    current_risk = "Medium" 
                    risk_reason = "Flagged as Suspicious by AI"
                elif "safe" in llm_verdict:
                    current_risk = "Low"
                    risk_reason = "Verified Safe by AI"
                    
                # Update text_assessment if LLM finds it risky
                # We prioritize LLM verdict BUT we must NOT downgrade a hard "High" risk from URL/Domain scans
                
                existing_risk = analysis["message"].get("overall_risk")
                
                # If we already have High risk from metadata (links/domain), only allow LLM to confirm or add info, never safe-wash it.
                if existing_risk == "High":
                    current_risk = "High"
                    if "safe" in llm_verdict:
                        risk_reason = "Malicious Link detected (overriding AI 'Safe' verdict)"
                    else:
                        risk_reason = f"Flagged as {llm_verdict.title()} by AI + Malicious Link"
                
                if "text_assessment" not in analysis["message"]:
                    analysis["message"]["text_assessment"] = {}
                
                analysis["message"]["text_assessment"]["risk_level"] = current_risk
                analysis["message"]["text_assessment"]["reason"] = risk_reason
                analysis["message"]["overall_risk"] = current_risk
        if "phone" in analysis and not analysis["phone"].get("error"):
            phone_value = analysis["phone"].get("phone_number") or ""
            llm_result = run_llm_analysis("phone", phone_value, analysis["phone"])
            analysis["phone"]["llm_summary"] = llm_result
            
            # Parse LLM Verdict to override risk level if necessary
            import re
            verdict_match = re.search(r"Verdict\s*\n\**(\w+)\**", llm_result, re.IGNORECASE)
            if verdict_match:
                llm_verdict = verdict_match.group(1).lower()
                
                # Only override if LLM finds risk or if current is unknown/safe but LLM is confident
                current_risk = analysis["phone"].get("risk_level", "Unknown")
                
                new_risk = None
                if "malicious" in llm_verdict:
                    new_risk = "High"
                elif "suspicious" in llm_verdict:
                    new_risk = "Suspicious"
                elif "safe" in llm_verdict and current_risk == "Unknown":
                    new_risk = "Low"
                    
                if new_risk:
                     # Prioritize the highest risk between keyword search and LLM
                     # If keyword says High, keep it. If LLM says High and keyword says Low, upgrade.
                     severity = {"High": 3, "Suspicious": 2, "Low": 1, "Unknown": 0, "Safe (no strong evidence)": 0}
                     
                     current_severity = severity.get(current_risk, 0)
                     new_severity = severity.get(new_risk, 0)
                     
                     if new_severity > current_severity:
                         analysis["phone"]["risk_level"] = new_risk
        if "url" in analysis and not analysis["url"].get("error"):
            url_value = analysis["url"].get("url") or ""
            analysis["url"]["llm_summary"] = run_llm_analysis("url", url_value, analysis["url"])
        if "domain_risk" in analysis and not analysis["domain_risk"].get("error"):
            domain_value = analysis["domain_risk"].get("domain") or ""
            analysis["domain_risk"]["llm_summary"] = run_llm_analysis("domain", domain_value, analysis["domain_risk"])
    return analysis


def save_image_file_to_temp(image_file):
    filename = secure_filename(image_file.filename or "uploaded")
    _, ext = os.path.splitext(filename)
    fd, temp_path = tempfile.mkstemp(suffix=ext or ".png")
    os.close(fd)
    image_file.save(temp_path)
    return temp_path


@app.route("/features")
def features():
    return render_template("features.html")


@app.route("/how-it-works")
def how_it_works():
    return render_template("how_it_works.html")


@app.route("/dashboard")
def dashboard():
    total_scans = len(RECENT_ANALYSES)
    threat_count = 0
    safe_count = 0
    recent_threats = []

    sorted_analyses = sorted(
        RECENT_ANALYSES.values(),
        key=lambda x: x.get("created_at", 0),
        reverse=True
    )

    for entry in sorted_analyses:
        analysis = entry.get("analysis", {})
        risk_label = None
        
        # Determine risk label priority
        if analysis.get("domain_risk") and analysis["domain_risk"].get("verdict"):
             risk_label = analysis["domain_risk"]["verdict"]
        elif analysis.get("url") and analysis["url"].get("risk_level"):
             risk_label = analysis["url"]["risk_level"]
        elif analysis.get("email") and analysis["email"].get("overall_risk"):
             risk_label = analysis["email"]["overall_risk"]
        elif analysis.get("message") and analysis["message"].get("overall_risk"):
             risk_label = analysis["message"]["overall_risk"]
        elif analysis.get("phone") and analysis["phone"].get("risk_level"):
             risk_label = analysis["phone"]["risk_level"]

        if risk_label and risk_label.lower() in ['malicious', 'high', 'suspicious', 'medium', 'moderate']:
            threat_count += 1
            recent_threats.append(entry)
        else:
            safe_count += 1

    return render_template(
        "dashboard.html",
        total_scans=total_scans,
        threat_count=threat_count,
        safe_count=safe_count,
        recent_threats=recent_threats[:5] # Show top 5 recent threats
    )


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "GET":
        # Sort analyses by created_at descending
        sorted_analyses = sorted(
            RECENT_ANALYSES.values(), 
            key=lambda x: x.get("created_at", 0), 
            reverse=True
        )
        return render_template(
            "homepage.html", 
            analysis=None, 
            input_text_value="", 
            image_error=None, 
            scan_id=None,
            recent_analyses=sorted_analyses
        )
    analysis = {}
    input_text_value = ""
    image_error = None
    image_file = request.files.get("image_file")
    raw_input = request.form.get("input_text", "").strip()
    input_text_value = raw_input
    if image_file and image_file.filename:
        temp_path = None
        try:
            temp_path = save_image_file_to_temp(image_file)
            ocr_text = ""
            try:
                ocr_text = extract_text_from_image(temp_path) or ""
            except Exception:
                ocr_text = ""
            qr_values = []
            try:
                qr_values = decode_qr(temp_path) or []
            except Exception:
                qr_values = []
            candidate_value = None
            if qr_values:
                for value in qr_values:
                    if not value:
                        continue
                    detected_qr = detect_input_types(value)
                    if detected_qr["kind"]:
                        candidate_value = value.strip()
                        break
            if not candidate_value and ocr_text:
                urls = extract_urls(ocr_text)
                if urls:
                    candidate_value = urls[0]
                else:
                    candidate_value = ocr_text.strip()
            if candidate_value:
                analysis = build_analysis_from_text(candidate_value)
                input_text_value = candidate_value
            else:
                image_error = "Could not read any text or QR code from this image. Try a clearer screenshot or paste the text manually."
        finally:
            if temp_path and os.path.exists(temp_path):
                os.remove(temp_path)
    elif raw_input:
        analysis = build_analysis_from_text(raw_input)
    if analysis:
        scan_id = uuid.uuid4().hex
        RECENT_ANALYSES[scan_id] = {
            "analysis": analysis,
            "input_text_value": input_text_value,
            "created_at": time.time(),
            "scan_id": scan_id
        }
        return redirect(url_for("result", scan_id=scan_id))
    
    # Sort analyses by created_at descending for POST render (fallback)
    sorted_analyses = sorted(
        RECENT_ANALYSES.values(), 
        key=lambda x: x.get("created_at", 0), 
        reverse=True
    )
    return render_template(
        "homepage.html", 
        analysis=None, 
        input_text_value=input_text_value, 
        image_error=image_error, 
        scan_id=None,
        recent_analyses=sorted_analyses
    )


@app.route("/clear_history", methods=["POST"])
def clear_history():
    RECENT_ANALYSES.clear()
    return redirect(url_for("index"))


@app.route("/result", methods=["GET"])
def result():
    scan_id = request.args.get("scan_id")
    entry = RECENT_ANALYSES.get(scan_id) if scan_id else None
    analysis = None
    input_text_value = ""
    ui_data = {}
    if entry:
        analysis = entry.get("analysis") or {}
        input_text_value = entry.get("input_text_value") or ""
        ui_data = get_ui_risk_data(analysis)
    
    return render_template(
        "result.html", 
        analysis=analysis, 
        input_text_value=input_text_value, 
        scan_id=scan_id,
        **ui_data
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=False)

# TOUCH TEST
