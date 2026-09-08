import re
import time
import base64
import requests
from flask import Flask, render_template, request, jsonify
from urllib.parse import urlparse

app = Flask(__name__)

# ============================================================
# 🔑 SET YOUR VIRUSTOTAL API KEY HERE (ONCE)
# ============================================================
VIRUSTOTAL_API_KEY = "b77289cdbd662ce006893cdb48207da19f1fac3769d08ac8c46bfea264da13a6"   # <--- Replace with your key
VT_MAX_WAIT = 60   # seconds to wait for scan completion

# ========== LOCAL RULES (instant) ==========
BAD_KEYWORDS = [
    'login', 'verify', 'account', 'secure', 'update', 'banking', 'signin', 'password',
    'confirm', 'validate', 'authenticate', 'security', 'alert', 'unlock', 'suspend',
    'upgrade', 'paypal', 'ebay', 'apple', 'microsoft', 'google', 'amazon', 'facebook',
    'instagram', 'whatsapp', 'dropbox', 'outlook', 'office365', 'icloud', 'gmail',
    'yahoo', 'aol', 'chase', 'wellsfargo', 'bankofamerica', 'citibank'
]

BAD_TLDS = [
    '.tk', '.ml', '.ga', '.cf', '.top', '.xyz', '.gq', '.bid',
    '.click', '.download', '.party', '.date', '.country', '.stream', '.gdn',
    '.mom', '.lol', '.men', '.win', '.review', '.trade', '.surf', '.science',
    '.racing', '.webcam', '.loan', '.accountant', '.cricket', '.property'
]

SHORTENERS = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 'tiny.cc', 'is.gd',
    'buff.ly', 'rebrand.ly', 'short.link', 'cutt.ly', 'shrtco.de', 'v.gd',
    'dub.sh', 't.co', 'lnkd.in', 'mzl.la'
]

def rule_check(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        full = url.lower()
        score = 0
        flags = []

        if any(k in full for k in BAD_KEYWORDS):
            score += 10
            flags.append('Contains suspicious keyword')
        if any(domain.endswith(t) for t in BAD_TLDS):
            score += 20
            flags.append('Uses risky top‑level domain')
        if any(s in domain for s in SHORTENERS):
            score += 15
            flags.append('URL shortened')
        if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', domain):
            score += 20
            flags.append('Direct IP address used')
        if '@' in full:
            score += 25
            flags.append('Contains @ (possible credential harvester)')
        if len(domain.split('.')) > 4:
            score += 10
            flags.append('Many subdomains')
        if 'example' in full or 'test' in full:
            score += 5
            flags.append('Contains "example" or "test" (often suspicious)')

        # Brand impersonation
        brands = ['paypal', 'ebay', 'apple', 'microsoft', 'google', 'amazon', 'facebook',
                  'instagram', 'whatsapp', 'dropbox', 'outlook', 'gmail', 'yahoo', 'aol',
                  'chase', 'wellsfargo', 'bankofamerica', 'citibank']
        for brand in brands:
            if brand in full and brand not in domain:
                score += 15
                flags.append(f'Brand impersonation: "{brand}" appears but domain is not {brand}')
                break

        return min(score, 100), flags
    except:
        return 0, ['Invalid URL format']

# ========== VIRUSTOTAL WITH POLLING ==========
def vt_check(url, api_key, max_wait=VT_MAX_WAIT):
    if not api_key:
        return None, None, None

    headers = {"x-apikey": api_key}
    try:
        # Submit URL
        r = requests.post("https://www.virustotal.com/api/v3/urls",
                          headers=headers, data={"url": url}, timeout=10)
        if r.status_code != 200:
            return None, None, f"Submission error: {r.status_code}"

        analysis_id = r.json()["data"]["id"]

        # Poll for completion
        start = time.time()
        while time.time() - start < max_wait:
            r = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                             headers=headers, timeout=10)
            if r.status_code != 200:
                return None, None, f"Analysis fetch error: {r.status_code}"

            data = r.json()["data"]
            status = data["attributes"]["status"]
            if status == "completed":
                stats = data["attributes"]["stats"]
                # Get detailed vendor results
                url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
                report_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
                r2 = requests.get(report_url, headers=headers, timeout=10)
                detections = []
                if r2.status_code == 200:
                    results = r2.json()["data"]["attributes"]["last_analysis_results"]
                    for vendor, result in results.items():
                        if result["category"] in ["malicious", "suspicious"]:
                            detections.append({
                                "vendor": vendor,
                                "category": result["category"],
                                "result": result["result"]
                            })
                return stats, detections, None
            time.sleep(2)

        return None, None, f"Analysis timed out after {max_wait}s"

    except Exception as e:
        return None, None, str(e)

# ========== FLASK ROUTES ==========
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/check', methods=['POST'])
def check_url():
    url = request.json.get('url', '').strip()
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    # 1. Local rules
    rule_score, flags = rule_check(url)

    # 2. VirusTotal
    vt_stats = None
    vt_detections = None
    vt_error = None
    if VIRUSTOTAL_API_KEY:
        vt_stats, vt_detections, vt_error = vt_check(url, VIRUSTOTAL_API_KEY)

    # 3. Final verdict
    verdict = 'SAFE'
    reason = 'No threats detected by VirusTotal or local rules'
    if vt_stats and vt_stats.get('malicious', 0) > 0:
        verdict = 'UNSAFE'
        reason = f"{vt_stats['malicious']} antivirus engines flagged it as malicious"
    elif vt_stats and vt_stats.get('suspicious', 0) >= 3:
        verdict = 'UNSAFE'
        reason = f"{vt_stats['suspicious']} engines flagged as suspicious"
    elif rule_score >= 25:
        verdict = 'UNSAFE'
        reason = 'Local rule engine flagged suspicious patterns'

    return jsonify({
        'url': url,
        'ruleScore': rule_score,
        'flags': flags,
        'vtStats': vt_stats,
        'vtDetections': vt_detections[:10] if vt_detections else [],
        'vtError': vt_error,
        'verdict': verdict,
        'reason': reason,
    })

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)