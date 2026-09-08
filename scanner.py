import re
import time
import requests
from urllib.parse import urlparse

# ============================================================
# 🔑 SET YOUR VIRUSTOTAL API KEY HERE (ONCE)
# ============================================================
VIRUSTOTAL_API_KEY = "b77289cdbd662ce006893cdb48207da19f1fac3769d08ac8c46bfea264da13a6"   # Replace with your actual key
# ============================================================

# ========== LOCAL RULES (instant) ==========
BAD_KEYWORDS = ['login', 'verify', 'account', 'secure', 'update', 'banking', 'signin', 'password']
BAD_TLDS = ['.tk', '.ml', '.ga', '.cf', '.top', '.xyz', '.gq', '.bid']
SHORTENERS = ['bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 'tiny.cc']

def rule_check(url):
    score = 0
    domain = urlparse(url).netloc.lower()
    full = url.lower()

    if any(k in full for k in BAD_KEYWORDS): score += 10
    if any(domain.endswith(t) for t in BAD_TLDS): score += 15
    if any(s in domain for s in SHORTENERS): score += 10
    if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', domain): score += 20
    if '@' in full: score += 25
    if len(domain.split('.')) > 4: score += 5

    return min(score, 100)

# ========== VIRUSTOTAL WITH POLLING ==========
def vt_check(url, api_key, max_wait=30):
    """
    Submits URL, polls until analysis is complete or timeout.
    Returns (stats_dict, list_of_detections, error_message)
    """
    if not api_key:
        return None, None, None

    headers = {"x-apikey": api_key}
    try:
        # 1. Submit URL
        r = requests.post("https://www.virustotal.com/api/v3/urls",
                          headers=headers, data={"url": url}, timeout=10)
        if r.status_code != 200:
            return None, None, f"Submission error: {r.status_code}"

        analysis_id = r.json()["data"]["id"]

        # 2. Poll for completion
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
                # Also fetch the detailed report to get vendor names
                # We need to get the URL ID to fetch the actual report
                url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
                report_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
                r2 = requests.get(report_url, headers=headers, timeout=10)
                if r2.status_code == 200:
                    results = r2.json()["data"]["attributes"]["last_analysis_results"]
                    detections = []
                    for vendor, result in results.items():
                        if result["category"] in ["malicious", "suspicious"]:
                            detections.append({
                                "vendor": vendor,
                                "category": result["category"],
                                "result": result["result"]
                            })
                    return stats, detections, None
                else:
                    # Fallback: return just stats without vendor list
                    return stats, None, None
            # Not completed yet – wait a bit
            time.sleep(2)

        return None, None, f"Analysis timed out after {max_wait}s"

    except Exception as e:
        return None, None, str(e)

# ========== MAIN LOOP ==========
def main():
    print("\n" + "="*60)
    print("🔐 REAL‑TIME URL SAFETY CHECKER (with VirusTotal)")
    print("Type a URL and press Enter – get the final verdict after full scan.")
    print("Type 'quit' to exit.")
    print("="*60)

    if VIRUSTOTAL_API_KEY:
        print("✅ VirusTotal enabled (70+ scanners) – will wait for completion.")
    else:
        print("⚠️  Using local rules only (no API)")

    while True:
        url = input("\n📎 URL: ").strip()
        if url.lower() in ('quit', 'exit', 'q'):
            print("👋 Bye!")
            break
        if not url:
            continue
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        print("   ⏳ Scanning with VirusTotal (please wait, up to 30s)...")

        # 1. Local rule check (instant)
        score = rule_check(url)

        # 2. VirusTotal (polling)
        vt_stats = None
        vt_detections = None
        vt_error = None
        if VIRUSTOTAL_API_KEY:
            vt_stats, vt_detections, vt_error = vt_check(url, VIRUSTOTAL_API_KEY)

        # 3. Display results
        if vt_error:
            print(f"   ⚠️  VirusTotal error: {vt_error}")
        elif vt_stats:
            total = sum(vt_stats.values())
            print(f"\n🛡️  VirusTotal results (out of {total} scanners):")
            print(f"   🚨 Malicious:  {vt_stats['malicious']}")
            print(f"   ⚠️  Suspicious: {vt_stats['suspicious']}")
            print(f"   ✅ Harmless:   {vt_stats['harmless']}")
            print(f"   ❓ Undetected: {vt_stats['undetected']}")

            if vt_detections:
                print("\n   🔍 Detected by these vendors:")
                for d in vt_detections[:10]:  # show first 10 to avoid spam
                    print(f"      - {d['vendor']}: {d['result']} ({d['category']})")
                if len(vt_detections) > 10:
                    print(f"      ... and {len(vt_detections)-10} more")

        # 4. Final verdict
        if vt_stats and vt_stats['malicious'] > 0:
            verdict = "UNSAFE / PHISHING"
            reason = f"{vt_stats['malicious']} antivirus engines flagged it as malicious"
        elif vt_stats and vt_stats['suspicious'] >= 3:
            verdict = "UNSAFE / PHISHING"
            reason = f"{vt_stats['suspicious']} engines flagged as suspicious"
        elif score >= 35:
            verdict = "UNSAFE / PHISHING"
            reason = "Local rule engine flagged suspicious patterns"
        else:
            verdict = "SAFE"
            reason = "No threats detected by VirusTotal or local rules"

        if verdict == "UNSAFE / PHISHING":
            print(f"\n🚨🚨🚨  {verdict}  🚨🚨🚨")
            print(f"   Reason: {reason}")
            print("   DO NOT VISIT THIS SITE!")
        else:
            print(f"\n✅✅✅  {verdict}  ✅✅✅")
            print("   (but always stay cautious)")

if __name__ == "__main__":
    import base64   # needed inside the function, import at top
    main()