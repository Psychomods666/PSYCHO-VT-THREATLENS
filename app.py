
import os
import re
import time
import base64
import requests

from flask import Flask, render_template, request, jsonify
from urllib.parse import urlparse


app = Flask(__name__)


# ============================================================
# 🔐 VIRUSTOTAL CONFIGURATION
# ============================================================
#
# DO NOT put your real API key directly in this file.
#
# Windows PowerShell:
#
#   $env:VIRUSTOTAL_API_KEY="YOUR_API_KEY"
#
# Then run:
#
#   python scanner.py
#
# Or use a .env file if you configure python-dotenv.
#
# ============================================================

VIRUSTOTAL_API_KEY = os.getenv("b77289cdbd662ce006893cdb48207da19f1fac3769d08ac8c46bfea264da13a6")

VT_MAX_WAIT = 60
VT_POLL_INTERVAL = 3


# ============================================================
# 🚨 LOCAL SUSPICIOUS URL RULES
# ============================================================

BAD_KEYWORDS = [
    "login",
    "verify",
    "account",
    "secure",
    "update",
    "banking",
    "signin",
    "password",
    "confirm",
    "validate",
    "authenticate",
    "security",
    "alert",
    "unlock",
    "suspend",
    "upgrade",
    "paypal",
    "ebay",
    "apple",
    "microsoft",
    "google",
    "amazon",
    "facebook",
    "instagram",
    "whatsapp",
    "dropbox",
    "outlook",
    "office365",
    "icloud",
    "gmail",
    "yahoo",
    "aol",
    "chase",
    "wellsfargo",
    "bankofamerica",
    "citibank",
]


BAD_TLDS = [
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".top",
    ".xyz",
    ".gq",
    ".bid",
    ".click",
    ".download",
    ".party",
    ".date",
    ".country",
    ".stream",
    ".gdn",
    ".mom",
    ".lol",
    ".men",
    ".win",
    ".review",
    ".trade",
    ".surf",
    ".science",
    ".racing",
    ".webcam",
    ".loan",
    ".accountant",
    ".cricket",
    ".property",
]


SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "ow.ly",
    "tiny.cc",
    "is.gd",
    "buff.ly",
    "rebrand.ly",
    "short.link",
    "cutt.ly",
    "shrtco.de",
    "v.gd",
    "dub.sh",
    "t.co",
    "lnkd.in",
    "mzl.la",
]


BRANDS = [
    "paypal",
    "ebay",
    "apple",
    "microsoft",
    "google",
    "amazon",
    "facebook",
    "instagram",
    "whatsapp",
    "dropbox",
    "outlook",
    "gmail",
    "yahoo",
    "aol",
    "chase",
    "wellsfargo",
    "bankofamerica",
    "citibank",
]


# ============================================================
# 🧠 LOCAL RULE ENGINE
# ============================================================

def rule_check(url):

    try:

        parsed = urlparse(url)

        domain = parsed.netloc.lower()

        # Remove username/password if present
        if "@" in domain:
            domain = domain.split("@")[-1]

        # Remove port
        domain = domain.split(":")[0]

        full = url.lower()

        score = 0

        flags = []


        # ----------------------------------------------------
        # Suspicious keywords
        # ----------------------------------------------------

        matched_keywords = [
            keyword
            for keyword in BAD_KEYWORDS
            if keyword in full
        ]

        if matched_keywords:

            score += 10

            flags.append(
                "Contains suspicious keyword(s): "
                + ", ".join(matched_keywords[:5])
            )


        # ----------------------------------------------------
        # Risky TLD
        # ----------------------------------------------------

        matched_tld = next(
            (
                tld
                for tld in BAD_TLDS
                if domain.endswith(tld)
            ),
            None
        )

        if matched_tld:

            score += 20

            flags.append(
                f"Uses risky top-level domain: {matched_tld}"
            )


        # ----------------------------------------------------
        # URL shortener
        # ----------------------------------------------------

        matched_shortener = next(
            (
                shortener
                for shortener in SHORTENERS
                if shortener in domain
            ),
            None
        )

        if matched_shortener:

            score += 15

            flags.append(
                f"URL shortener detected: {matched_shortener}"
            )


        # ----------------------------------------------------
        # Direct IP address
        # ----------------------------------------------------

        if re.match(
            r"^(\d{1,3}\.){3}\d{1,3}$",
            domain
        ):

            score += 20

            flags.append(
                "Direct IP address used instead of domain name"
            )


        # ----------------------------------------------------
        # @ symbol
        # ----------------------------------------------------

        if "@" in full:

            score += 25

            flags.append(
                "Contains @ symbol - possible credential "
                "harvesting technique"
            )


        # ----------------------------------------------------
        # Many subdomains
        # ----------------------------------------------------

        if len(domain.split(".")) > 4:

            score += 10

            flags.append(
                "Unusually large number of subdomains"
            )


        # ----------------------------------------------------
        # Example/test domains
        # ----------------------------------------------------

        if "example" in full or "test" in full:

            score += 5

            flags.append(
                'Contains "example" or "test"'
            )


        # ----------------------------------------------------
        # Brand impersonation
        # ----------------------------------------------------

        for brand in BRANDS:

            if brand in full and brand not in domain:

                score += 15

                flags.append(
                    f'Possible brand impersonation: "{brand}"'
                )

                break


        return min(score, 100), flags


    except Exception:

        return 0, [
            "Invalid URL format"
        ]


# ============================================================
# 🦠 VIRUSTOTAL SCANNER
# ============================================================

def vt_check(
    url,
    api_key,
    max_wait=VT_MAX_WAIT
):

    if not api_key:

        return (
            None,
            [],
            "VirusTotal API key is not configured"
        )


    headers = {

        "x-apikey": api_key,

        "accept": "application/json",

    }


    try:

        # ====================================================
        # STEP 1 — SUBMIT URL
        # ====================================================

        print()
        print("=" * 70)
        print("VIRUSTOTAL SCAN")
        print("=" * 70)

        print(
            f"[VT] Submitting URL: {url}"
        )


        submit_response = requests.post(

            "https://www.virustotal.com/api/v3/urls",

            headers=headers,

            data={
                "url": url
            },

            timeout=20

        )


        # ----------------------------------------------------
        # Submission status
        # ----------------------------------------------------

        if submit_response.status_code not in [200, 201]:

            try:

                error_data = submit_response.json()

            except Exception:

                error_data = submit_response.text


            return (

                None,

                [],

                (
                    "VirusTotal submission error "
                    f"{submit_response.status_code}: "
                    f"{error_data}"
                )

            )


        submit_data = submit_response.json()


        # ----------------------------------------------------
        # Get analysis ID
        # ----------------------------------------------------

        try:

            analysis_id = (
                submit_data["data"]["id"]
            )

        except KeyError:

            return (

                None,

                [],

                "VirusTotal response did not contain analysis ID"

            )


        print(
            f"[VT] Analysis ID: {analysis_id}"
        )


        # ====================================================
        # STEP 2 — WAIT FOR ANALYSIS
        # ====================================================

        start_time = time.time()

        analysis_attributes = None


        while (
            time.time() - start_time
            < max_wait
        ):

            analysis_response = requests.get(

                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",

                headers=headers,

                timeout=20

            )


            if analysis_response.status_code != 200:

                return (

                    None,

                    [],

                    (
                        "VirusTotal analysis fetch error "
                        f"{analysis_response.status_code}: "
                        f"{analysis_response.text}"
                    )

                )


            analysis_json = (
                analysis_response.json()
            )


            analysis_data = (
                analysis_json.get("data", {})
            )


            analysis_attributes = (
                analysis_data.get(
                    "attributes",
                    {}
                )
            )


            status = (
                analysis_attributes.get(
                    "status"
                )
            )


            print(
                f"[VT] Analysis status: {status}"
            )


            # ------------------------------------------------
            # Completed
            # ------------------------------------------------

            if status == "completed":

                break


            # ------------------------------------------------
            # Failed
            # ------------------------------------------------

            if status in [
                "failed",
                "error"
            ]:

                return (

                    None,

                    [],

                    (
                        "VirusTotal analysis failed "
                        f"with status: {status}"
                    )

                )


            time.sleep(
                VT_POLL_INTERVAL
            )


        else:

            return (

                None,

                [],

                (
                    "VirusTotal analysis timed out "
                    f"after {max_wait} seconds"
                )

            )


        # ====================================================
        # STEP 3 — GET ANALYSIS STATS
        # ====================================================

        stats = (
            analysis_attributes.get(
                "stats",
                {}
            )
        )


        print()
        print("[VT] Analysis statistics")
        print("-" * 50)

        print(
            f"Malicious   : "
            f"{stats.get('malicious', 0)}"
        )

        print(
            f"Suspicious  : "
            f"{stats.get('suspicious', 0)}"
        )

        print(
            f"Harmless    : "
            f"{stats.get('harmless', 0)}"
        )

        print(
            f"Undetected  : "
            f"{stats.get('undetected', 0)}"
        )

        print(
            f"Timeout     : "
            f"{stats.get('timeout', 0)}"
        )


        # ====================================================
        # STEP 4 — GET VENDOR RESULTS
        # ====================================================

        analysis_results = (
            analysis_attributes.get(
                "results",
                {}
            )
        )


        all_vendors = []

        detections = []


        for vendor_name, vendor_data in (
            analysis_results.items()
        ):

            category = vendor_data.get(
                "category",
                "undetected"
            )


            result = vendor_data.get(
                "result"
            )


            vendor_info = {

                "vendor": vendor_name,

                "category": category,

                "result": result,

                "method": vendor_data.get(
                    "method"
                ),

                "engine_name": vendor_data.get(
                    "engine_name"
                ),

                "engine_version": vendor_data.get(
                    "engine_version"
                ),

                "engine_update": vendor_data.get(
                    "engine_update"
                ),

            }


            all_vendors.append(
                vendor_info
            )


            # ------------------------------------------------
            # Malicious / Suspicious
            # ------------------------------------------------

            if category in [
                "malicious",
                "suspicious"
            ]:

                detections.append(
                    vendor_info
                )


        print()
        print(
            f"[VT] Vendors returned: "
            f"{len(all_vendors)}"
        )

        print(
            f"[VT] Detections: "
            f"{len(detections)}"
        )


        # ====================================================
        # STEP 5 — FALLBACK TO URL OBJECT
        # ====================================================

        #
        # VirusTotal URL ID:
        # URL encoded using URL-safe base64
        # without '=' padding.
        #

        url_id = (
            base64.urlsafe_b64encode(
                url.encode("utf-8")
            )
            .decode("utf-8")
            .rstrip("=")
        )


        report_response = requests.get(

            f"https://www.virustotal.com/api/v3/urls/{url_id}",

            headers=headers,

            timeout=20

        )


        if report_response.status_code == 200:

            report_json = (
                report_response.json()
            )


            report_data = (
                report_json.get(
                    "data",
                    {}
                )
            )


            report_attributes = (
                report_data.get(
                    "attributes",
                    {}
                )
            )


            # ------------------------------------------------
            # Latest analysis statistics
            # ------------------------------------------------

            latest_stats = (
                report_attributes.get(
                    "last_analysis_stats"
                )
            )


            if latest_stats:

                stats = latest_stats


            # ------------------------------------------------
            # Latest vendor results
            # ------------------------------------------------

            latest_results = (
                report_attributes.get(
                    "last_analysis_results",
                    {}
                )
            )


            # If analysis endpoint didn't give vendors,
            # use URL report vendors.
            #

            if latest_results:

                existing_vendors = {
                    vendor["vendor"]
                    for vendor in all_vendors
                }


                for vendor_name, vendor_data in (
                    latest_results.items()
                ):

                    category = vendor_data.get(
                        "category",
                        "undetected"
                    )


                    vendor_info = {

                        "vendor": vendor_name,

                        "category": category,

                        "result": vendor_data.get(
                            "result"
                        ),

                        "method": vendor_data.get(
                            "method"
                        ),

                        "engine_name": vendor_data.get(
                            "engine_name"
                        ),

                        "engine_version": vendor_data.get(
                            "engine_version"
                        ),

                        "engine_update": vendor_data.get(
                            "engine_update"
                        ),

                    }


                    if vendor_name not in existing_vendors:

                        all_vendors.append(
                            vendor_info
                        )

                        existing_vendors.add(
                            vendor_name
                        )


                    # Add detection if missing

                    if category in [
                        "malicious",
                        "suspicious"
                    ]:

                        already_detected = any(

                            detection["vendor"]
                            == vendor_name

                            for detection
                            in detections

                        )


                        if not already_detected:

                            detections.append(
                                vendor_info
                            )


        # ====================================================
        # STEP 6 — SORT VENDORS
        # ====================================================

        category_order = {

            "malicious": 0,

            "suspicious": 1,

            "harmless": 2,

            "undetected": 3,

            "timeout": 4,

        }


        all_vendors.sort(

            key=lambda vendor:

            category_order.get(

                vendor.get(
                    "category"
                ),

                99

            )

        )


        # ====================================================
        # PRINT DETECTIONS
        # ====================================================

        print()
        print("[VT] Vendor detections")
        print("-" * 70)


        if detections:

            for detection in detections:

                print(

                    f"{detection.get('vendor')} "
                    f"| "
                    f"{detection.get('category')} "
                    f"| "
                    f"{detection.get('result')}"

                )

        else:

            print(
                "No malicious/suspicious detections reported"
            )


        print("=" * 70)
        print()


        # ====================================================
        # RETURN DATA
        # ====================================================

        vt_data = {

            "stats": stats,

            "total_vendors": len(
                all_vendors
            ),

            "vendors": all_vendors,

        }


        return (

            vt_data,

            detections,

            None

        )


    # ========================================================
    # NETWORK ERROR
    # ========================================================

    except requests.exceptions.Timeout:

        return (

            None,

            [],

            "VirusTotal request timed out"

        )


    # ========================================================
    # REQUEST ERROR
    # ========================================================

    except requests.exceptions.RequestException as e:

        return (

            None,

            [],

            f"VirusTotal network error: {str(e)}"

        )


    # ========================================================
    # UNKNOWN ERROR
    # ========================================================

    except Exception as e:

        return (

            None,

            [],

            f"VirusTotal unexpected error: {str(e)}"

        )


# ============================================================
# 🌐 HOME PAGE
# ============================================================

@app.route("/")
def index():

    return render_template(
        "index.html"
    )


# ============================================================
# 🔍 CHECK URL
# ============================================================

@app.route(
    "/check",
    methods=["POST"]
)
def check_url():

    try:

        # ----------------------------------------------------
        # Read JSON
        # ----------------------------------------------------

        data = request.get_json(
            silent=True
        )


        if not data:

            return jsonify({

                "error": "Invalid JSON request"

            }), 400


        url = data.get(
            "url",
            ""
        ).strip()


        # ----------------------------------------------------
        # URL missing
        # ----------------------------------------------------

        if not url:

            return jsonify({

                "error": "No URL provided"

            }), 400


        # ----------------------------------------------------
        # Add protocol if missing
        # ----------------------------------------------------

        if not url.startswith(
            (
                "http://",
                "https://"
            )
        ):

            url = (
                "http://"
                + url
            )


        # ====================================================
        # 1. LOCAL RULE ENGINE
        # ====================================================

        rule_score, flags = (
            rule_check(url)
        )


        # ====================================================
        # 2. VIRUSTOTAL
        # ====================================================

        vt_data = None

        vt_detections = []

        vt_error = None


        if VIRUSTOTAL_API_KEY:

            (
                vt_data,
                vt_detections,
                vt_error
            ) = vt_check(

                url,

                VIRUSTOTAL_API_KEY

            )

        else:

            vt_error = (
                "VirusTotal API key is not configured. "
                "Set VIRUSTOTAL_API_KEY as an environment variable."
            )


        # ====================================================
        # 3. VIRUSTOTAL STATS
        # ====================================================

        vt_stats = None


        if vt_data:

            vt_stats = vt_data.get(
                "stats",
                {}
            )


        malicious_count = 0

        suspicious_count = 0


        if vt_stats:

            malicious_count = vt_stats.get(
                "malicious",
                0
            )

            suspicious_count = vt_stats.get(
                "suspicious",
                0
            )


        # ====================================================
        # 4. FINAL VERDICT
        # ====================================================

        verdict = "SAFE"


        reason = (
            "No threats detected by "
            "VirusTotal or local rules"
        )


        # ----------------------------------------------------
        # VirusTotal malicious
        # ----------------------------------------------------

        if malicious_count > 0:

            verdict = "UNSAFE"

            reason = (

                f"{malicious_count} antivirus "
                "engine(s) flagged this URL "
                "as malicious"

            )


        # ----------------------------------------------------
        # VirusTotal suspicious
        # ----------------------------------------------------

        elif suspicious_count >= 3:

            verdict = "UNSAFE"

            reason = (

                f"{suspicious_count} antivirus "
                "engine(s) flagged this URL "
                "as suspicious"

            )


        # ----------------------------------------------------
        # Local rule engine
        # ----------------------------------------------------

        elif rule_score >= 25:

            verdict = "UNSAFE"

            reason = (
                "Local rule engine detected "
                "multiple suspicious URL patterns"
            )


        # ----------------------------------------------------
        # Only 1–2 suspicious vendors
        # ----------------------------------------------------

        elif suspicious_count > 0:

            verdict = "SUSPICIOUS"

            reason = (

                f"{suspicious_count} antivirus "
                "engine(s) reported the URL "
                "as suspicious"

            )


        # ====================================================
        # 5. BUILD RESPONSE
        # ====================================================

        response = {

            "success": True,

            "url": url,


            # ------------------------------------------------
            # Local engine
            # ------------------------------------------------

            "ruleScore": rule_score,

            "flags": flags,


            # ------------------------------------------------
            # VirusTotal statistics
            # ------------------------------------------------

            "vtStats": vt_stats,


            # ------------------------------------------------
            # Total vendors
            # ------------------------------------------------

            "vtTotalVendors": (

                vt_data.get(
                    "total_vendors",
                    0
                )

                if vt_data

                else 0

            ),


            # ------------------------------------------------
            # Malicious/suspicious only
            # ------------------------------------------------

            "vtDetections": (
                vt_detections
            ),


            # ------------------------------------------------
            # ALL vendors
            # ------------------------------------------------

            "vtVendors": (

                vt_data.get(
                    "vendors",
                    []
                )

                if vt_data

                else []

            ),


            # ------------------------------------------------
            # VT error
            # ------------------------------------------------

            "vtError": vt_error,


            # ------------------------------------------------
            # Final result
            # ------------------------------------------------

            "verdict": verdict,

            "reason": reason,

        }


        return jsonify(
            response
        )


    except Exception as e:

        print(
            f"[ERROR] /check: {str(e)}"
        )


        return jsonify({

            "success": False,

            "error": str(e)

        }), 500


# ============================================================
# 🚀 START SERVER
# ============================================================

if __name__ == "__main__":

    print()
    print("=" * 80)
    print(
        "                 PSYCHO VT"
    )
    print(
        "              URL THREAT SCANNER"
    )
    print(
        "          VIRUSTOTAL API v3"
    )
    print("=" * 80)


    if VIRUSTOTAL_API_KEY:

        print(
            "✅ VirusTotal API key loaded"
        )

    else:

        print(
            "❌ VirusTotal API key NOT configured"
        )

        print()
        print(
            "PowerShell:"
        )

        print(
            '$env:VIRUSTOTAL_API_KEY="b77289cdbd662ce006893cdb48207da19f1fac3769d08ac8c46bfea264da13a6"'
        )


    print()
    print(
        "🌐 Server: http://127.0.0.1:5000"
    )

    print("=" * 80)
    print()


    app.run(

        debug=True,

        host="0.0.0.0",

        port=5000

    )

