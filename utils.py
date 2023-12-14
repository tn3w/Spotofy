import os
import re
import json
import random
import ipaddress
import secrets
import requests
import subprocess
import numpy as np
from time import time
from PIL import Image
from io import BytesIO
import yt_dlp
import distro
from collections import Counter
from threading import Lock, Thread
from spotipy import Spotify, client
from flask import request, g, Response
from spotipy.oauth2 import SpotifyClientCredentials
from base64 import urlsafe_b64encode, urlsafe_b64decode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from jinja2 import Environment, select_autoescape, Undefined
from canvas_pb2 import EntityCanvazRequest, EntityCanvazResponse
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from typing import Union, Optional, Tuple
import hashlib

def generate_random_string(length: int, with_punctuation: bool = True, with_letters: bool = True):
    """
    Generates a random string

    :param length: The length of the string
    :param with_punctuation: Whether to include special characters
    :param with_letters: Whether letters should be included
    """

    characters = "0123456789"

    if with_punctuation:
        characters += "!\"#$%&'()*+,-.:;<=>?@[\]^_`{|}~"

    if with_letters:
        characters += "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    
    random_string = ''.join(secrets.choice(characters) for _ in range(length))
    return random_string

def shorten_text(text: str, length: int) -> str:
    "Shortens text to the given length and adds '...'"

    if len(text) > length:
        text = text[length - 3] + "..."
    return text

class SilentUndefined(Undefined):
    def _fail_with_undefined_error(self, *args, **kwargs):
        return None

def render_template(file_name: str, **args) -> str:
    """
    Function to load an HTML file and perform optional string replacements.
    """

    if not os.path.isfile(file_name):
        raise FileNotFoundError("File '" + file_name + "' not found.")

    env = Environment(
        autoescape=select_autoescape(['html', 'xml']),
        undefined=SilentUndefined
    )
    
    with open(file_name, "r") as file:
        html = file.read()

    template = env.from_string(html)
    
    html = template.render(**args)
  
    html = re.sub(r'<!--(.*?)-->', '', html, flags=re.DOTALL)
    html = re.sub(r'\s+', ' ', html)

    script_pattern = r'<script\b[^>]*>(.*?)<\/script>'
    def minimize_script(match):
        script_content = match.group(1)
        script_content = re.sub(r'\s+', ' ', script_content)
        return f'<script>{script_content}</script>'
    html = re.sub(script_pattern, minimize_script, html, flags=re.DOTALL | re.IGNORECASE)

    style_pattern = r'<style\b[^>]*>(.*?)<\/style>'
    def minimize_style(match):
        style_content = match.group(1)
        style_content = re.sub(r'\s+', ' ', style_content)
        return f'<style>{style_content}</style>'
    html = re.sub(style_pattern, minimize_style, html, flags=re.DOTALL | re.IGNORECASE)

    return html

file_locks = dict()

class JSON:
    "Class for loading / saving JavaScript Object Notation (= JSON)"

    @staticmethod
    def load(file_name: str, default: Union[dict, list] = dict()) -> Union[dict, list]:
        """
        Function to load a JSON file securely.

        :param file_name: The JSON file you want to load
        :param default: Returned if no data was found
        """

        if not os.path.isfile(file_name):
            if isinstance(default, list):
                return list()
            return dict()
        
        if file_name not in file_locks:
            file_locks[file_name] = Lock()

        with file_locks[file_name]:
            with open(file_name, "r") as file:
                data = json.load(file)
            return data
    
    @staticmethod
    def dump(data: Union[dict, list], file_name: str) -> None:
        """
        Function to save a JSON file securely.
        
        :param data: The data to be stored should be either dict or list
        :param file_name: The file to save to
        """

        file_directory = os.path.dirname(file_name)
        if not os.path.isdir(file_directory):
            raise FileNotFoundError("Directory '" + file_directory + "' does not exist.")
        
        if file_name not in file_locks:
            file_locks[file_name] = Lock()

        with file_locks[file_name]:
            with open(file_name, "w") as file:
                json.dump(data, file)
                
class SymmetricCrypto:
    """
    Implementation of symmetric encryption with AES
    """

    def __init__(self, password: Optional[str] = None, salt_length: int = 32):
        """
        :param password: A secure encryption password, should be at least 32 characters long
        :param salt_length: The length of the salt, should be at least 16
        """

        if password is None:
            password = secrets.token_urlsafe(64)

        self.password = password.encode()
        self.salt_length = salt_length

    def encrypt(self, plain_text: str) -> str:
        """
        Encrypts a text

        :param plaintext: The text to be encrypted
        """

        salt = secrets.token_bytes(self.salt_length)

        kdf_ = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf_.derive(self.password)

        iv = secrets.token_bytes(16)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plain_text.encode()) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        return urlsafe_b64encode(salt + iv + ciphertext).decode()

    def decrypt(self, cipher_text: str) -> str:
        """
        Decrypts a text

        :param ciphertext: The encrypted text
        """

        cipher_text = urlsafe_b64decode(cipher_text.encode())

        salt, iv, cipher_text = cipher_text[:self.salt_length], cipher_text[self.salt_length:self.salt_length + 16], cipher_text[self.salt_length + 16:]

        kdf_ = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf_.derive(self.password)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_data = decryptor.update(cipher_text) + decryptor.finalize()
        plaintext = unpadder.update(decrypted_data) + unpadder.finalize()

        return plaintext.decode()

class Hashing:
    """
    Implementation of hashing with SHA256 and 50000 iterations
    """

    def __init__(self, salt: Optional[str] = None):
        """
        :param salt: The salt, makes the hashing process more secure
        """

        self.salt = salt

    def hash(self, plain_text: str, hash_length: int = 32) -> str:
        """
        Function to hash a plaintext

        :param plain_text: The text to be hashed
        :param hash_length: The length of the returned hashed value
        """

        plain_text = str(plain_text).encode('utf-8')

        salt = self.salt
        if salt is None:
            salt = secrets.token_bytes(32)
        else:
            if not isinstance(salt, bytes):
                try:
                    salt = bytes.fromhex(salt)
                except:
                    salt = salt.encode('utf-8')

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=hash_length,
            salt=salt,
            iterations=50000,
            backend=default_backend()
        )

        hashed_data = kdf.derive(plain_text)

        hash = urlsafe_b64encode(hashed_data).decode('utf-8') + "//" + salt.hex()
        return hash

    def compare(self, plain_text: str, hash: str) -> bool:
        """
        Compares a plaintext with a hashed value

        :param plain_text: The text that was hashed
        :param hash: The hashed value
        """

        salt = self.salt
        if "//" in hash:
            hash, salt = hash.split("//")

        if salt is None:
            raise ValueError("Salt cannot be None if there is no salt in hash")
        
        salt = bytes.fromhex(salt)

        hash_length = len(urlsafe_b64decode(hash.encode('utf-8')))

        comparison_hash = Hashing(salt=salt).hash(plain_text, hash_length = hash_length).split("//")[0]

        return comparison_hash == hash

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(CURRENT_DIR, "data")
CACHE_DIR = os.path.join(CURRENT_DIR, "cache")
SESSIONS_PATH = os.path.join(DATA_DIR, "sessions.json")

class Session(dict):

    def __init__(self, session_id: Optional[str] = None, session_token: Optional[str] = None) -> str:
        super().__init__()

        self.session_id = None
        self.session_token = None

        if not None in [session_id, session_token]:
            hashed_session_id, _ = self._get_session(session_id, session_token)
            if hashed_session_id is None:
                raise Exception("Given session does not exist")
            self.session_id = session_id
            self.session_token = session_token
        
        if not request.cookies.get("SESSION") is None:
            client_session_id, client_session_token = request.cookies.get("SESSION").split("//")

            hashed_session_id, _ = self._get_session(client_session_id, client_session_token)
            if not hashed_session_id is None:
                self.session_id = client_session_id
                self.session_token = client_session_token
    
    @staticmethod
    def _after_request(response: Response):
        try:
            g.session_cookie
        except:
            pass
        else:
            response.set_cookie("SESSION", g.session_cookie, max_age=93312000)
        return response

    @staticmethod
    def _get_session(session_id: str, session_token: Optional[str] = None):
        if os.path.isfile(SESSIONS_PATH):
            sessions = JSON.load(SESSIONS_PATH)
        else:
            sessions = {}
        for hashed_session_id, session_data in sessions.items():
            session_id_comparison = Hashing().compare(session_id, hashed_session_id)
            if session_id_comparison:
                if not session_token is None:
                    session_token_comparison = Hashing().compare(session_token, session_data["hash"])
                    if session_token_comparison:
                        return hashed_session_id, session_data
                else:
                    return hashed_session_id, session_data
            break
        return None, None

    def __getitem__(self, key) -> Optional[str]:
        if self.session_id is None:
            return None
        
        _, session_data = self._get_session(self.session_id, self.session_token)
        
        if session_data["data"] == None:
            data = {}
        else:
            decrypted_data = SymmetricCrypto(self.session_token).decrypt(session_data["data"])
            data = json.loads(decrypted_data)
        
        try:
            return data[key]
        except:
            return None
    
    def __setitem__(self, key, value) -> str:
        if self.session_id is None:
            if os.path.isfile(SESSIONS_PATH):
                sessions = JSON.load(SESSIONS_PATH)
            else:
                sessions = {}
            
            session_id = generate_random_string(10, with_punctuation = False)
            while any([Hashing().compare(session_id, hashed_session_id) for hashed_session_id, _ in sessions.items()]):
                session_id = generate_random_string(10)
            hashed_session_id = Hashing().hash(session_id)
            session_token = generate_random_string(40)
            hashed_session_token = Hashing().hash(session_token)

            sessions[hashed_session_id] = {
                "hash": hashed_session_token,
                "data": SymmetricCrypto(session_token).encrypt(json.dumps({key: value}))
            }

            JSON.dump(sessions, SESSIONS_PATH)

            g.session_cookie = session_id + "//" + session_token

            self.session_id = session_id
            self.session_token = session_token
        else:
            hashed_session_id, session_data = self._get_session(self.session_id, self.session_token)

            symmetric_crypto = SymmetricCrypto(self.session_token)

            decrypted_data = symmetric_crypto.decrypt(session_data["data"])
            data = json.loads(decrypted_data)

            data[key] = value
            encrypted_data = symmetric_crypto.encrypt(json.dumps(data))

            if os.path.isfile(SESSIONS_PATH):
                sessions = JSON.load(SESSIONS_PATH)
            else:
                sessions = {}

            session_data["data"] = encrypted_data

            sessions[hashed_session_id] = session_data
            JSON.dump(sessions, SESSIONS_PATH)

class FastHashing:
    "Implementation for fast hashing"

    def __init__(self, salt: Optional[str] = None):
        ":param salt: The salt, makes the hashing process more secure (Optional)"

        self.salt = salt
    
    def hash(self, plain_text: str, hash_length: int = 8) -> str:
        """
        Function to hash a plaintext

        :param plain_text: The text to be hashed
        :param hash_length: The length of the returned hashed value
        """

        salt = self.salt
        if salt is None:
            salt = secrets.token_hex(hash_length)
        plain_text = salt + plain_text
        
        hash_object = hashlib.sha256(plain_text.encode())
        hex_dig = hash_object.hexdigest()

        return hex_dig + "//" + salt
    
    def compare(self, plain_text: str, hash: str) -> bool:
        """
        Compares a plaintext with a hashed value

        :param plain_text: The text that was hashed
        :param hash: The hashed value
        """
        
        salt = self.salt
        if "//" in hash:
            hash, salt = hash.split("//")
        
        hash_length = len(hash)

        comparison_hash = FastHashing(salt=salt).hash(plain_text, hash_length = hash_length).split("//")[0]

        return comparison_hash == hash

def get_client_ip() -> str:
    "Get the client IP in v4 or v6"

    def shorten_ipv6(ip_address):
        try:
            return str(ipaddress.IPv6Address(ip_address).compressed)
        except:
            return ip_address
    
    headers_to_check = [
        'X-Forwarded-For',
        'X-Real-Ip',
        'CF-Connecting-IP',
        'True-Client-Ip',
    ]

    for header in headers_to_check:
        if header in request.headers:
            client_ip = request.headers[header]
            client_ip = client_ip.split(',')[0].strip()
            client_ip = shorten_ipv6(client_ip)
            return client_ip

    client_ip = request.remote_addr
    client_ip = shorten_ipv6(client_ip)
    return client_ip


IP_API_PATH = os.path.join(CACHE_DIR, "ipapi.json")
IP_INFO_KEYS = ['continent', 'continentCode', 'country', 'countryCode', 'region', 'regionName', 'city', 'district', 'zip', 'lat', 'lon', 'timezone', 'offset', 'currency', 'isp', 'org', 'as', 'asname', 'reverse', 'mobile', 'proxy', 'hosting', 'time']


def get_ip_info(ip_address: str) -> dict:
    """
    Function to query IP information with cache con ip-api.com

    :param ip_address: The client IP
    """

    ip_api_cache = JSON.load(IP_API_PATH)

    for hashed_ip, crypted_data in ip_api_cache.items():
        comparison = FastHashing().compare(ip_address, hashed_ip)
        if comparison:
            data = SymmetricCrypto(ip_address).decrypt(crypted_data)

            data_json = {}
            for i in range(23):
                data_json[IP_INFO_KEYS[i]] = {"True": True, "False": False}.get(data.split("-&%-")[i], data.split("-&%-")[i])

            if int(time()) - int(data_json["time"]) > 518400:
                del ip_api_cache[hashed_ip]
                break

            return data_json
        
    response = requests.get(f"http://ip-api.com/json/{ip_address}?fields=66846719")
    response.raise_for_status()
    if response.ok:
        response_json = response.json()
        if response_json["status"] == "success":
            del response_json["status"], response_json["query"]
            response_json["time"] = int(time())
            response_string = '-&%-'.join([str(value) for value in response_json.values()])
            
            crypted_response = SymmetricCrypto(ip_address).encrypt(response_string)
            hashed_ip = FastHashing().hash(ip_address)

            ip_api_cache[hashed_ip] = crypted_response
            JSON.dump(ip_api_cache, IP_API_PATH)

            return response_json
        
    raise requests.RequestException("ip-api.com could not be requested or did not provide a correct answer")

def before_request_get_info():
    g.ip_address = get_client_ip()
    try:
        g.info = get_ip_info(g.ip_address)
    except:
        g.info = {"continent":"North America","continentCode":"NA","country":"United States","countryCode":"US","region":"CA","regionName":"California","city":"Los Angeles","district":"Downtown","zip":"90001","lat":34.0522,"lon":-118.2437,"timezone":"America/Los_Angeles","offset":-28800,"currency":"USD","isp":"AT&T","org":"AT&T Services, Inc.","as":"AS7018 AT&T Services, Inc.","asname":"AT&T","reverse":"cpe-192-180-220-1.socal.res.rr.com","mobile":False,"proxy":False,"hosting":False}
    

DISTRO_TO_PACKAGE_MANAGER = {
    "ubuntu": {"installation_command": "apt-get install", "update_command": "apt-get update; apt-get upgrade"},
    "debian": {"installation_command": "apt-get install", "update_command": "apt-get update; apt-get upgrade"},
    "fedora": {"installation_command": "dnf install", "update_command": "dnf upgrade"},
    "centos": {"installation_command": "yum install", "update_command": "yum update"},
    "arch": {"installation_command": "pacman -S", "update_command": "pacman -Syu"},
    "opensuse": {"installation_command": "zypper install", "update_command": "zypper update"},
    "linuxmint": {"installation_command": "apt-get install", "update_command": "apt-get update; apt-get upgrade"},
    "gentoo": {"installation_command": "emerge", "update_command": "emerge --sync"},
    "rhel": {"installation_command": "yum install", "update_command": "yum update"},
    "kali": {"installation_command": "apt-get install", "update_command": "apt-get update; apt-get upgrade"},
    "tails": {"installation_command": "apt-get install", "update_command": "apt-get update; apt-get upgrade"},
    "zorin": {"installation_command": "apt-get install", "update_command": "apt-get update; apt-get upgrade"},
    "mx": {"installation_command": "apt-get install", "update_command": "apt-get update; apt-get upgrade"},
    "solus": {"installation_command": "eopkg install", "update_command": "eopkg up"},
    "antergos": {"installation_command": "pacman -S", "update_command": "pacman -Syu"},
    "lubuntu": {"installation_command": "apt-get install", "update_command": "apt-get update; apt-get upgrade"},
    "xubuntu": {"installation_command": "apt-get install", "update_command": "apt-get update; apt-get upgrade"},
}
PACKAGE_MANAGERS = [
    {"version_command": "apt-get --version", "installation_command": "apt-get install", "update_command": "apt-get update; apt-get upgrade"},
    {"version_command": "dnf --version", "installation_command": "dnf install", "update_command": "dnf upgrade"},
    {"version_command": "yum --version", "installation_command": "yum install", "update_command": "yum update"},
    {"version_command": "pacman --version", "installation_command": "pacman -S", "update_command": "pacman -Syu"},
    {"version_command": "zypper --version", "installation_command": "zypper install", "update_command": "zypper update"},
    {"version_command": "emerge --version", "installation_command": "emerge", "update_command": "emerge --sync"},
    {"version_command": "eopkg --version", "installation_command": "eopkg install", "update_command": "eopkg up"}
]

class Linux:
    "Collection of functions that have something to do with Linux"

    @staticmethod
    def get_package_manager() -> Tuple[Optional[str], Optional[str]]:
        "Returns the Packet Manager install command and the update command"

        distro_id = distro.id()

        package_manager = DISTRO_TO_PACKAGE_MANAGER.get(distro_id, {"installation_command": None, "update_command": None})

        installation_command, update_command = package_manager["installation_command"], package_manager["update_command"]
        
        if None in [installation_command, update_command]:
            for package_manager in PACKAGE_MANAGERS:
                try:
                    subprocess.check_call(package_manager["version_command"], shell=True)
                except:
                    pass
                else:
                    installation_command, update_command = package_manager["installation_command"], package_manager["update_command"]
        
        return installation_command, update_command
    
    @staticmethod
    def install_package(package_name: str) -> None:
        """
        Attempts to install a Linux package
        
        :param package_name: Name of the Linux packet
        """
        
        installation_command, update_command = Linux.get_package_manager()

        if not None in [installation_command, update_command]:
            try:
                update_process = subprocess.Popen("sudo " + update_command, shell=True)
                update_process.wait()
            except Exception as e:
                print(f"[Error]Error using update Command while installing linux package '{package_name}': '{e}'")
            
            install_process = subprocess.Popen(f"sudo {installation_command} {package_name} -y", shell=True)
            install_process.wait()
        
        else:
            raise Exception("No package manager found!")

        return None

USER_AGENTS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.3", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36 Edg/116.0.1938.76", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5.1 Safari/605.1.1", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/117.0", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/117.", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36 Edg/116.0.1938.69", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36 Edg/116.0.1938.7", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/117.0"]

def get_image_color(image_url: str):
    """
    Function to get the main color of an image based on its image url
    :param image_url: The url of the image
    """

    if not isinstance(image_url, str):
        return None

    response = requests.get(image_url, headers={"User-Agent": random.choice(USER_AGENTS)})
    response.raise_for_status()
    image = Image.open(BytesIO(response.content))
    image_np = np.array(image)

    try:
        pixels = image_np.reshape(-1, 3)
    except:
        return None

    color_counts = Counter(map(tuple, pixels))

    sorted_colors = sorted(color_counts.items(), key=lambda x: -x[1])

    for color, _ in sorted_colors:
        r, g, b = color

        brightness = (0.299 * r + 0.587 * g + 0.114 * b) / 255

        if 0.1 < brightness < 0.9:
            hex_color = "#{:02X}{:02X}{:02X}".format(r, g, b)
            return hex_color

    return None

YOUTUBE_IDS_CACHE_PATH = os.path.join(CACHE_DIR, "youtube-ids-cache.json")

def get_youtube_id(search: str, spotify_id: Optional[str] = None) -> str:
    """
    Function to get a YouTube video ID based on a search term
    :param search: Search term after searching for video ids on YouTube
    """

    if os.path.isfile(YOUTUBE_IDS_CACHE_PATH):
        youtube_ids = JSON.load(YOUTUBE_IDS_CACHE_PATH)
        
        copy_youtube_ids = youtube_ids.copy()
        for youtube_search, search_data in youtube_ids.items():
            if search_data["time"] + 2592000 < int(time()):
                del copy_youtube_ids[youtube_search]
        
        if len(copy_youtube_ids) != len(youtube_ids):
            JSON.dump(copy_youtube_ids, YOUTUBE_IDS_CACHE_PATH)
            youtube_ids = copy_youtube_ids
    else:
        youtube_ids = {}

    for youtube_search, search_data in youtube_ids.items():
        if not spotify_id is None:
            if search_data["spotify_id"] == spotify_id:
                return search_data["youtube_id"]
        else:
            if youtube_search == search:
                return search_data["youtube_id"]
    
    response = requests.get("https://www.youtube.com/results?search_query=" + search.replace(" ", "+"), headers = {'User-Agent': random.choice(USER_AGENTS)})

    video_id = re.findall(r"watch\?v=(\S{11})", response.content.decode())[0]

    if os.path.isfile(YOUTUBE_IDS_CACHE_PATH):
        youtube_videos = JSON.load(YOUTUBE_IDS_CACHE_PATH)
    else:
        youtube_videos = {}

    youtube_videos[search] = {
        "youtube_id": video_id,
        "spotify_id": spotify_id,
        "time": int(time())
    }

    JSON.dump(youtube_videos, YOUTUBE_IDS_CACHE_PATH)

    return video_id

SPOTIFY_CANVAS_CACHE_PATH = os.path.join(CACHE_DIR, "spotify-canvas-cache.json")

def get_canvas_url(spotify_track_id: str) -> str:
    """
    Gets the canvas of a Spotify track
    :param spotify_track_id: The ID of the Spotify track
    """

    def get_access_token():
        try:
            response = requests.get('https://open.spotify.com/get_access_token?reason=transport', headers={'User-Agent': random.choice(USER_AGENTS)})
            data = response.json()
            return data.get("accessToken")
        except:
            return
        
    if os.path.isfile(SPOTIFY_CANVAS_CACHE_PATH):
        spotify_canvas = JSON.load(SPOTIFY_CANVAS_CACHE_PATH)

        copy_spotify_canvas = spotify_canvas.copy()
        for track_id, canvas_data in spotify_canvas.items():
            if canvas_data["time"] + 2592000 < int(time()):
                del copy_spotify_canvas[track_id]
        
        if len(copy_spotify_canvas) != len(spotify_canvas):
            JSON.dump(copy_spotify_canvas, SPOTIFY_CANVAS_CACHE_PATH)
            spotify_canvas = copy_spotify_canvas
    else:
        spotify_canvas = {}
    
    for track_id, canvas_data in spotify_canvas.items():
        if track_id == spotify_track_id:
            if len(canvas_data["urls"]) == 0:
                return

            if len(canvas_data["urls"]) == 1:
                return canvas_data["urls"][0]
            
            return random.choice(canvas_data["urls"])

    access_token = get_access_token()
    if access_token is None:
        return

    canvas_request = EntityCanvazRequest()
    canvas_request_entities = canvas_request.entities.add()
    canvas_request_entities.entity_uri = 'spotify:track:'+ spotify_track_id

    try:
        response = requests.post('https://gew1-spclient.spotify.com/canvaz-cache/v0/canvases', 
            headers=
            {
                "Content-Type": "application/x-protobuf", 
                "Authorization": "Bearer %s" % access_token, 
                "User-Agent": random.choice(USER_AGENTS)
            }, 
            data = canvas_request.SerializeToString()
        )
    except:
        return
    
    canvas_response = EntityCanvazResponse()
    try:
        canvas_response.ParseFromString(response.content)
    except:
        return
    
    canvas_urls = [canvas.url for canvas in canvas_response.canvases]

    spotify_canvas[spotify_track_id] = {"time": int(time()), "urls": canvas_urls}
    JSON.dump(spotify_canvas, SPOTIFY_CANVAS_CACHE_PATH)

    if len(canvas_urls) == 0:
        return

    if len(canvas_urls) == 1:
        return canvas_urls[0]
    
    return random.choice(canvas_urls)

MUSIC_CACHE_DIR = os.path.join(CACHE_DIR, "music")
FFMPEG_CONF_PATH = os.path.join(DATA_DIR, "FFmpeg.conf")

def get_music(youtube_video_id: str, duration_ms: int) -> str:
    """
    Function to get the music file path of a YouTube video
    :param youtube_video_id: The YouTube Video ID
    :param duration_ms: The length of the music in milliseconds
    """

    if os.path.isfile(FFMPEG_CONF_PATH):
        with open(FFMPEG_CONF_PATH, "r") as file:
            ffmpeg_path = file.read()
    else:
        ffmpeg_path = None

    for file in os.listdir(MUSIC_CACHE_DIR):
        file_youtube_id, file_time = file.split(".")[0].split("++")
        if int(file_time) + 2592000 < int(time()):
            os.remove(os.path.join(MUSIC_CACHE_DIR, file))
        else:
            if file_youtube_id == youtube_video_id:
                return os.path.join(MUSIC_CACHE_DIR, file)
    
    current_time = time()

    yt_dlp.utils.std_headers["User-Agent"] = random.choice(USER_AGENTS)
    
    ydl_opts = {
        "format": "bestaudio/best",
        "outtmpl": os.path.join(MUSIC_CACHE_DIR, f"{youtube_video_id}++{str(int(current_time))}" + ".%(ext)s"),
        "postprocessors": [{
            "key": "FFmpegExtractAudio",
            "preferredcodec": "mp3",
            "preferredquality": "best",
        }],
        "ffmpeg_location": ffmpeg_path,
        "duration": 600,
        "quiet": True,
        "no_warnings": True,
        "user_agent": random.choice(USER_AGENTS)
    }

    with yt_dlp.YoutubeDL(ydl_opts) as ydl:
        ydl.download(["https://www.youtube.com/watch?v=" + youtube_video_id])

    output_file = os.path.join(MUSIC_CACHE_DIR, f"{youtube_video_id}++{str(int(current_time))}.mp3")
    
    if ffmpeg_path is None:
        ffmpeg_path = "ffmpeg"
    
    cut_command = [
        ffmpeg_path,
        "-i", output_file,
        "-t", str(round(duration_ms / 1000) - 1),
        output_file.replace(".mp3", "output.mp3")
    ]

    try:
        subprocess.run(cut_command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        # FIXME: Log Error
        pass
    else:
        os.remove(output_file)
        os.rename(output_file.replace(".mp3", "output.mp3"), output_file)
    
    for file in os.listdir(MUSIC_CACHE_DIR):
        file_youtube_id, file_time = file.split(".")[0].split("++")
        if file_youtube_id == youtube_video_id:
            return os.path.join(MUSIC_CACHE_DIR, file)
    
    raise Exception("Something went wrong with the YouTube download...")

def remove_elements(source: dict, elements_to_remove: list):
    """
    Deletes listed items from a dict
    :param source: The dict from which things are to be deleted
    :param elements_to_remove: Things to be deleted from the list
    """

    for element in elements_to_remove:
        del source[element]
    return source

CREDENTIALS_PATH = os.path.join(DATA_DIR, "creds.conf")
TRACKS_CACHE_PATH = os.path.join(CACHE_DIR, "tracks-cache.json")
ARTISTS_CACHE_PATH = os.path.join(CACHE_DIR, "artists-cache.json")
PLAYLISTS_CACHE_PATH = os.path.join(CACHE_DIR, "playlists-cache.json")
SEARCHS_CACHE_PATH = os.path.join(CACHE_DIR, "searchs-cache.json")
RECOMMENDATIONS_CACHE_PATH = os.path.join(CACHE_DIR, "recommendations-cache.json")

class Spotofy:

    def __init__(self):
        with open(CREDENTIALS_PATH, "r") as file:
            credentials = file.read().split("---")
        self.spotify_client_id, self.spotify_client_secret = credentials
        self._reconnect()

    def _reconnect(self):
        """
        Function to (re)connect with the Spotify Api
        """

        client_credentials_manager = SpotifyClientCredentials(client_id=self.spotify_client_id, client_secret=self.spotify_client_secret)
        spotify = Spotify(client_credentials_manager=client_credentials_manager)
        self.spotify = spotify
    
    @property
    def country_codes(self) -> list:
        """
        Returns all country codes
        """
        
        return self.spotify.country_codes
    
    @staticmethod
    def _complete_track_data(spotify_track_id: str) -> None:
        """
        Function to add more data to a track
        :param spotify_track_id: The Spotify track ID
        """
        
        tracks = Spotofy._load(TRACKS_CACHE_PATH)

        track = tracks[spotify_track_id]

        track_search = track["name"] + " "
        for index, artist in enumerate(track["artists"]):
            if not index == len(track["artists"]) - 1:
                track_search += artist["name"] + ", "
            else:
                track_search += artist["name"] + " "
        track_search += "Full Lyrics"

        youtube_id = get_youtube_id(track_search, spotify_track_id)
        image_theme = get_image_color(track["image"])

        tracks = Spotofy._load(TRACKS_CACHE_PATH)

        track = tracks[spotify_track_id]

        track["youtube_id"] = youtube_id
        track["theme"] = image_theme

        tracks[spotify_track_id] = track
        JSON.dump(tracks, TRACKS_CACHE_PATH)
    
    @staticmethod
    def _add_theme(spotify_id: str, cache_path: str) -> None:
        """
        Function to add the theme color to artists / playlists
        :param spotofy_id: The Spotify ID from the playlist or artist
        :param cache_path: The path to the cache file
        """
        
        dictionary = Spotofy._load(cache_path)

        item = dictionary[spotify_id]
        item["theme"] = get_image_color(item["image"])

        dictionary = Spotofy._load(cache_path)

        dictionary[spotify_id] = item
        JSON.dump(dictionary, cache_path)

    @staticmethod
    def _load(cache_path: str) -> dict:
        """
        Function to load all tracks / artists / playlists
        :param cache_path: The path to the cache file
        """

        if os.path.isfile(cache_path):
            dictionary = JSON.load(cache_path)
            
            copy_dictionary = dictionary.copy()
            for item_id, item_data in dictionary.items():
                if item_data["time"] + 2592000 < int(time()):
                    del copy_dictionary[item_id]

            
            if len(copy_dictionary) != len(dictionary):
                JSON.dump(copy_dictionary, cache_path)
            
            return copy_dictionary
        return {}
    
    def track(self, spotify_track_id: str) -> dict:
        """
        Gets information about a specific Spotify track
        :param spotify_track_id: The Spotify track ID
        
        > Data points: artists(id, name), duration_ms, explicit, id, name, image, Optional: youtube_id, theme
        """

        tracks = Spotofy._load(TRACKS_CACHE_PATH)

        for track_id, track_data in tracks.items():
            if track_id == spotify_track_id:
                del track_data["time"]

                if track_data.get("youtube_id") is None or track_data.get("theme") is None:
                    thread = Thread(target = self._complete_track_data, args = (spotify_track_id, ))
                    thread.start()

                return track_data
        
        try:
            track = self.spotify.track(track_id = spotify_track_id)
        except (client.SpotifyException, ConnectionError):
            self._reconnect()
            track = self.spotify.track(track_id = spotify_track_id)
        
        try:
            track["image"] = max(track["album"]["images"], key=lambda x: x['height'])["url"]
        except:
            track["image"] = track["album"]["images"][0]["url"]
        
        track = remove_elements(track, ["album", "available_markets", "disc_number", "external_ids", "external_urls", "href", "is_local", "popularity", "preview_url", "track_number", "type", "uri"])
        track["artists"] = [remove_elements(artist, ["external_urls", "href", "type", "uri"]) for artist in track["artists"]]
        track["time"] = int(time())

        tracks = Spotofy._load(TRACKS_CACHE_PATH)

        tracks[spotify_track_id] = track
        JSON.dump(tracks, TRACKS_CACHE_PATH)

        thread = Thread(target = self._complete_track_data, args = (spotify_track_id, ))
        thread.start()

        del track["time"]

        return track
    
    def artist(self, spotify_artist_id: str) -> dict:
        """
        Gets information about a specific artist
        :param spotify_artist_id: The Spotify artist ID
        """

        artists = Spotofy._load(ARTISTS_CACHE_PATH)

        for artist_id, artist_data in artists.items():
            if artist_id == spotify_artist_id:
                if not artist_data.get("followers") is None:                
                    del artist_data["time"]
                    if not artist_data.get("top_tracks") is None:
                        del artist_data["top_tracks"]
                    return artist_data
        
        try:
            artist = self.spotify.artist(artist_id = spotify_artist_id)
        except (client.SpotifyException, ConnectionError):
            self._reconnect()
            artist = self.spotify.artist(artist_id = spotify_artist_id)
        
        try:
            artist["image"] = max(artist["images"], key=lambda x: x['height'])["url"]
        except:
            artist["image"] = artist["images"][0]["url"]
        
        artist = remove_elements(artist, ["external_urls", "popularity", "type", "uri", "href", "images"])
        artist["followers"] = artist["followers"]["total"]
        artist["time"] = int(time())

        artists = Spotofy._load(ARTISTS_CACHE_PATH)

        if spotify_artist_id in artists:
            artists[spotify_artist_id].update(artist)
        else:
            artists[spotify_artist_id] = artist

        JSON.dump(artists, ARTISTS_CACHE_PATH)

        thread = Thread(target = self._add_theme, args = (spotify_artist_id, ARTISTS_CACHE_PATH, ))
        thread.start()

        del artist["time"]

        return artist
    
    def artist_top_tracks(self, spotify_artist_id: str, country: str = "US") -> dict:
        """
        Get all top tracks of an artist
        :param spotify_artist_id: The Spotify artist ID
        :param country: The country code of the client in ISO-3166-1 format
        """

        artists = Spotofy._load(ARTISTS_CACHE_PATH)

        for artist_id, artist_data in artists.items():
            if artist_id == spotify_artist_id:
                for top_tracks_country, top_tracks in artist_data.get("top_tracks", dict()).items():
                    if top_tracks_country == country:
                        return [self.track(track_id) for track_id in top_tracks]
        
        try:
            artist_top_tracks = self.spotify.artist_top_tracks(artist_id = spotify_artist_id, country = country)
        except (client.SpotifyException, ConnectionError):
            self._reconnect()
            artist_top_tracks = self.spotify.artist_top_tracks(artist_id = spotify_artist_id, country = country)
        
        if os.path.isfile(TRACKS_CACHE_PATH):
            tracks = JSON.load(TRACKS_CACHE_PATH)

            copy_tracks = tracks.copy()
            for track_id, track_data in tracks.items():
                if track_data["time"] + 2592000 < int(time()):
                    del copy_tracks[track_id]
            
            if len(copy_tracks) != len(tracks):
                JSON.dump(copy_tracks, TRACKS_CACHE_PATH)
                tracks = copy_tracks
        else:
            tracks = {}

        top_tracks = []

        for track in artist_top_tracks["tracks"]:
            if not track["id"] in tracks:
                try:
                    track["image"] = max(track["album"]["images"], key=lambda x: x['height'])["url"]
                except:
                    track["image"] = track["album"]["images"][0]["url"]

                track = remove_elements(track, ["album", "disc_number", "external_ids", "external_urls", "href", "is_local", "popularity", "preview_url", "track_number", "type", "uri", "is_playable"])
                track["artists"] = [remove_elements(artist, ["external_urls", "href", "type", "uri"]) for artist in track["artists"]]

                top_tracks.append(track)

                track["time"] = int(time())

                tracks[track["id"]] = track

        JSON.dump(tracks, TRACKS_CACHE_PATH)

        for track in artist_top_tracks["tracks"]:
            thread = Thread(target = self._complete_track_data, args = (track["id"], ))
            thread.start()

        top_tracks_ids = [track["id"] for track in artist_top_tracks["tracks"]]

        artists = Spotofy._load(ARTISTS_CACHE_PATH)

        artist = artists.get(spotify_artist_id, None)
        if artist == None:
            artists[spotify_artist_id] = {
                "time": time(),
                "top_tracks": {}
            }

        artists[spotify_artist_id]["top_tracks"][country] = top_tracks_ids
        JSON.dump(artists, ARTISTS_CACHE_PATH)

        return top_tracks
    
    def playlist(self, spotify_playlist_id: str, limit: int = 100) -> dict:
        """
        Gets information about a specific playlist
        :param spotify_playlist_id: The Spotify playlist ID
        :param limit: How many tracks to return
        """

        playlists = Spotofy._load(PLAYLISTS_CACHE_PATH)

        for playlist_id, playlist_data in playlists.items():
            if playlist_id == spotify_playlist_id:
                del playlist_data["time"]
                if limit == 0:
                    del playlist_data["tracks"]
                else:
                    # Add the tracks to be added
                    playlist_data["tracks"] = [self.track(track_id) for track_id in playlist_data["tracks"][:limit]]
                return playlist_data

        try:
            playlist = self.spotify.playlist(playlist_id = spotify_playlist_id)
        except (client.SpotifyException, ConnectionError):
            self._reconnect()
            playlist = self.spotify.playlist(playlist_id = spotify_playlist_id)

        if limit == 0:
            playlist_tracks_data = []
        else:
            try:
                playlist_tracks_data = self.spotify.playlist_tracks(playlist_id = spotify_playlist_id, limit = limit)
            except (client.SpotifyException, ConnectionError):
                self._reconnect
                playlist_tracks_data = self.spotify.playlist_tracks(playlist_id = spotify_playlist_id, limit = limit)

        try:
            playlist["image"] = max(playlist["images"], key=lambda x: x['height'])["url"]
        except:
            playlist["image"] = playlist["images"][0]["url"]

        playlist = remove_elements(playlist, ["collaborative", "external_urls", "href", "primary_color", "public", "snapshot_id", "type", "images", "uri"])
        playlist["followers"] = playlist["followers"]["total"]
        playlist["owner"] = playlist["owner"]["id"]
        playlist["time"] = int(time())

        tracks = Spotofy._load(TRACKS_CACHE_PATH)

        playlist_tracks = []

        for track in playlist_tracks_data["items"]:
            track = track["track"]
            if not track["id"] in tracks:
                try:
                    track["image"] = max(track["album"]["images"], key=lambda x: x['height'])["url"]
                except:
                    track["image"] = track["album"]["images"][0]["url"]

                track = remove_elements(track, ["available_markets", "disc_number", "episode", "external_ids", "external_urls", "href", "is_local", "popularity", "preview_url", "track", "track_number", "type", "uri", "album"])
                track["artists"] = [remove_elements(artist, ["external_urls", "href", "type", "uri"]) for artist in track["artists"]]

                playlist_tracks.append(track)

                track["time"] = int(time())

                tracks[track["id"]] = track

        JSON.dump(tracks, TRACKS_CACHE_PATH)

        for track in playlist["tracks"]["items"]:
            thread = Thread(target = self._complete_track_data, args = (track["track"]["id"], ))
            thread.start()

        playlist["tracks"] = [track["track"]["id"] for track in playlist["tracks"]["items"]]

        playlists = Spotofy._load(PLAYLISTS_CACHE_PATH)

        playlists[spotify_playlist_id] = playlist

        JSON.dump(playlists, PLAYLISTS_CACHE_PATH)

        thread = Thread(target = self._add_theme, args = (spotify_playlist_id, PLAYLISTS_CACHE_PATH, ))
        thread.start()

        del playlist["time"]
        playlist["tracks"] = playlist_tracks

        if limit == 0:
            del playlist["tracks"]

        return playlist
    
    def search(self, q: str, limit: int = 20, types: list = ["track", "playlist", "artist"]) -> dict:
        """
        Function to search for tracks / playlists / artists
        :param q: What to search for
        :param limit: How many tracks to return
        :param types: What types of objects to return
        """

        searchs = Spotofy._load(SEARCHS_CACHE_PATH)

        for search_q, search_data in searchs.items():
            if search_q == q:
                del search_data["time"]
                
                if "track" in types:
                    search_data["tracks"] = [self.track(track_id) for track_id in search_data["tracks"][:limit]]
                else:
                    del search_data["tracks"]

                if "playlist" in types:
                    search_data["playlists"] = [self.playlist(playlist_id, limit=0) for playlist_id in search_data["playlists"][:limit]]
                else:
                    del search_data["playlists"]
                
                if "artist" in types:
                    search_data["artists"] = [self.artist(artist_id) for artist_id in search_data["artists"][:limit]]
                else:
                    del search_data["artists"]
                
                return search_data
        
        try:
            search = self.spotify.search(q, limit, type = "track,playlist,artist")
        except:
            self._reconnect()
            search = self.spotify.search(q, limit, type = "track,playlist,artist")
        
        tracks = Spotofy._load(TRACKS_CACHE_PATH)

        search_tracks = []
        for track in search["tracks"]["items"]:
            try:
                track["image"] = max(track["album"]["images"], key=lambda x: x['height'])["url"]
            except:
                track["image"] = track["album"]["images"][0]["url"]

            track = remove_elements(track, ["available_markets", "disc_number", "external_ids", "external_urls", "href", "is_local", "popularity", "preview_url", "track_number", "type", "uri", "album"])
            track["artists"] = [remove_elements(artist, ["external_urls", "href", "type", "uri"]) for artist in track["artists"]]

            search_tracks.append(track)

            track["time"] = int(time())

            tracks[track["id"]] = track

        JSON.dump(tracks, TRACKS_CACHE_PATH)

        for track in search["tracks"]["items"]:
            thread = Thread(target = self._complete_track_data, args = (track["id"], ))
            thread.start()
        
        artists = Spotofy._load(ARTISTS_CACHE_PATH)
        
        search_artists = []
        for artist in search["artists"]["items"]:
            try:
                artist["image"] = max(artist["images"], key=lambda x: x['height'])["url"]
            except:
                try:
                    artist["image"] = artist["images"][0]["url"]
                except:
                    artist["image"] = None
            
            artist = remove_elements(artist, ["external_urls", "popularity", "type", "uri", "href", "images"])
            artist["followers"] = artist["followers"]["total"]

            search_artists.append(artist)

            artist["time"] = int(time())

            artists[artist["id"]] = artist
        
        JSON.dump(artists, ARTISTS_CACHE_PATH)

        for artist in search["artists"]["items"]:
            thread2 = Thread(target = self._add_theme, args = (artist["id"], ARTISTS_CACHE_PATH, ))
            thread2.start()

        playlists = Spotofy._load(PLAYLISTS_CACHE_PATH)

        search_playlists = []
        for playlist in search["playlists"]["items"]:
            try:
                playlist["image"] = max(playlist["images"], key=lambda x: x['height'])["url"]
            except:
                playlist["image"] = playlist["images"][0]["url"]

            playlist = remove_elements(playlist, ["collaborative", "external_urls", "href", "primary_color", "public", "snapshot_id", "type", "images", "uri"])
            playlist["owner"] = playlist["owner"]["id"]

            search_playlists.append(playlist)

            playlist["time"] = int(time())

            playlists[playlist["id"]] = playlist
        
        JSON.dump(playlists, PLAYLISTS_CACHE_PATH)

        for playlist in search["playlists"]["items"]:
            thread3 = Thread(target = self._add_theme, args = (playlist["id"], PLAYLISTS_CACHE_PATH, ))
            thread3.start()

        search_ids = {
            "time": int(time()),
            "tracks": [track["id"] for track in search_tracks],
            "artists": [artist["id"] for artist in search_artists],
            "playlists": [playlist["id"] for playlist in search_playlists]
        }
        
        searchs = Spotofy._load(SEARCHS_CACHE_PATH)
        searchs[q] = search_ids
        JSON.dump(searchs, SEARCHS_CACHE_PATH)

        search = {
            "tracks": search_tracks,
            "artists": search_artists,
            "playlists": search_playlists
        }

        return search
    
    def recommendations(self, seed_artists: list = [], seed_genres: list = [], seed_tracks: list = [], limit: int = 30, country: str = "US") -> dict:
        """
        Function to get track recommendations based on tracks, artists and genres
        :param seed_artists: Artists on which recommendations should be generated
        :param seed_genres: Genres on which recommendations should be generated
        :param seed_tracks: Tracks on which recommendations should be generated
        :param limit: How many tracks to return
        :param country: The country code of the client in ISO-3166-1 format
        """

        recommendations = Spotofy._load(RECOMMENDATIONS_CACHE_PATH)

        total_seeds = seed_artists + seed_genres + seed_tracks

        for seeds, recommendation_data in recommendations.items():
            if seeds == ''.join(total_seeds) + country:
                del recommendation_data["time"]
                return [self.track(track_id) for track_id in recommendation_data["tracks"][:limit]]

        if len(total_seeds) > 5:
            generated_seeds = random.sample(seed_artists + seed_genres + seed_tracks, 4)
            
            while len(set(generated_seeds)) < 5:
                generated_seeds = random.sample(seed_artists + seed_genres + seed_tracks, 4)

            seed_artists = [seed for seed in generated_seeds if seed in seed_artists]
            seed_genres = [seed for seed in generated_seeds if seed in seed_genres]
            seed_tracks = [seed for seed in generated_seeds if seed in seed_tracks]

        try:
            recommendation = self.spotify.recommendations(seed_artists, seed_genres, seed_tracks, 40, country)
        except:
            self._reconnect()
            recommendation = self.spotify.recommendations(seed_artists, seed_genres, seed_tracks, 40, country)
        
        tracks = Spotofy._load(TRACKS_CACHE_PATH)

        recommendation_tracks = []
        for track in recommendation["tracks"]:
            try:
                track["image"] = max(track["album"]["images"], key=lambda x: x['height'])["url"]
            except:
                track["image"] = track["album"]["images"][0]["url"]

            track = remove_elements(track, ["disc_number", "external_ids", "external_urls", "href", "is_local", "popularity", "preview_url", "track_number", "type", "uri", "album"])
            track["artists"] = [remove_elements(artist, ["external_urls", "href", "type", "uri"]) for artist in track["artists"]]

            recommendation_tracks.append(track)

            track["time"] = int(time())

            tracks[track["id"]] = track
        
        JSON.dump(tracks, TRACKS_CACHE_PATH)

        for track in recommendation["tracks"]:
            thread = Thread(target = self._complete_track_data, args = (track["id"], ))
            thread.start()

        recommendations = Spotofy._load(RECOMMENDATIONS_CACHE_PATH)
        recommendations[''.join(total_seeds) + country] = {
            "time": int(time()),
            "tracks": [track["id"] for track in recommendation["tracks"]]
        }
        JSON.dump(recommendations, RECOMMENDATIONS_CACHE_PATH)

        return recommendation_tracks