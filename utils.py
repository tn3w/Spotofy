import os
import re
import json
import secrets
from time import time
from threading import Lock
from flask import request, g
from base64 import urlsafe_b64encode, urlsafe_b64decode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from jinja2 import Environment, select_autoescape, Undefined
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from typing import Union, Optional, Tuple

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

    def load(file_name: str) -> Union[dict, list]:
        """
        Function to load a JSON file securely.

        :param file_name: The JSON file you want to load
        """
        if not os.path.isfile(file_name):
            raise FileNotFoundError("File '" + file_name + "' does not exist.")
        
        if file_name not in file_locks:
            file_locks[file_name] = Lock()

        with file_locks[file_name]:
            with open(file_name, "r") as file:
                data = json.load(file)
            return data
        
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
SESSIONS_PATH = os.path.join(DATA_DIR, "sessions.json")

class Session(dict):
    
    def __init__(self):
        super().__init__()

    @staticmethod
    def _add_session() -> Tuple[str, str]:        
        if os.path.isfile(SESSIONS_PATH):
            sessions = JSON.load(SESSIONS_PATH)
        else:
            sessions = {}
        
        session_id = generate_random_string(10, with_punctuation = False)
        while any([Hashing().compare(session_id, hashed_session_id) for hashed_session_id, _ in sessions.items()]):
            session_id = generate_random_string(10)

        hashed_session_id = Hashing().hash(session_id)

        session_token = generate_random_string(40)

        sessions[hashed_session_id] = None

        JSON.dump(sessions, SESSIONS_PATH)

        g.session_cookie = session_id + "//" + session_token
        return session_id, session_token

    @staticmethod
    def _get_session(session_id):
        if os.path.isfile(SESSIONS_PATH):
            sessions = JSON.load(SESSIONS_PATH)
        else:
            sessions = {}
        for hashed_session_id, session_data in sessions.items():
            session_id_comparison = Hashing().compare(session_id, hashed_session_id)
            if session_id_comparison:
                return hashed_session_id, session_data
        return None, None

    @staticmethod
    def after_request(response: Response):
        try:
            g.session_cookie
        except:
            pass
        else:
            response.set_cookie("SESSION", g.session_cookie, max_age=93312000)
        return response

    def __getitem__(self, key) -> str:
        if request.cookies.get("SESSION") is None:
            raise Exception("Client has not been assigned a session yet.")
            
        client_session_id, client_session_token = request.cookies.get("SESSION").split("//")

        hashed_session_id, session_data = self._get_session(client_session_id)
        if hashed_session_id is None:
            raise Exception("Client has not been assigned a session yet.")
        
        if session_data == None:
            data = {}
        else:
            decrypted_data = SymmetricCrypto(client_session_token).decrypt(session_data)
            data = json.loads(decrypted_data)
        
        return data[key]
                
    def __setitem__(self, key, value) -> str:
        if request.cookies.get("SESSION") is None:
            client_session_id, client_session_token = Session._add_session()
        else:
            client_session_id, client_session_token = request.cookies.get("SESSION").split("//")

        hashed_session_id, session_data = self._get_session(client_session_id)
        if hashed_session_id is None:
            client_session_id, client_session_token = Session._add_session()
            hashed_session_id, session_data = self._get_session(client_session_id)
        
        symmetric_crypto = SymmetricCrypto(client_session_token)

        if session_data == None:
            data = {}
        else:
            decrypted_data = symmetric_crypto.decrypt(session_data)
            data = json.loads(decrypted_data)
        
        data[key] = value
        encrypted_data = symmetric_crypto.encrypt(json.dumps(data))

        if os.path.isfile(SESSIONS_PATH):
            sessions = JSON.load(SESSIONS_PATH)
        else:
            sessions = {}

        sessions[hashed_session_id] = encrypted_data
        JSON.dump(sessions, SESSIONS_PATH)
        
