import os
import re
import json
import random
import secrets
import requests
import numpy as np
from time import time
from PIL import Image
from io import BytesIO
from yt_dlp import YoutubeDL
from threading import Lock
import matplotlib.colors as mcolors
from flask import request, g, Response
from base64 import urlsafe_b64encode, urlsafe_b64decode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from jinja2 import Environment, select_autoescape, Undefined
from canvas_pb2 import EntityCanvazRequest, EntityCanvazResponse
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
CACHE_DIR = os.path.join(CURRENT_DIR, "cache")
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
    def _after_request(response: Response):
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

USER_AGENTS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.3", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36 Edg/116.0.1938.76", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5.1 Safari/605.1.1", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/117.0", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/117.", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36 Edg/116.0.1938.69", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36 Edg/116.0.1938.7", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/117.0"]

def get_image_color(image_url: str):
    """
    Function to get the main color of an image based on its image url
    :param image_url: The url of the image
    """
    try:
        response = requests.get(image_url, headers={"User-Agent": random.choice(USER_AGENTS)})
        response.raise_for_status()
        image = Image.open(BytesIO(response.content))
        image_array = np.array(image)
        
        flattened_colors = image_array.reshape(-1, image_array.shape[-1])
        colors, count = np.unique(flattened_colors, axis=0, return_counts=True)
        
        most_common_color = colors[count.argmax()]
        
        hex_color = mcolors.rgb2hex(most_common_color / 255)
        
        return hex_color
    except:
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

def get_music(youtube_video_id: str) -> str:
    """
    Function to get the music file path of a YouTube video
    :param youtube_video_id: The YouTube Video ID
    """

    if os.path.isfile(FFMPEG_CONF_PATH):
        with open(FFMPEG_CONF_PATH, "r") as file:
            FFMPEG_PATH = file.read()
    else:
        FFMPEG_PATH = "ffmpeg"

    for file in os.listdir(MUSIC_CACHE_DIR):
        file_youtube_id, file_time = file.split(".")[0].split("++")
        if int(file_time) + 2592000 < int(time()):
            os.remove(os.path.join(MUSIC_CACHE_DIR, file))
        else:
            if file_youtube_id == youtube_video_id:
                return os.path.join(MUSIC_CACHE_DIR, file)
    
    ydl_opts = {
        "format": "bestaudio/best",
        "outtmpl": os.path.join(MUSIC_CACHE_DIR, f"{youtube_video_id}++{str(int(time()))}" + ".%(ext)s"),
        "postprocessors": [{
            "key": "FFmpegExtractAudio",
            "preferredcodec": "mp3",
            "preferredquality": "192",
        }],
        "ffmpeg_location": FFMPEG_PATH,
        "duration": 600,
    }

    with YoutubeDL(ydl_opts) as ydl:
        ydl.download(["https://www.youtube.com/watch?v=" + youtube_video_id])
    
    for file in os.listdir(MUSIC_CACHE_DIR):
        file_youtube_id, file_time = file.split(".")[0].split("++")
        if file_youtube_id == youtube_video_id:
            return os.path.join(MUSIC_CACHE_DIR, file)
    
    raise Exception("Something went wrong with the YouTube download...")
