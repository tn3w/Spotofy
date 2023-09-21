from flask import Flask
import os
import spotipy
import logging
import subprocess
import platform
import zipfile
import shutil
import requests
from time import time, sleep
from spotipy.oauth2 import SpotifyClientCredentials
from utils import Session, get_youtube_id

if not __name__ == "__main__":
    exit()

LOGO = """   _____             __        ____     
  / ___/____  ____  / /_____  / __/_  __
  \__ \/ __ \/ __ \/ __/ __ \/ /_/ / / /
 ___/ / /_/ / /_/ / /_/ /_/ / __/ /_/ / 
/____/ .___/\____/\__/\____/_/  \__, /  
    /_/                        /____/\n"""

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(CURRENT_DIR, "data")
if not os.path.isdir(DATA_DIR):
    os.mkdir(DATA_DIR)

CACHE_DIR = os.path.join(CURRENT_DIR, "cache")
if not os.path.isdir(CACHE_DIR):
    os.mkdir(CACHE_DIR)

MUSIC_CACHE_DIR = os.path.join(CACHE_DIR, "music")
if not os.path.isdir(MUSIC_CACHE_DIR):
    os.mkdir(MUSIC_CACHE_DIR)

CREDENTIALS_PATH = os.path.join(DATA_DIR, "creds.conf")
FFMPEG_CONF_PATH = os.path.join(DATA_DIR, "FFmpeg.conf")
SYSTEM = platform.system()

if not os.path.isfile(FFMPEG_CONF_PATH):
    try:
        with open(os.devnull, 'w') as devnull:
            subprocess.call(["ffmpeg", "-version"], stdout=devnull, stderr=devnull)
    except OSError:
        os.system('cls' if os.name == 'nt' else 'clear')
        print(LOGO)
        print("-- FFmpeg is not installed --")
        if SYSTEM not in ["Windows", "Darwin", "Linux"]:
            print("Operating system not found...\n\nPlease install FFmpeg by following the instructions on the following web page for your operating system:\nhttps://ffmpeg.org/download.html")
            print('Unzip the downloaded "7z" or "zip" file, and go into the unzipped folder and search for the "ffmpeg.exe" file, now copy the path of this file and enter it below.')
            FFMPEG_PATH = input("[FFMPEG PATH]: ") # FIXME: Input Validation
        elif SYSTEM == "Windows":
            WINDOWS_FFMPEG_URL = "https://github.com/BtbN/FFmpeg-Builds/releases/download/latest/ffmpeg-master-latest-win64-gpl.zip"
            FFMPEG_ARCHIVE_PATH = os.path.join(DATA_DIR, "ffmpeg.zip")

            print("Operating system is Windows\n\nDownloading FFmpeg from", WINDOWS_FFMPEG_URL, "...")

            response = requests.get(WINDOWS_FFMPEG_URL, stream=True)
            if response.status_code == 200:
                with open(FFMPEG_ARCHIVE_PATH, "wb") as ffmpeg_zip:
                    total_length = int(response.headers.get('content-length'))
                    downloaded = 0

                    for data in response.iter_content(chunk_size=1024):
                        if data:
                            ffmpeg_zip.write(data)
                            downloaded += len(data)
                            progress = (downloaded / total_length) * 100
                            print(f'Downloaded: {downloaded}/{total_length} Bytes ({progress:.2f}%)', end='\r')
            
            os.system('cls' if os.name == 'nt' else 'clear')
            print(LOGO)
            print("-- FFmpeg is not installed --")
            print("Operating system is Windows\n\nExtracting...")

            with zipfile.ZipFile(FFMPEG_ARCHIVE_PATH, 'r') as zip_ref:
                zip_ref.extractall(DATA_DIR)
            
            FFMPEG_PATH = os.path.join(DATA_DIR, "ffmpeg-master-latest-win64-gpl", "bin", "ffmpeg.exe")
        elif SYSTEM == "Darwin":
            MACOS_FFMPEG_URL = "https://evermeet.cx/ffmpeg/ffmpeg-6.0.7z"
            FFMPEG_ARCHIVE_PATH = os.path.join(DATA_DIR, "ffmpeg.7z")

            print("Operating system is MacOS\n\nDownloading FFmpeg from", MACOS_FFMPEG_URL, "...")

            response = requests.get(MACOS_FFMPEG_URL, stream=True)
            if response.status_code == 200:
                with open(FFMPEG_ARCHIVE_PATH, "wb") as ffmpeg_7z:
                    total_length = int(response.headers.get('content-length'))
                    downloaded = 0

                    for data in response.iter_content(chunk_size=1024):
                        if data:
                            ffmpeg_7z.write(data)
                            downloaded += len(data)
                            progress = (downloaded / total_length) * 100
                            print(f'Downloaded: {downloaded}/{total_length} Bytes ({progress:.2f}%)', end='\r')
            
            os.system('cls' if os.name == 'nt' else 'clear')
            print(LOGO)
            print("-- FFmpeg is not installed --")
            print("Operating system is MacOS\n\nExtracting...")
            
            shutil.unpack_archive(FFMPEG_ARCHIVE_PATH, DATA_DIR)

            FFMPEG_PATH = os.path.join(DATA_DIR, "ffmpeg")
        else:
            print("~ Linux installation instructions ~")
            print("Now open a console and enter the commands below based on your Linux distro, after installation, restart this Python script and you should be able to start!")
            print("Ubuntu/Debian:\nsudo apt-get update\nsudo apt-get install ffmpeg\n\nCentOS/RHEL:\nsudo yum install epel-release\nsudo yum install ffmpeg\n\nFedora:\nsudo dnf install ffmpeg\n\nArch Linux:\nsudo pacman -S ffmpeg\n\nopenSUSE:\nsudo zypper install ffmpeg\n\nGeneric Linux (with snap)\nsudo snap install ffmpeg")
            input("\nEnter: ")
            exit()
        
        with open(FFMPEG_CONF_PATH, "w") as file:
            file.write(FFMPEG_PATH)
        os.system('cls' if os.name == 'nt' else 'clear')

if not os.path.isfile(CREDENTIALS_PATH):
    while True:
        while True:
            os.system('cls' if os.name == 'nt' else 'clear')
            print(LOGO)
            spotify_client_id = input("Please enter your Spotify Client ID: ")
            if len(spotify_client_id) == 32:
                break
            print("[Error] A Spotify Client ID must normally have 32 characters.")
            input("\nEnter: ")
        while True:
            os.system('cls' if os.name == 'nt' else 'clear')
            print(LOGO)
            print(f"Please enter your Spotify Client ID: {spotify_client_id}\n")
            spotify_client_secret = input("Please enter your Spotify Client Secret: ")
            if len(spotify_client_secret) == 32:
                break
            print("[Error] A Spotify Client Secret must normally have 32 characters.")
            input("\nEnter: ")
        try:
            sp_oauth = SpotifyClientCredentials(client_id = spotify_client_id, client_secret = spotify_client_secret)
            sp = spotipy.Spotify(client_credentials_manager=sp_oauth)
            track = sp.track(track_id="4cOdK2wGLETKBW3PvgPWqT")
        except Exception as e:
            print(f"[Error] When connecting to Spotify the following error occurred: '{str(e)}' this could be because the credentials are wrong.")
            input("\nEnter: ")
        else:
            break
    with open(CREDENTIALS_PATH, "w") as file:
        file.write(spotify_client_id + "---" + spotify_client_secret)
else:
    with open(CREDENTIALS_PATH, "r") as file:
        credentials = file.read().split("---")
    spotify_client_id, spotify_client_secret = credentials

app = Flask("Spotofy")
app.after_request(Session._after_request)

log = logging.getLogger('werkzeug')
log.setLevel(logging.WARNING)

@app.route("/")
def index():
    return "Hello World!"

os.system('cls' if os.name == 'nt' else 'clear')
print(LOGO)
app.run(host = "localhost", port = 8080)
