from flask import Flask, request, send_file
import os
import spotipy
import logging
import subprocess
import platform
import zipfile
import shutil
import requests
from spotipy.oauth2 import SpotifyClientCredentials
from utils import Session, Spotofy, get_music, get_youtube_id

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
TRACKS_CACHE_PATH = os.path.join(CACHE_DIR, "tracks-cache.json")
ARTISTS_CACHE_PATH = os.path.join(CACHE_DIR, "artists-cache.json")
PLAYLISTS_CACHE_PATH = os.path.join(CACHE_DIR, "playlists-cache.json")
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
            FFMPEG_PATH = input("[FFMPEG PATH]: ")
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

spotofy = Spotofy()

@app.route("/")
def index():
    return "Hello World!"

@app.route("/api/track")
def api_track():
    spotify_track_id = request.args.get("spotify_track_id")

    if spotify_track_id is None:
        return {"status_code": 400, "error": "Bad Request - The spotify_track_id parameter is not given."}, 400
    
    if len(spotify_track_id) != 22:
        return {"status_code": 400, "error": "Bad Request - The Spotify track ID given in spotify_track_id is incorrect."}, 400
    
    tracks = spotofy._load(TRACKS_CACHE_PATH)
    if tracks.get(spotify_track_id) is None:
        try:
            track = spotofy.track(spotify_track_id)
        except:
            return {"status_code": 400, "error": "Bad Request - The Spotify track ID given in spotify_track_id is incorrect."}, 400
    else:
        track = tracks.get(spotify_track_id)
    
    return track

@app.route("/api/artist")
def api_artist():
    spotify_artist_id = request.args.get("spotify_artist_id")

    if spotify_artist_id is None:
        return {"status_code": 400, "error": "Bad Request - The spotify_artist_id parameter is not given."}, 400
    
    if len(spotify_artist_id) != 22:
        return {"status_code": 400, "error": "Bad Request - The Spotify artist ID given in spotify_artist_id is incorrect."}, 400
    
    artists = spotofy._load(ARTISTS_CACHE_PATH)
    if artists.get(spotify_artist_id) is None:
        try:
            return spotofy.artist(spotify_artist_id)
        except:
            return {"status_code": 400, "error": "Bad Request - The Spotify track ID given in spotify_track_id is incorrect."}, 400
    else:
        return artists.get(spotify_artist_id)

@app.route("/api/playlist")
def api_playlist():
    spotify_playlist_id = request.args.get("spotify_playlist_id")
    limit = request.args.get("limit")

    if spotify_playlist_id is None:
        return {"status_code": 400, "error": "Bad Request - The spotify_artist_id parameter is not given."}, 400
    
    if limit is None:
        limit = 100
    else:
        try:
            if int(limit) > 100:
                return {"status_code": 400, "error": "Bad Request - The limit parameter must not be greater than 100."}, 400
        except:
            return {"status_code": 400, "error": "Bad Request - The limit parameter must be an integer."}, 400
    
    playlists = spotofy._load(PLAYLISTS_CACHE_PATH)
    if playlists.get(spotify_playlist_id) is None:
        try:
            return spotofy.playlist(spotify_playlist_id, limit)
        except:
            return {"status_code": 400, "error": "Bad Request - The Spotify playlist ID given in spotify_playlist_id is incorrect."}, 400
    else:
        return playlists.get(spotify_playlist_id)
    
@app.route("/api/music")
def api_music():
    spotify_track_id = request.args.get("spotify_track_id")

    if spotify_track_id is None:
        return {"status_code": 400, "error": "Bad Request - The spotify_track_id parameter is not given."}, 400
    
    if len(spotify_track_id) != 22:
        return {"status_code": 400, "error": "Bad Request - The Spotify track ID given in spotify_track_id is incorrect."}, 400
    
    tracks = spotofy._load(TRACKS_CACHE_PATH)
    if tracks.get(spotify_track_id) is None:
        try:
            track = spotofy.track(spotify_track_id)
        except:
            return {"status_code": 400, "error": "Bad Request - The Spotify track ID given in spotify_track_id is incorrect."}, 400
    else:
        track = tracks.get(spotify_track_id)
    
    if track.get("youtube_id") is None:
        track_search = track["name"] + " "
        for index, artist in enumerate(track["artists"]):
            if not index == len(track["artists"]) - 1:
                track_search += artist["name"] + ", "
            else:
                track_search += artist["name"] + " "
        track_search += "Full Lyrics"

        youtube_id = get_youtube_id(track_search, spotify_track_id)
    else:
        youtube_id = track.get("youtube_id")

    music_path = get_music(youtube_id, track["duration_ms"])

    return send_file(music_path)

os.system('cls' if os.name == 'nt' else 'clear')
print(LOGO)
print("Running on http://localhost:8080")
app.run(host = "localhost", port = 8080)
