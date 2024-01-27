"""
This open-source software, named 'Spotofy' is distributed under the Apache 2.0 license.
GitHub: https://github.com/tn3w/Spotofy
"""

import re
import os
import logging
import subprocess
import platform
import zipfile
import shutil
from flask import Flask, request, send_file, g
import spotipy
from spotipy.oauth2 import SpotifyClientCredentials
import requests
from utils import Session, Spotofy, Linux, YouTube, get_music,\
                  render_template, before_request_get_info, shorten_text

if __name__ != "__main__":
    exit()

LOGO = r"""   _____             __        ____
  / ___/____  ____  / /_____  / __/_  __
  \__ \/ __ \/ __ \/ __/ __ \/ /_/ / / /
 ___/ / /_/ / /_/ / /_/ /_/ / __/ /_/ / 
/____/ .___/\____/\__/\____/_/  \__, /  
    /_/                        /____/
"""

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(CURRENT_DIR, "templates")
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
        with open(os.devnull, 'w', encoding = "utf-8") as devnull:
            subprocess.call(["ffmpeg", "--version"], stdout=devnull, stderr=devnull)
    except OSError:
        os.system('cls' if os.name == 'nt' else 'clear')
        print(LOGO)
        print("-- FFmpeg is not installed --")
        if SYSTEM not in ["Windows", "Darwin", "Linux"]:
            while True:
                print("Operating system not found...\n\nPlease install FFmpeg by following the instructions on the following web page for your operating system:\nhttps://ffmpeg.org/download.html")
                print('Unzip the downloaded "7z" or "zip" file, and go into the unzipped folder and search for the "ffmpeg.<extension>" file, now copy the path of this file and enter it below.')
                FFMPEG_PATH = input("[FFMPEG PATH]: ")
                FFMPEG_PATH = FFMPEG_PATH.strip()
                if FFMPEG_PATH == "":
                    print("\n[Error] You have not given a path.")
                    input("Enter: ")
                if not os.path.isfile(FFMPEG_PATH):
                    print("\n[Error] The specified path does not exist.")
                    input("Enter: ")
                else:
                    try:
                        with open(os.devnull, 'w', encoding = "utf-8") as devnull:
                            subprocess.call([FFMPEG_PATH, "--version"], stdout=devnull, stderr=devnull)
                    except OSError:
                        print("\n[Error] The given FFMPEG does not work properly.")
                        input("Enter: ")
                    else:
                        break
        elif SYSTEM == "Windows":
            WINDOWS_FFMPEG_URL = "https://github.com/BtbN/FFmpeg-Builds/releases/download/latest/ffmpeg-master-latest-win64-gpl.zip"
            FFMPEG_ARCHIVE_PATH = os.path.join(DATA_DIR, "ffmpeg.zip")

            print("Operating system is Windows\n\nDownloading FFmpeg from", WINDOWS_FFMPEG_URL, "...")

            response = requests.get(WINDOWS_FFMPEG_URL, stream=True, timeout = 3)
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
            Linux.install_package("ffmpeg")

        try:
            FFMPEG_PATH
            with open(FFMPEG_CONF_PATH, "w") as file:
                file.write(FFMPEG_PATH)
        except:
            pass
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

    with open(CREDENTIALS_PATH, "w", encoding = "utf-8") as file:
        file.write(spotify_client_id + "---" + spotify_client_secret)
else:
    with open(CREDENTIALS_PATH, "r", encoding = "utf-8") as file:
        credentials = file.read().split("---")

    spotify_client_id, spotify_client_secret = credentials

app = Flask("Spotofy")

app.before_request(before_request_get_info)
app.after_request(Session._after_request)

log = logging.getLogger('werkzeug')
log.setLevel(logging.WARNING)

spotofy = Spotofy()

@app.route("/", methods = ["GET", "POST"])
def index():
    "Returns the main page and the search function"

    sections = []

    session: Session = g.session

    if request.method == "POST":
        try:
            search_q = request.form["q"].strip()
        except:
            pass
        else:
            if not search_q == "" and not len(search_q) > 40:
                results = spotofy.search(search_q)
                num_results = len(results["tracks"]) + len(results["playlists"]) + len(results["artists"])

                if num_results == 0:
                    sections.append({"title": "No search results were found", "tracks": []})
                else:
                    sections.extend([
                        {"title": "Tracks found", "tracks": results["tracks"]},
                        {"title": "Playlists found", "tracks": results["playlists"]},
                        {"title": "Artists found", "tracks": results["artists"]}
                    ])

    if len(sections) == 0:
        played_tracks = session["played_tracks"]
        if played_tracks is None:
            played_tracks = []

        if len(played_tracks) != 0:
            tracks = spotofy.recommendations(seed_tracks = played_tracks, country = g.info["countryCode"])
        else:
            tracks = spotofy.recommendations(seed_genres = ["pop", "electropop", "synthpop", "indie pop"], country = g.info["countryCode"])

        formatted_tracks = []
        for track in tracks:
            track["name"] = shorten_text(track["name"])
            formatted_tracks.append(track)

        sections.extend([
            {"title": "You might like this", "tracks": tracks[:8]},
            {"title": "Do you know this already", "tracks": tracks[8:16]},
        ])

        if len(played_tracks) != 0:
            new_tracks = []
            for track_id in played_tracks:
                track = spotofy.track(track_id)
                new_tracks.append(track)

            sections.append({"title": "Recently played", "tracks": new_tracks[:8]})
    return render_template("index.html", sections=sections)

@app.route("/api/track")
def api_track():
    """
    Api Route to query information about a specific track
    e.g. `curl -X GET "https://example.com/api/track?spotify_track_id=7I3skNaQdvZSS7zXY2VHId" -H "Content-Type: application/json"`

    :arg spotify_track_id: The ID of the Spotify track
    """

    spotify_track_id = request.args.get("spotify_track_id")

    if spotify_track_id is None: return {"status_code": 400, "error": "Bad Request - The spotify_track_id parameter is not given."}, 400
    if len(spotify_track_id) != 22: return {"status_code": 400, "error": "Bad Request - The Spotify track ID given in spotify_track_id is incorrect."}, 400
    if not re.match(r'^[a-zA-Z0-9]+$', spotify_track_id, re.IGNORECASE): return {"status_code": 400, "error": "Bad Request - The Spotify track ID given in spotify_track_id is incorrect."}, 400

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
    """
    Api Route to query information about a specific artist
    e.g. `curl -X GET "https://example.com/api/artist?spotify_artist_id=3YQKmKGau1PzlVlkL1iodx" -H "Content-Type: application/json"`

    :arg spotify_artist_id: The ID of the Spotify artist
    """

    spotify_artist_id = request.args.get("spotify_artist_id")

    if spotify_artist_id is None: return {"status_code": 400, "error": "Bad Request - The spotify_artist_id parameter is not given."}, 400
    if len(spotify_artist_id) != 22: return {"status_code": 400, "error": "Bad Request - The Spotify artist ID given in spotify_artist_id is incorrect."}, 400
    if not re.match(r'^[a-zA-Z0-9]+$', spotify_artist_id, re.IGNORECASE): return {"status_code": 400, "error": "Bad Request - The Spotify artist ID given in spotify_artist_id is incorrect."}, 400

    artists = spotofy._load(ARTISTS_CACHE_PATH)
    if artists.get(spotify_artist_id) is None:
        try:
            return spotofy.artist(spotify_artist_id)
        except:
            return {"status_code": 400, "error": "Bad Request - The Spotify track ID given in spotify_track_id is incorrect."}, 400
    return artists.get(spotify_artist_id)

@app.route("/api/playlist")
def api_playlist():
    """
    Api Route to query information about a specific playlist
    e.g. `curl -X GET "https://example.com/api/playlist?spotify_playlist_id=37i9dQZF1E4yrYiQJfy370&limit=20" -H "Content-Type: application/json"`

    :arg spotify_playlist_id: The ID of the Spotify playlist
    :arg limit: How many tracks contained in the playlist should be returned
    """

    spotify_playlist_id = request.args.get("spotify_playlist_id")

    if spotify_playlist_id is None: return {"status_code": 400, "error": "Bad Request - The spotify_playlist_id parameter is not given."}, 400
    if len(spotify_playlist_id) != 22: return {"status_code": 400, "error": "Bad Request - The Spotify playlist ID given in spotify_playlist_id is incorrect."}, 400
    if not re.match(r'^[a-zA-Z0-9]+$', spotify_playlist_id, re.IGNORECASE): return {"status_code": 400, "error": "Bad Request - The Spotify playlist ID given in spotify_playlist_id is incorrect."}, 400

    limit = request.args.get("limit", 50)

    if not limit.isdigit(): return {"status_code": 400, "error": "Bad Request - The limit parameter must be an integer."}, 400
    if int(limit) > 100: return {"status_code": 400, "error": "Bad Request - The limit parameter must not be greater than 100."}, 400

    playlists = spotofy._load(PLAYLISTS_CACHE_PATH)
    if playlists.get(spotify_playlist_id) is None:
        try:
            return spotofy.playlist(spotify_playlist_id, limit)
        except:
            return {"status_code": 400, "error": "Bad Request - The Spotify playlist ID given in spotify_playlist_id is incorrect."}, 400
    return playlists.get(spotify_playlist_id)
    
@app.route("/api/music")
def api_music():
    """
    Api route to query music of a specific track
    e.g. `curl -o TheHype_TwentyOnePilots.mp3 "https://example.com/api/music?spotify_track_id=7I3skNaQdvZSS7zXY2VHId"`

    :arg spotify_track_id: The ID of the Spotify track
    """

    spotify_track_id = request.args.get("spotify_track_id")

    if spotify_track_id is None: return {"status_code": 400, "error": "Bad Request - The spotify_track_id parameter is not given."}, 400
    if len(spotify_track_id) != 22: return {"status_code": 400, "error": "Bad Request - The Spotify track ID given in spotify_track_id is incorrect."}, 400
    if not re.match(r'^[a-zA-Z0-9]+$', spotify_track_id, re.IGNORECASE): return {"status_code": 400, "error": "Bad Request - The Spotify track ID given in spotify_track_id is incorrect."}, 400

    tracks = spotofy._load(TRACKS_CACHE_PATH)
    if tracks.get(spotify_track_id) is None:
        try:
            track = spotofy.track(spotify_track_id)
        except:
            return {"status_code": 400, "error": "Bad Request - The Spotify track ID given in spotify_track_id is incorrect."}, 400
    else:
        track = tracks.get(spotify_track_id)

    session: Session = g.session

    played_tracks = session["played_tracks"]
    if played_tracks is None:
        played_tracks = []

    played_tracks.append(spotify_track_id)
    played_tracks = list(dict.fromkeys(played_tracks).keys())
    session["played_tracks"] = played_tracks

    if track.get("youtube_id") is None:
        track_search = track["name"] + " "
        for i, artist in enumerate(track["artists"]):
            if not i == len(track["artists"]) - 1:
                track_search += artist["name"] + ", "
            else:
                track_search += artist["name"] + " "
        track_search += "Full Lyrics"

        youtube_id = YouTube.search_ids(track_search, spotify_track_id)[0]
    else:
        youtube_id = track.get("youtube_id")
    
    if youtube_id is None:
        return {"status_code": 500, "error": "Internal Server Error - An error occurred during your request."}, 500

    music_path = get_music(youtube_id, track["duration_ms"])

    if music_path is None:
        return {"status_code": 500, "error": "Internal Server Error - An error occurred during your request."}, 500

    file_name = track["name"].replace(" ", "") + "_" + track["artists"][0]["name"].replace(" ", "") + ".mp3"
    return send_file(music_path, as_attachment = True, download_name = file_name, max_age = 3600)

@app.route("/api/youtube_music")
def api_youtube_music():
    """
    Api route to query music of a specific youtube video
    e.g. `curl -o TheHype_TwentyOnePilots.mp3 "https://example.com/api/youtube_music?youtube_id=wbdE_Q_eq2k"`

    :arg youtube_id: The ID of the YouTube Video
    """

    youtube_id = request.args.get("youtube_id")

    if youtube_id is None: return {"status_code": 400, "error": "Bad Request - The youtube_id parameter is not given."}, 400
    if len(youtube_id) != 11: return {"status_code": 400, "error": "Bad Request - The YouTube Video ID given in youtube_id is incorrect."}, 400
    if not re.match(r'^[a-zA-Z0-9_-]+$', youtube_id): return {"status_code": 400, "error": "Bad Request - The YouTube Video ID given in youtube_id is incorrect."}, 400

    try:
        video_data = YouTube.get_video(youtube_id)
    except Exception as e:
        return {"status_code": 400, "error": "Bad Request - The YouTube Video ID given in youtube_id is incorrect."}, 400
    
    if video_data.get("duration", 421) > 420:
        return {"status_code": 400, "error": "Bad Request - The given YouTube Video is too long."}, 400
    
    music_path = get_music(youtube_id)

    if music_path is None:
        return {"status_code": 500, "error": "Internal Server Error - An error occurred during your request."}, 500
    
    file_name = video_data["name"].replace(" ", "") + "_" + video_data["artist"].replace(" ", "") + ".mp3"
    return send_file(music_path, as_attachment = True, download_name = file_name, max_age = 3600)


@app.route("/api/played_track")
def api_played_track():
    """
    Api route to add a track to the playes_tracks data
    e.g. `curl -X GET "https://example.com/api/played_track?spotify_track_id=7I3skNaQdvZSS7zXY2VHId" -H "Content-Type: application/json"`

    :arg spotify_track_id: The ID of the Spotify track
    """

    spotify_track_id = request.args.get("spotify_track_id")

    if spotify_track_id is None: return {"status_code": 400, "error": "Bad Request - The spotify_track_id parameter is not given."}, 400
    if len(spotify_track_id) != 22: return {"status_code": 400, "error": "Bad Request - The Spotify track ID given in spotify_track_id is incorrect."}, 400
    if not re.match(r'^[a-zA-Z0-9]+$', spotify_track_id, re.IGNORECASE): return {"status_code": 400, "error": "Bad Request - The Spotify track ID given in spotify_track_id is incorrect."}, 400

    session: Session = g.session
    played_tracks = session["played_tracks"]
    if played_tracks is None:
        played_tracks = []

    played_tracks.append(spotify_track_id)
    played_tracks = list(dict.fromkeys(played_tracks).keys())
    session["played_tracks"] = played_tracks

    return "200"

@app.route("/api/search")
def api_search():
    """
    Api Route to search for tracks, playlists and artists
    e.g. `curl -X GET "https://example.com/api/search?q=The%20Hype%20TwentyOnePilots&max_results=16" -H "Content-Type: application/json"`

    :arg q: What to search for
    :arg max_results: How many results should be returned per section
    """

    q = request.args.get("q")
    if q is None: return {"status_code": 400, "error": "Bad Request - The q parameter is not given."}, 400
    
    max_results = request.args.get("max_results", 8)

    if not max_results.isdigit(): return {"status_code": 400, "error": "Bad Request - The max_results parameter must be an integer."}, 400
    if int(max_results) > 20: return {"status_code": 400, "error": "Bad Request - The max_results parameter cannot be greater than 20."}, 400
    if int(max_results) == 0: return {"status_code": 400, "error": "Bad Request - The max_results parameter cannot be 0."}, 400

    return "", 404

@app.errorhandler(404)
def not_found(_):
    "Route to return a 404 error when a page cannot be found"

    return render_template(os.path.join(TEMPLATE_DIR, "404.html"))

os.system('cls' if os.name == 'nt' else 'clear')
print(LOGO)
print("Running on http://localhost:8010")
app.run(host = "0.0.0.0", port = 8010)
