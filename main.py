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
from utils import Session, Spotofy, Linux, YouTube, LM, get_music,\
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
IMAGE_NOT_FOUND =  "data:image/png;base64,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"

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

@app.route("/")
def index():
    "Returns the main page and the search function"

    session: Session = g.session

    played_tracks = session["played_tracks"]
    if played_tracks is None:
        played_tracks = []

    if len(played_tracks) != 0:
        tracks = spotofy.recommendations(seed_tracks = LM.reverse(played_tracks)[:5], country = g.info["countryCode"])
    else:
        tracks = spotofy.recommendations(seed_genres = ["pop", "electropop", "synthpop", "indie pop"], country = g.info["countryCode"])

    tracks = [{"name": shorten_text(track["name"]), **track} for track in tracks]

    sections = [
        {"title": "You might like this", "tracks": tracks[:8]},
        {"title": "Do you know this already", "tracks": tracks[8:16]},
    ]

    if len(played_tracks) != 0:
        new_tracks = []
        for track_id in played_tracks:
            track = spotofy.track(track_id)
            new_tracks.append(track)

        new_tracks = [{"name": shorten_text(track["name"]), "image": IMAGE_NOT_FOUND if track["image"] is None else track["image"], **track} for track in LM.reverse(new_tracks)]

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

    if not str(limit).isdigit(): return {"status_code": 400, "error": "Bad Request - The limit parameter must be an integer."}, 400
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

    played_tracks = LM.reverse(played_tracks)
    played_tracks.insert(0, spotify_track_id)
    session["played_tracks"] = LM.reverse(LM.remove_duplicates(played_tracks))

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
    
    file_name = video_data["name"].replace(" ", "") + ".mp3"
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

    played_tracks = LM.reverse(played_tracks)
    played_tracks.insert(0, spotify_track_id)
    session["played_tracks"] = LM.reverse(LM.remove_duplicates(played_tracks))

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
    if len(q) == 0 or len(q) > 40: return {"status_code": 400, "error": "Bad Request - The q parameter is not valid."}, 400
    
    max_results = request.args.get("max_results", 8)

    if not str(max_results).isdigit(): return {"status_code": 400, "error": "Bad Request - The max_results parameter must be an integer."}, 400
    max_results = int(max_results)
    if int(max_results) > 8: return {"status_code": 400, "error": "Bad Request - The max_results parameter cannot be greater than 20."}, 400
    if int(max_results) == 0: return {"status_code": 400, "error": "Bad Request - The max_results parameter cannot be 0."}, 400
    
    try:
        spotify_results = spotofy.search(q)

        if not "Lyric" in q:
            if not q.endswith(" "): q += " "
            q += "Lyrics"
        youtube_results = YouTube.search_ids(q)[:max_results + 1]
        videos = YouTube.get_information_about_videos(youtube_results)[:max_results]
    except:
        return {"status_code": 500, "error": "Internal Server Error - The search could not be completed because an error occurred."}, 500
    
    num_results = len(spotify_results["tracks"]) + len(spotify_results["playlists"]) + len(spotify_results["artists"]) + len(youtube_results)

    if num_results == 0:
        sections = {"title": "No search results were found", "tracks": []}
    else:
        def format_objects(objects: list, type: str) -> list:
            new_objects = []
            for object in objects:
                object["name"] = shorten_text(object["name"])
                object["image"] = IMAGE_NOT_FOUND if object["image"] is None else object["image"]
                object["type"] = type
                new_objects.append(object)
            return new_objects
        
        tracks = format_objects(spotify_results["tracks"][:max_results], "track")
        playlists = format_objects(spotify_results["playlists"][:max_results], "playlist")
        artists = format_objects(spotify_results["artists"][:max_results], "artist")
        videos = format_objects(videos, "youtube")
        sections = [
            {"title": "Tracks", "tracks": tracks},
            {"title": "YouTube Videos", "tracks": videos},
            {"title": "Playlists", "tracks": playlists},
            {"title": "Artists", "tracks": artists}
        ]

    return {"sections": sections}

@app.errorhandler(404)
def not_found(_):
    "Route to return a 404 error when a page cannot be found"

    return render_template(os.path.join(TEMPLATE_DIR, "404.html"))

os.system('cls' if os.name == 'nt' else 'clear')
print(LOGO)
print("Running on http://localhost:8010")
app.run(host = "0.0.0.0", port = 8010)
