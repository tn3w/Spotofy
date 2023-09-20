from flask import Flask
import os
import spotipy
import logging
from spotipy.oauth2 import SpotifyClientCredentials
from utils import Session

if not __name__ == "__main__":
    exit()

LOGO = """   _____             __        ____     
  / ___/____  ____  / /_____  / __/_  __
  \__ \/ __ \/ __ \/ __/ __ \/ /_/ / / /
 ___/ / /_/ / /_/ / /_/ /_/ / __/ /_/ / 
/____/ .___/\____/\__/\____/_/  \__, /  
    /_/                        /____/\n"""

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
CREDENTIALS_PATH = os.path.join(CURRENT_DIR, "creds.conf")

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
