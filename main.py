from flask import Flask

app = Flask("Spotofy")

@app.route("/")
def index():
    return "Hello World!"

if __name__ == "__main__":
    app.run(host = "localhost", port = 8080)
