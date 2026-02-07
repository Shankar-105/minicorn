from flask import Flask
app = Flask(__name__)  # Flask creates callable

@app.route('/home')
def home():
    return {
        "message" : "Hello from, Flask"
    }