from flask import Flask, request, jsonify
app = Flask(__name__)

@app.route("/events", methods=['POST'])
def events():
    print request.json
    return 'Ack'
