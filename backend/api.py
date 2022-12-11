from flask import Flask, request 
from flask_socketio import SocketIO,send, emit, join_room, leave_room

from flask import Flask

app = Flask(__name__)

requestFiles = {}
masters = {}
@app.route("/requestfile" , methods = ['POST'])
def requestfile():
    payload = request.get_json()
    requestFiles[payload['filename']] = payload['key']
    print(requestFiles)
    return "okay"

@app.route("/submitMasterKey" , methods = ['POST' , 'GET'])
def submitMasterKey():
    payload = request.get_json()
    masters[payload['p']] = {"masterKey" : payload['message'] , "filename" : payload['file']}
    del requestFiles[payload['file']]
    print(masters)
    return "okay"


@app.route("/checkMasterKeys" , methods = ['POST'])
def checkMasterKeys():
    payload = request.get_json()
    return masters[payload['n']]

@app.route("/checkMasterKeysRequests" , methods = ['GET'])
def checkMasterKeysRequests():
    return requestFiles

if __name__ == '__main__':
    app.run(debug=True , host="0.0.0.0")