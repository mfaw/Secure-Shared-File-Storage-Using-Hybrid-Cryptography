from flask import Flask, request 
from flask_socketio import SocketIO,send, emit, join_room, leave_room

from flask import Flask

app = Flask(__name__)

requestFiles = {}
masters = {}
@app.route("/requestfile" , methods = ['POST'])
def requestfile():
    payload = request.get_json()
    if payload['filename'] in requestFiles:
         requestFiles[payload['filename']].append(payload['key'])
    else:
        requestFiles[payload['filename']] = [payload['key']]
    print(requestFiles)
    return "okay"

@app.route("/submitMasterKey" , methods = ['POST' , 'GET'])
def submitMasterKey():
    payload = request.get_json()
    if str(payload['n']) in masters:
        masters[str(payload['n'])].append({"masterKey" : payload['message'] , "filename" : payload['file']})
    else:
        masters[str(payload['n'])] = [{"masterKey" : payload['message'] , "filename" : payload['file']}]

    print(masters)
    del requestFiles[payload['file']]
    return "okay"


@app.route("/checkMasterKeys" , methods = ['POST'])
def checkMasterKeys():
    payload = request.get_json()
    data = masters[str(payload['n'])]
    del masters[str(payload['n'])]
    return data

@app.route("/checkMasterKeysRequests" , methods = ['GET'])
def checkMasterKeysRequests():
    return requestFiles

if __name__ == '__main__':
    app.run(debug=True , host="0.0.0.0")