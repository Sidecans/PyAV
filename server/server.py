from flask import Flask, request, jsonify, send_file
import os
import hashlib


app = Flask(__name__)

hashFile = "hashes.txt"

def get_file_hash(filepath):
  if not os.path.exists(filepath):
    return None
  with open(filepath, 'rb') as f:
    content = f.read()
    return hashlib.sha256(content).hexdigest()


@app.route('/')
def home(): 
  return jsonify({"message": "PyAV Server is Running"})

@app.route('/get-hashes', methods=['GET'])
def get_hashes():
  if not os.path.exists(hashFile):
    return jsonify({"message": "Hashes file not found"}), 404
  return send_file(hashFile, mimetype="text/plain")

@app.route('/get-version', methods=['GET'])
def get_version():
  version = get_file_hash(hashFile)
  return jsonify({"version": version})


if __name__ == '__main__':
  app.run(host='0.0.0.0', port=8000)
