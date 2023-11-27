from flask import Flask, request, jsonify
from tempfile import NamedTemporaryFile
import subprocess

app = Flask(__name__)

def check(code):
    blacklist = "{}@_\n\r\\\x00\x09\x0a\x0b\x0c\x0d\x85\xa0"
    for c in code:
        if c in blacklist:
            return False
    return True


def run(code):
    with NamedTemporaryFile() as f:
        f.write(code.encode('utf-8'))
        f.flush()
        return subprocess.check_output([ 'python3', f.name ], timeout=.2)


@app.route("/")
def main():
    return app.send_static_file("index.html")


@app.route("/api/submit", methods=["POST"])
def submit():
    body = request.get_json()
    code = body.get("code", "")

    isValid = check(code)

    if isValid:
        res = run(code)
        return jsonify({ "status": "success", "result": res.decode() })
    return jsonify({ "status": "error", "comment": "filtered" })


if __name__ == "__main__":
    app.run("0.0.0.0", port=5000, debug=False)
