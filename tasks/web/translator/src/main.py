from flask import Flask, request, render_template_string
import os
import re
import requests

with open("./static/index.html", "r") as f:
    TMPL = f.read()


TRANSLATE_API_URL = "https://translate.api.cloud.yandex.net/translate/v2/translate"
API_KEY = os.environ.get("API_KEY", "")
FOLDER_ID = os.environ.get("FOLDER_ID", "")

def translate_to_english(text: str) -> str:
    body = {
        "targetLanguageCode": "en",
        "texts": [text],
        "folderId": FOLDER_ID,
    }
    headers = {
        "Authorization": f"Api-Key {API_KEY}"
    }

    res = requests.post(TRANSLATE_API_URL, headers=headers, json=body)
    res = res.json()
    if not "translations" in res:
        return "Translation error"
    
    return res["translations"][0]["text"]


app = Flask(__name__)


@app.route("/", methods=["GET"])
def main():
    q = request.args.get("q", "")
    if re.search("[A-Za-z]", q):
        q = "English words are not supported in nonenglish languages!"
    elif q != "":
        q = translate_to_english(q)

    # TODO: Add translate API

    return render_template_string(TMPL.format(q))

if __name__ == "__main__":
    app.run("0.0.0.0", port=5000, debug=False)
