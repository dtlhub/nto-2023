from flask import Flask, request, render_template, redirect, url_for, render_template_string, redirect
from os import urandom, getenv
import signal
import func_timeout
app = Flask(__name__)
app.config["SECRET_KEY"] = urandom(16)
FLAG = getenv('FLAG')
allowed = [
    '▶',
    '➡',
    '0',
    '1',
    '2',
    '3',
    '4',
    '5',
    '⬇',
    '❌'
]

checks = {
    "0": "0",
    "1": "1",
    "10": "01",
    "11": "11",
    "00": "00",
    "100": "001",
    "10101": "10101",
    "10111": "11101",
    "1111101": "1011111",
    "1110011": "1100111",
}

def handler(signum, frame):
    raise Exception("end of time")


def machine_run(instructions, input : str):
    index = 0
    state = 0
    while state != 1 and index < len(instructions):
        rep = ('❌' + input + '❌').replace(instructions[index][0],instructions[index][1], 1)
        rep = rep.replace('❌', "")
        if rep == input:
            index += 1
        else:
            print(rep)
            input = rep
            state = instructions[index][2]
            index = 0
    return input

def check_code(buffer):
    buffer = buffer.decode()
    for i in buffer:
        if i not in ['0', '1', '2', '3', '4', '5']:
            print(i)
    lines = buffer.split('\n')
    prep = []
    for i in lines:
        pre = ''
        for j in i:
            if j in allowed:
                pre += j
        prep.append(pre)
    insts = []
    for i in prep:
        if i.find(allowed[0]) == 0 or len(i) - 1 == i.find(allowed[0]):
            return 3
        if i.find(allowed[1]) == 0 or len(i) - 1 == i.find(allowed[1]):
            return 3

        if allowed[0] in i:
            s = i.split(allowed[0])
            insts.append([s[0],s[1], 1])
        elif allowed[1] in i:
            s = i.split(allowed[1])
            insts.append([s[0],s[1], 0])
    if len(insts) == 0:
        return 3
    for check in list(checks.keys()):
        try:
            buf = func_timeout.func_timeout(5,machine_run, (insts, check))
        except:
            return 4
        if buf != checks[check]:
            return 2
    return 0



    

@app.route("/", methods=['POST', 'GET'])
def main():
    if request.method == 'GET':
        answer = "No file provided"
    if request.method == 'POST':
        file = request.files['file']
        if file.filename == '':
            answer = "No file provided"
        else:
            ans = check_code(file.read())
            if ans == 0:
                answer = "Your flag: " + FLAG
            elif ans == 2:
                answer = "Wrong code"
            elif ans == 3:
                answer = "No code in file"
            elif ans == 4:
                answer = "Timeout Error"

    return render_template("index.html", answer=answer)

if __name__ == "__main__":
    app.run("0.0.0.0", port=8080, debug=False)


