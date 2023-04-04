from flask import Flask, render_template, redirect,request,jsonify,session,make_response
import requests
import json
import base64

config = []

with open('config.json','r') as f:
    data = json.load(f)


for key, value in data.items():
    config.append(value)

client_id = config[0]
client_secret = config[1]
redirect_uri = config[2]



def get_widget_token(access_token):
    url = "https://streamlabs.com/api/v2.0/socket/token"
    headers = {
        "accept": "application/json",
        "Authorization": f"Bearer {access_token}"
    }
    response = requests.get(url,headers=headers)
    jwt_token = response.json()
    jwt_token = jwt_token['socket_token']

    jwt_parts = jwt_token.split('.')
    header = jwt_parts[0]
    payload = jwt_parts[1]
    signature = jwt_parts[2]

    # Decode the header and payload using base64
    decoded_header = base64.urlsafe_b64decode(header + '=' * (-len(header) % 4)).decode('utf-8')
    decoded_payload = base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4)).decode('utf-8')

    widget_token = json.loads(decoded_payload)
    widget_token = widget_token['token']
    print(widget_token)
    return widget_token


def oauth(code):
    url = "https://streamlabs.com/api/v2.0/token"
    headers = {"accept": "application/json"}
    data = {
        "grant_type": "authorization_code",
        "client_id": f"{client_id}",
        "client_secret": f"{client_secret}",
        "redirect_uri": f"{redirect_uri}",
        "code":f"{code}"
    }
    response = requests.post(url, data=data ,headers=headers)
    data = response.json()
    access_token = data['access_token']
    print(access_token)
    return access_token


app = Flask(__name__)

app.secret_key = client_secret

@app.route("/")
def index():
    if 'widgetToken' in session:
        return redirect('/projects')
    else:
        return render_template("index.html")

@app.route("/streamlabs/connect")
def redir():
    return redirect(f"https://streamlabs.com/api/v2.0/authorize?client_id={client_id}&redirect_uri={redirect_uri}&scope=profile.basic+alerts.create+socket.token&response_type=code")

@app.route("/streamlabs/auth")
def auth():
    if request.args.get('code'):
        code = request.args.get('code')
        access_token = oauth(code)
        widget_token = get_widget_token(access_token)

        session['type'] = 'user'
        session['widgetToken'] = widget_token
        session['access_token'] = access_token
        
        return redirect('/projects')
    else:
        return("Bad Request.")


@app.route("/projects")
def project():
    if 'widgetToken' in session:
        return render_template("projects.html",widgetToken=session['widgetToken'])
    else:
        return redirect('/')


@app.route('/access_token')
def access_token():
    if 'access_token' in session:
        return session['access_token']
    else:
        return redirect('/')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')


if __name__ == "__main__":
    app.run(host="127.0.0.1",port=1337)
