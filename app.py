from flask import *
from flask_mysqldb import MySQL
import requests
import json

app = Flask(__name__, static_url_path='')

app.secret_key = "DONT_DO_THIS_IN_PRODUCTION"
#app.secret_key = secrets.token_hex()

app.config["MYSQL_USER"] = "root"
app.config["MYSQL_PASSWORD"] = "1234"
app.config["MYSQL_DB"] = "vidzy"
app.config["MYSQL_CURSORCLASS"] = "DictCursor"

mysql = MySQL(app)

@app.route("/")
def index_page():
    if not "username" in session:
        return "<script>window.location.href='/login';</script>"

    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM shorts LIMIT 20;")
    rv = cur.fetchall()

    return render_template('index.html', shorts=rv, session=session)

@app.route("/yt")
def yt_page():
    if not "username" in session:
        return "<script>window.location.href='/login';</script>"

    r = requests.get("https://sea1.iv.ggtyler.dev/api/v1/search?q=duration:short&sort_by=rating&features=creative_commons").text
    rv = json.loads(r)[:8]

    return render_template('yt.html', shorts=rv, session=session)

@app.route("/users/<user>")
def profile_page(user):
    if not "username" in session:
        return "<script>window.location.href='/login';</script>"

    cur = mysql.connection.cursor()

    cur.execute("SELECT * FROM users WHERE username='" + user + "';")
    user = cur.fetchall()[0]

    cur.execute("SELECT * FROM shorts WHERE user_id='" + str(user["id"]) + "';")
    print("SELECT * FROM shorts WHERE user_id='" + str(user["id"]) + "';")
    latest_short_list = cur.fetchall()

    return render_template('profile.html', user=user, session=session, latest_short_list=latest_short_list)

@app.route("/shorts/<short>")
def short_page(short):
    if not "username" in session:
        return "<script>window.location.href='/login';</script>"

    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM shorts WHERE id = '" + short + "';")
    rv = cur.fetchall()[0]

    return render_template('short.html', short=rv, session=session)

@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)

@app.route('/login', methods=['POST', 'GET'])
def login_page():
    if "username" in session:
        return "<script>window.location.href='/';</script>"

    if "username" in request.form:
        username = request.form["username"]
        password = request.form["password"]

        mycursor = mysql.connection.cursor()

        mycursor.execute("SELECT * FROM users WHERE username = '" + username + "';")

        myresult = mycursor.fetchall()

        for x in myresult:
            if x["password"] == password:
                session["username"] = username
                session["id"] = x["id"]
                session["user"] = x
                return "<script>window.location.href='/';</script>"
            return "<script>window.location.href='/login';</script>"
    else:
        return render_template("login.html")

if __name__ == "__main__":
    app.run(debug=True)