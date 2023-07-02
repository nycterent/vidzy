from flask import *
from flask_mysqldb import MySQL
import requests
import json
import mysql.connector

app = Flask(__name__, static_url_path='')

app.secret_key = "DONT_DO_THIS_IN_PRODUCTION"
#app.secret_key = secrets.token_hex()

app.config["MYSQL_USER"] = "root"
app.config["MYSQL_PASSWORD"] = "1234"
app.config["MYSQL_DB"] = "vidzy"
app.config["MYSQL_CURSORCLASS"] = "DictCursor"

mydb = mysql.connector.connect(
  host="localhost",
  user="root",
  password="1234",
  database="vidzy"
)

mysql = MySQL(app)

@app.route("/like_post")
def like_post_page():
    mycursor = mysql.connection.cursor()



    mycursor.execute("SELECT * FROM likes WHERE short_id = " + str(request.args.get("id")) + " AND user_id = " + str(session["user"]["id"]))

    myresult = mycursor.fetchall()

    for x in myresult:
        return "Already Liked"

    mycursor = mysql.connection.cursor()

    sql = "INSERT INTO likes (`short_id`, `user_id`) VALUES (%s, %s)"
    val = (request.args.get("id"), str(session["user"]["id"]))
    mycursor.execute(sql, val)

    mydb.commit()

    return "Success"

@app.route("/if_liked_post")
def liked_post_page():
    mycursor = mysql.connection.cursor()
    
    mycursor.execute("SELECT * FROM likes WHERE short_id = " + str(request.args.get("id")) + " AND user_id = " + str(session["user"]["id"]))

    myresult = mycursor.fetchall()

    for x in myresult:
        return "true"

    return "false"

@app.route("/")
def index_page():
    if not "username" in session:
        return "<script>window.location.href='/login';</script>"

    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM shorts p INNER JOIN follows f ON (f.following_id = p.user_id) WHERE f.follower_id = " + str(session["user"]["id"]) + " OR p.user_id = " + str(session["user"]["id"]) + " LIMIT 20;")
    rv = cur.fetchall()

    return render_template('index.html', shorts=rv, session=session)

@app.route("/explore")
def explore_page():
    if not "username" in session:
        return "<script>window.location.href='/login';</script>"

    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM shorts LIMIT 20;")
    rv = cur.fetchall()

    return render_template('explore.html', shorts=rv, session=session)

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

@app.route("/users/<user>/feed")
def profile_feed_page(user):
    cur = mysql.connection.cursor()

    cur.execute("SELECT * FROM users WHERE username='" + user + "';")
    user = cur.fetchall()[0]
    
    cur.execute("SELECT * FROM shorts WHERE user_id='" + str(user["id"]) + "';")
    latest_short_list = cur.fetchall()

    resp = make_response(render_template('profile_feed.xml', user=user, session=session, latest_short_list=latest_short_list))
    resp.headers['Content-type'] = 'text/xml; charset=utf-8'
    return resp

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

@app.route('/.well-known/webfinger')
def webfinger():
    info = {}

    info["subject"] = request.args.get("resource")

    info["aliases"] = [request.host_url + "users/" + request.args.get("resource").replace("acct:", "").split("@")[0]]

    info["links"] = [
		{
			"rel": "self",
			"type": "application/activity+json",
			"href": request.host_url + "activitypub/actor/" + request.args.get("resource").replace("acct:", "").split("@")[0]
		}
    ]

    if info["subject"].split("@")[1] != request.host:
        return " "

    resp = Response(json.dumps(info))
    resp.headers['Content-Type'] = 'application/json'
    return resp

@app.route('/activitypub/actor/<user>')
def activitypub_actor(user):
    info = {
        "@context": [
            "https://www.w3.org/ns/activitystreams",
            "https://w3id.org/security/v1"
        ],

        "id": request.base_url,
        "type": "Person",
        "following": "https://mastodon.jgarr.net/following",
        "followers": "https://mastodon.jgarr.net/followers",
        "featured": "https://mastodon.jgarr.net/featured",
        "inbox": "https://mastodon.jgarr.net/inbox",
        "outbox": "https://mastodon.jgarr.net/outbox",
        "preferredUsername": user,
        "name": "Justin Garrison",
        "summary": "Static mastodon server example.",
        "url": "https://justingarrison.com",
        "manuallyApprovesFollowers": true,
        "discoverable": true,
        "published": "2000-01-01T00:00:00Z",
    }

    resp = Response(json.dumps(info))
    resp.headers['Content-Type'] = 'application/json'
    return resp

if __name__ == "__main__":
    app.run(debug=True)