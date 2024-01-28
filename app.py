from flask import *
from flask_mysqldb import MySQL
from flask_htmlmin import HTMLMIN

import hashlib
import requests
import json
from urllib.parse import quote, unquote, urlparse
import re
import os

vidzy_version = "v0.0.9"

mysql = MySQL()
app = Flask(__name__, static_url_path='')

app.config.from_pyfile('settings.py', silent=False)

if app.config['MINIFY_HTML']:
    htmlmin = HTMLMIN(app, remove_comments=True)

mysql.init_app(app)

@app.template_filter('image_proxy')
def image_proxy(src):
    return "/proxy/?url=" + quote(str(src))


@app.template_filter('get_gravatar')
def get_gravatar(email):
    return "https://www.gravatar.com/avatar/" + hashlib.md5(email.encode()).hexdigest() + "?d=mp"


@app.route('/proxy/')
def route_proxy():
    url = request.args.get("url")
    if url != None:
        if re.search(r"https://media.*?/media_attachments/", url):
            data = requests.get(unquote(url))
            content_type = data.headers["content-type"]
            if content_type.startswith("image/") or content_type.startswith("video/"):
                return Response(data.content, content_type=data.headers["content-type"])
            else:
                return Response(render_template("400.html"), status=400)
        else:
            return Response(render_template("400.html"), status=400)
    else:
        return Response(render_template("400.html"), status=400)


@app.route("/like_post")
def like_post_page():
    mycursor = mysql.connection.cursor()

    mycursor.execute("SELECT * FROM likes WHERE short_id = " +
                     str(request.args.get("id")) + " AND user_id = " + str(session["user"]["id"]))

    myresult = mycursor.fetchall()

    for x in myresult:
        return "Already Liked"

    mycursor = mysql.connection.cursor()

    sql = "INSERT INTO `likes` (`short_id`, `user_id`) VALUES (%s, %s)"
    val = (request.args.get("id"), session["user"]["id"])
    mycursor.execute(sql, val)

    mysql.connection.commit()

    return "Success"


@app.route("/if_liked_post")
def liked_post_page():
    mycursor = mysql.connection.cursor()

    mycursor.execute("SELECT * FROM likes WHERE short_id = " +
                     str(request.args.get("id")) + " AND user_id = " + str(session["user"]["id"]))

    myresult = mycursor.fetchall()

    for x in myresult:
        return "true"

    return "false"


@app.route("/")
def index_page():
    if not "username" in session:
        return "<script>window.location.href='/login';</script>"

    cur = mysql.connection.cursor()
    cur.execute("SELECT *, (SELECT count(*) FROM `likes` WHERE short_id = p.id) likes, (SELECT username FROM `users` WHERE id = p.user_id) username FROM shorts p INNER JOIN follows f ON (f.following_id = p.user_id) WHERE f.follower_id = " +
                str(session["user"]["id"]) + " OR p.user_id = " + str(session["user"]["id"]) + " LIMIT 20;")
    rv = cur.fetchall()

    return render_template('index.html', shorts=rv, session=session)


@app.route("/search")
def search_page():
    if not "username" in session:
        return "<script>window.location.href='/login';</script>"

    query = request.args.get('q')

    cur = mysql.connection.cursor()
    cur.execute("SELECT *, (SELECT count(*) FROM `likes` WHERE short_id = p.id) likes FROM shorts p INNER JOIN follows f ON (f.following_id = p.user_id) WHERE title LIKE '%" +
                query + "%' ORDER BY f.follower_id = " + str(session["user"]["id"]) + ", p.user_id = " + str(session["user"]["id"]) + " LIMIT 20;")
    rv = cur.fetchall()

    return render_template('search.html', shorts=rv, session=session, query=query)


@app.route("/explore")
def explore_page():
    if not "username" in session:
        return "<script>window.location.href='/login';</script>"

    cur = mysql.connection.cursor()
    cur.execute(
        "SELECT *, (SELECT count(*) FROM `likes` p WHERE short_id = p.id) likes FROM shorts LIMIT 20;")
    rv = cur.fetchall()

    return render_template('explore.html', shorts=rv, session=session)


@app.route("/yt")
def yt_page():
    if not "username" in session:
        return "<script>window.location.href='/login';</script>"

    r = requests.get(app.config["invidious_instance"] +
                     "/api/v1/search?q=duration:short&sort_by=rating&features=creative_commons").text
    rv = json.loads(r)[:8]

    return render_template('yt.html', shorts=rv, session=session, invidious_instance=app.config["invidious_instance"])


@app.route("/pt")
def pt_page():
    if not "username" in session:
        return "<script>window.location.href='/login';</script>"

    r = requests.get("https://share.tube/api/v1/videos").text
    rv = json.loads(r)

    print(rv)

    return render_template('pt.html', shorts=rv, session=session)


@app.route("/users/<user>")
def profile_page(user):
    if not "username" in session:
        return "<script>window.location.href='/login';</script>"

    cur = mysql.connection.cursor()

    cur.execute("SELECT * FROM users WHERE username='" + user + "';")
    user = cur.fetchall()[0]

    cur.execute("SELECT * FROM shorts WHERE user_id='" +
                str(user["id"]) + "';")
    print("SELECT * FROM shorts WHERE user_id='" + str(user["id"]) + "';")
    latest_short_list = cur.fetchall()

    return render_template('profile.html', user=user, session=session, latest_short_list=latest_short_list)


@app.route("/hcard/users/<guid>")
def hcard_page(guid):
    user = bytes.fromhex(guid).decode('utf-8')

    cur = mysql.connection.cursor()

    cur.execute("SELECT * FROM users WHERE username='" + user + "';")
    user = cur.fetchall()[0]

    cur.execute("SELECT * FROM shorts WHERE user_id='" +
                str(user["id"]) + "';")
    print("SELECT * FROM shorts WHERE user_id='" + str(user["id"]) + "';")
    latest_short_list = cur.fetchall()

    return render_template('profile_hcard.html', user=user, session=session, latest_short_list=latest_short_list, guid=guid)


@app.route("/external/users/<user>")
def external_profile_page(user):
    if not "username" in session:
        return "<script>window.location.href='/login';</script>"

    acc = json.loads(requests.get(
        "https://mstdn.social/api/v1/accounts/lookup?acct=stux@mstdn.social").text)

    posts = json.loads(requests.get(
        "https://mstdn.social/api/v1/accounts/" + acc["id"] + "/statuses").text)

    return render_template('external_profile.html', user=acc, session=session, posts=posts)


@app.route("/users/<user>/feed")
def profile_feed_page(user):
    cur = mysql.connection.cursor()

    cur.execute("SELECT * FROM users WHERE username='" + user + "';")
    user = cur.fetchall()[0]

    cur.execute("SELECT * FROM shorts WHERE user_id='" +
                str(user["id"]) + "';")
    latest_short_list = cur.fetchall()

    resp = make_response(render_template(
        'profile_feed.xml', user=user, session=session, latest_short_list=latest_short_list))
    resp.headers['Content-type'] = 'text/xml; charset=utf-8'
    return resp


@app.route("/shorts/<short>")
def short_page(short):
    if not "username" in session:
        return "<script>window.location.href='/login';</script>"

    cur = mysql.connection.cursor()
    cur.execute("SELECT *, (SELECT count(*) FROM `likes` WHERE short_id = p.id) likes FROM shorts p WHERE id = '" + short + "';")
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

        mycursor.execute(
            "SELECT * FROM users WHERE username = %s;", (username,))

        myresult = mycursor.fetchall()

        for x in myresult:
            if x["password"] == hashlib.sha256(password.encode()).hexdigest():
                session["username"] = username
                session["id"] = x["id"]
                session["user"] = x
                return "<script>window.location.href='/';</script>"
            return "<script>window.location.href='/login';</script>"
    else:
        return render_template("login.html")

@app.route('/register', methods =['GET', 'POST'])
def register():
    if "username" in session:
        return "<script>window.location.href='/';</script>"
    
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form :
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        cursor = mysql.connection.cursor()
        cursor.execute('SELECT * FROM users WHERE username = %s', (username, ))
        account = cursor.fetchone()
        if account:
            msg = 'Account already exists !'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address !'
        elif not re.match(r'[A-Za-z0-9]+', username):
            msg = 'Username must contain only characters and numbers !'
        elif not username or not password or not email:
            msg = 'Please fill out the form !'
        else:
            cursor.execute('INSERT INTO users (`username`, `password`, `email`) VALUES (%s, %s, %s)', (username, hashlib.sha256(password.encode()).hexdigest(), email, ))
            mysql.connection.commit()
            msg = 'You have successfully registered! <a href="/login">Click here to login</a>'
    elif request.method == 'POST':
        msg = 'Please fill out the form !'
    return render_template('register.html', msg = msg)


@app.route('/.well-known/webfinger')
def webfinger():
    info = {}

    info["subject"] = request.args.get("resource")

    info["aliases"] = [request.host_url + "users/" +
                       request.args.get("resource").replace("acct:", "").split("@")[0]]

    info["links"] = [
        {
            "rel": "http://microformats.org/profile/hcard",
            "type": "text/html",
            "href": request.host_url + "hcard/users/" + request.args.get("resource").replace("acct:", "").split("@")[0].encode("utf-8").hex()
        },
        {
            "rel": "http://joindiaspora.com/seed_location",
            "type": "text/html",
            "href": request.host_url
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
        "manuallyApprovesFollowers": True,
        "discoverable": True,
        "published": "2000-01-01T00:00:00Z",
    }

    resp = Response(json.dumps(info))
    resp.headers['Content-Type'] = 'application/json'
    return resp


@app.route('/api/v1/instance')
def instance_info():
    info = {
        "uri": str(urlparse(request.base_url).scheme) + "://" + str(urlparse(request.base_url).netloc),
        "title": "Vidzy",
        "short_description": "The testing server operated by Vidzy",
        "description": "",
        "version": vidzy_version
    }

    resp = Response(json.dumps(info))
    resp.headers['Content-Type'] = 'application/json'
    return resp

def create_app():
    return app

if __name__ == "__main__":
    app.run(host=app.config["HOST"], debug=True)
