from flask import *
from flask_mysqldb import MySQL
from flask_htmlmin import HTMLMIN

import hashlib
import requests
import json
import mysql.connector
from urllib.parse import quote, unquote
import re
import os

import vidzy_config

app = Flask(__name__, static_url_path='')

app.secret_key = "DONT_DO_THIS_IN_PRODUCTION"
#app.secret_key = secrets.token_hex()

app.config["MYSQL_USER"] = "root"
app.config["MYSQL_PASSWORD"] = "1234"
app.config["MYSQL_DB"] = "vidzy"
app.config["MYSQL_CURSORCLASS"] = "DictCursor"

if vidzy_config.minify_html:
    app.config['MINIFY_HTML'] = True

    htmlmin = HTMLMIN(app, remove_comments=True)

mydb = mysql.connector.connect(
    host="localhost",
    user="root",
    password="1234",
    database="vidzy"
)

mysql = MySQL(app)


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
        if re.search("https:\/\/media\..*\/media_attachments\/", url):
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

    mydb.commit()

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

    r = requests.get(vidzy_config.invidious_instance +
                     "/api/v1/search?q=duration:short&sort_by=rating&features=creative_commons").text
    rv = json.loads(r)[:8]

    return render_template('yt.html', shorts=rv, session=session, invidious_instance=vidzy_config.invidious_instance)


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
        "uri": "127.0.0.1:5000",
        "title": "Vidzy",
        "short_description": "The testing server operated by Vidzy",
        "description": "",
        "email": "",
        "version": "4.1.2+nightly-20230705",
        "urls": {
            "streaming_api": "wss://streaming.mastodon.online"
        },
        "stats": {
            "user_count": 181756,
            "status_count": 5486286,
            "domain_count": 35493
        },
        "thumbnail": "https://files.mastodon.online/site_uploads/files/000/000/001/@1x/dac498d1edf4191b.png",
        "languages": [
            "en"
        ],
        "registrations": True,
        "approval_required": False,
        "invites_enabled": True,
        "configuration": {
            "accounts": {
                "max_featured_tags": 10
            },
            "statuses": {
                "max_characters": 500,
                "max_media_attachments": 4,
                "characters_reserved_per_url": 23
            },
            "media_attachments": {
                "supported_mime_types": [
                    "image/jpeg",
                    "image/png",
                    "image/gif",
                    "image/heic",
                    "image/heif",
                    "image/webp",
                    "image/avif",
                    "video/webm",
                    "video/mp4",
                    "video/quicktime",
                    "video/ogg",
                    "audio/wave",
                    "audio/wav",
                    "audio/x-wav",
                    "audio/x-pn-wave",
                    "audio/vnd.wave",
                    "audio/ogg",
                    "audio/vorbis",
                    "audio/mpeg",
                    "audio/mp3",
                    "audio/webm",
                    "audio/flac",
                    "audio/aac",
                    "audio/m4a",
                    "audio/x-m4a",
                    "audio/mp4",
                    "audio/3gpp",
                    "video/x-ms-asf"
                ],
                "image_size_limit": 16777216,
                "image_matrix_limit": 33177600,
                "video_size_limit": 103809024,
                "video_frame_rate_limit": 120,
                "video_matrix_limit": 8294400
            },
            "polls": {
                "max_options": 4,
                "max_characters_per_option": 50,
                "min_expiration": 300,
                "max_expiration": 2629746
            }
        },
        "contact_account": {
            "id": "6891",
            "username": "Mastodon",
            "acct": "Mastodon@mastodon.social",
            "display_name": "Mastodon",
            "locked": False,
            "bot": False,
            "discoverable": True,
            "group": False,
            "created_at": "2016-11-23T00:00:00.000Z",
            "note": "<p>Official account of the Mastodon project. News, releases, announcements! Learn more on our website!</p>",
            "url": "https://mastodon.social/@Mastodon",
            "avatar": "https://files.mastodon.online/cache/accounts/avatars/000/006/891/original/331abf389ab49bb1.png",
            "avatar_static": "https://files.mastodon.online/cache/accounts/avatars/000/006/891/original/331abf389ab49bb1.png",
            "header": "https://files.mastodon.online/cache/accounts/headers/000/006/891/original/4d816e58a8569ecf.png",
            "header_static": "https://files.mastodon.online/cache/accounts/headers/000/006/891/original/4d816e58a8569ecf.png",
            "followers_count": 784750,
            "following_count": 8,
            "statuses_count": 239,
            "last_status_at": "2023-07-02",
            "emojis": [],
            "fields": [
                {
                    "name": "Homepage",
                    "value": "<a href=\"https://joinmastodon.org\" rel=\"nofollow noopener noreferrer\" translate=\"no\" target=\"_blank\"><span class=\"invisible\">https://</span><span class=\"\">joinmastodon.org</span><span class=\"invisible\"></span></a>",
                    "verified_at": "2023-07-05T19:25:17.795+00:00"
                },
                {
                    "name": "Patreon",
                    "value": "<a href=\"https://patreon.com/mastodon\" rel=\"nofollow noopener noreferrer\" translate=\"no\" target=\"_blank\"><span class=\"invisible\">https://</span><span class=\"\">patreon.com/mastodon</span><span class=\"invisible\"></span></a>",
                    "verified_at": None
                },
                {
                    "name": "GitHub",
                    "value": "<a href=\"https://github.com/mastodon\" rel=\"nofollow noopener noreferrer\" translate=\"no\" target=\"_blank\"><span class=\"invisible\">https://</span><span class=\"\">github.com/mastodon</span><span class=\"invisible\"></span></a>",
                    "verified_at": "2023-07-05T19:25:20.250+00:00"
                }
            ]
        },
        "rules": [
            {
                "id": "1",
                "text": "No racism, sexism, homophobia, transphobia, xenophobia, or casteism"
            },
            {
                "id": "6",
                "text": "Sexually explicit or violent media must be marked as sensitive when posting"
            },
            {
                "id": "7",
                "text": "No incitement of violence or promotion of violent ideologies"
            },
            {
                "id": "8",
                "text": "No harassment, dogpiling or doxxing of other users"
            },
            {
                "id": "10",
                "text": "Do not share false or misleading information that may lead to physical harm"
            }
        ]
    }

    resp = Response(json.dumps(info))
    resp.headers['Content-Type'] = 'application/json'
    return resp


@app.route('/api/v1/apps', methods=['POST'])
def api_apps_page():
    info = {
        "id": "563419",
        "name": request.get_json().get("client_name"),
        "website": None,
        "redirect_uri": "urn:ietf:wg:oauth:2.0:oob",
        "client_id": "client_id",
        "client_secret": "ZEaFUFmF0umgBX1qKJDjaU99Q31lDkOU8NutzTOoliw",
    }
    resp = Response(json.dumps(info))
    resp.headers['Content-Type'] = 'application/json'
    return resp


@app.route('/oauth/authorize/')
def authorize_oauth():
    if request.args.get("response_type") == "code" and request.args.get("redirect_uri") == "urn:ietf:wg:oauth:2.0:oob":
        return "Here is your code: 123456"
    else:
        return "A response type other than code is not supported"


@app.route('/oauth/token', methods=['POST', 'GET'])
def oauth_token_page():
    # has to return something like    https://docs.joinmastodon.org/methods/oauth/#token
    return request.get_json()


def create_app():
    return app


if __name__ == "__main__":
    app.run(host=vidzy_config.host, debug=True)
