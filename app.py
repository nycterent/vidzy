import hashlib
import json
import re
import os
import math
import uuid

import requests
import nh3
import boto3
import vidzyconfig

from operator import itemgetter
from datetime import date

from flask import *
from flask_mysqldb import MySQL
from flask_htmlmin import HTMLMIN

from urllib.parse import quote, unquote, urlparse
from werkzeug.utils import secure_filename
from datetime import datetime
from flask_wtf.csrf import CSRFProtect

from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend

CLEANR = re.compile('<.*?>')
def cleanhtml(raw_html):
    cleantext = re.sub(CLEANR, '', raw_html)
    return cleantext

key = rsa.generate_private_key(
    backend=crypto_default_backend(),
    public_exponent=65537,
    key_size=2048
)

private_key = key.private_bytes(
    crypto_serialization.Encoding.PEM,
    crypto_serialization.PrivateFormat.PKCS8,
    crypto_serialization.NoEncryption())

public_key = key.public_key().public_bytes(
    crypto_serialization.Encoding.PEM,
    crypto_serialization.PublicFormat.SubjectPublicKeyInfo
)


VIDZY_VERSION = "v0.1.5"

UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'mp4', 'webm'}

mysql = MySQL()
app = Flask(__name__, static_url_path='')
csrf = CSRFProtect(app)

app.jinja_env.globals.update(VIDZY_VERSION=VIDZY_VERSION)

app.config.from_pyfile('settings.py', silent=False)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['WTF_CSRF_CHECK_DEFAULT'] = False

if app.config['MINIFY_HTML']:
    htmlmin = HTMLMIN(app, remove_comments=True)

mysql.init_app(app)

s3_enabled = app.config['S3_ENABLED']
print("S3 enabled:", s3_enabled)

@app.template_filter('get_gravatar')
def get_gravatar(email):
    return "https://www.gravatar.com/avatar/" + hashlib.md5(email.encode()).hexdigest() + "?d=mp"

@app.template_filter('get_comments')
def get_comments(vid):
    mycursor = mysql.connection.cursor()

    mycursor.execute("SELECT * FROM `comments` WHERE short_id = %s;", (vid,))
    myresult = mycursor.fetchall()

    return myresult

@app.template_filter('get_comment_count')
def get_comment_count(vid):
    cursor = mysql.connection.cursor()

    cursor.execute("SELECT count(*) comment_count FROM `comments` WHERE short_id = %s;", (vid,))
    comment_count = int(cursor.fetchall()[0]["comment_count"])

    return comment_count

@app.template_filter('get_user_info')
def get_user_info(userid):
    mycursor = mysql.connection.cursor()

    mycursor.execute("SELECT * FROM `users` WHERE id = %s;", (userid,))
    myresult = mycursor.fetchall()[0]

    return myresult

@app.template_filter('get_username')
def get_username(userid):
    return get_user_info(userid)["username"]

@app.route("/like_post")
def like_post_page():
    if "user" not in session:
        return "NotLoggedIn"

    mycursor = mysql.connection.cursor()

    mycursor.execute("SELECT * FROM likes WHERE short_id = %s AND user_id = %s;", (str(request.args.get("id")), str(session["user"]["id"])))

    myresult = mycursor.fetchall()

    for x in myresult:
        return "Already Liked"

    mycursor = mysql.connection.cursor()

    sql = "INSERT INTO `likes` (`short_id`, `user_id`) VALUES (%s, %s)"
    val = (request.args.get("id"), session["user"]["id"])
    mycursor.execute(sql, val)

    mysql.connection.commit()

    return "Success"

@app.route("/send_comment")
def send_comment_page():
    if "user" not in session:
        return "NotLoggedIn"

    shortid = request.args.get("shortid")

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT count(*) comment_count FROM `comments` WHERE short_id = %s AND user_id = %s;", (shortid, session["user"]["id"]))
    comment_count = int(cursor.fetchall()[0]["comment_count"])

    if comment_count >= 40:
        return "TooManyComments"

    mycursor = mysql.connection.cursor()

    sql = "INSERT INTO `comments` (`short_id`, `user_id`, `comment_text`) VALUES (%s, %s, %s)"
    val = (request.args.get("shortid"), session["user"]["id"], request.args.get("txt"))
    mycursor.execute(sql, val)

    mysql.connection.commit()

    return "Success"

@app.route("/if_liked_post")
def liked_post_page():
    if "user" not in session:
        return "NotLoggedIn"

    mycursor = mysql.connection.cursor()

    mycursor.execute("SELECT * FROM likes WHERE short_id = %s AND user_id = %s;", (str(request.args.get("id")), str(session["user"]["id"])))

    myresult = mycursor.fetchall()

    for x in myresult:
        return "true"

    return "false"


@app.route("/")
def index_page():
    logged_in = "username" in session

    cur = mysql.connection.cursor()
    if logged_in:
        cur.execute(
            "SELECT p.id, title, url, user_id, date_uploaded, MIN(f.id) followid, MIN(follower_id) follower_id, following_id, (SELECT count(*) FROM `likes` WHERE short_id = p.id) likes, (SELECT username FROM `users` WHERE id = p.user_id) username FROM shorts p INNER JOIN follows f ON (f.following_id = p.user_id) WHERE f.follower_id = %s OR p.user_id = %s GROUP BY p.id ORDER BY p.id DESC LIMIT 20;",
            (str(session["user"]["id"]), str(session["user"]["id"]),)
        )

        rv = cur.fetchall()

        instances = json.loads(requests.get("https://raw.githubusercontent.com/vidzy-social/vidzy-social.github.io/main/instancelist.json").text)

        for i in instances:
            if requests.get("https://vo.group.lt/api/vidzy").text != "vidzy":
                print("Skipped instance: " + i)
            else:
                r = json.loads(requests.get(i + "/api/live_feed?startat=0").text)
                for c in r:
                    c["url"] = i + "/static/uploads/" + c["url"]
                    rv = rv + (c,)

        rv = sorted(rv, key=itemgetter('id'), reverse=True)

        return render_template('index.html', shorts=rv, session=session, logged_in = logged_in)
    return explore_page()

@app.route("/settings", methods=['POST', 'GET'])
def settings_page():
    if "username" in request.form:
        cursor = mysql.connection.cursor()
        cursor.execute("UPDATE `users` SET `username` = %s WHERE (`id` = %s);", (request.form["username"], session["user"]["id"]))
        mysql.connection.commit()

        cursor.execute("UPDATE `users` SET `email` = %s WHERE (`id` = %s);", (request.form["email"], session["user"]["id"]))
        mysql.connection.commit()

        session.clear()

        return redirect("login")

    return render_template('settings.html', username=session["user"]["username"], email=session["user"]["email"])

########################################################################
########################### ADMIN STUFF ################################

@app.route("/admin")
def admin_panel():
    if "user" not in session:
        return "<script>window.location.href='/login';</script>"

    if not session["user"]["is_admin"] == 1:
        return "<script>window.location.href='/';</script>"

    cur = mysql.connection.cursor()
    cur.execute("SELECT count(*) total_accounts FROM `users`;")
    total_accounts = cur.fetchall()[0]["total_accounts"]

    cur.execute("SELECT count(*) total_shorts FROM `shorts`;")
    total_shorts = cur.fetchall()[0]["total_shorts"]

    cur.execute("SELECT *, (SELECT count(*) FROM `follows` WHERE following_id = u.id) followers FROM `users` u ORDER BY id DESC LIMIT 50;")
    accounts = cur.fetchall()

    cur.execute("SELECT *, (SELECT count(*) FROM `likes` WHERE short_id = p.id) like_count FROM `shorts` p ORDER BY id DESC LIMIT 50;")
    shorts = cur.fetchall()

    videos_on_date_uploaded = {}

    for short in shorts:
        if not short["date_uploaded"] in videos_on_date_uploaded:
            videos_on_date_uploaded[short["date_uploaded"]] = []

        videos_on_date_uploaded[short["date_uploaded"]].append(short)

    print(videos_on_date_uploaded)

    return render_template('admin_panel.html', session=session, total_accounts=total_accounts, accounts=accounts, shorts=shorts, total_shorts=total_shorts, videos_on_date_uploaded=videos_on_date_uploaded)

@app.route("/admin/banform")
def ban_form():
    if "user" not in session:
        return "You are not logged in"
    if not session["user"]["is_admin"] == 1:
        return "You are not an admin"

    userid = request.args.get('user')

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM `users` WHERE (`id` = %s);", (userid,))
    user = cursor.fetchall()[0]

    if len(user) == 0:
        return "User doesn't exist."

    if user["is_admin"] == 1:
        return "User is an admin. Admins are not bannable through the admin panel."

    return render_template("banform.html", user=user, userid=userid)

@app.route("/admin/ban", methods=['POST'])
def ban_user():
    csrf.protect()

    if "user" not in session:
        return "NotLoggedIn"
    if not session["user"]["is_admin"] == 1:
        return "NotAdmin"

    user = request.form['user']

    cursor = mysql.connection.cursor()
    cursor.execute("DELETE FROM `users` WHERE (`id` = %s);", (user,))
    mysql.connection.commit()

    return redirect("/admin", code=302)

@app.route("/admin/deletevidform")
def delete_vid_form():
    if "user" not in session:
        return "You are not logged in"
    if not session["user"]["is_admin"] == 1:
        return "You are not an admin"

    shortid = request.args.get('short')

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM `shorts` WHERE (`id` = %s);", (shortid,))
    short = cursor.fetchall()[0]

    if len(short) == 0:
        return "Short doesn't exist."

    return render_template("deletevidform.html", short=short, shortid=shortid)

@app.route("/admin/deletevid", methods=['POST'])
def delete_vid():
    csrf.protect()

    if "user" not in session:
        return "NotLoggedIn"
    if not session["user"]["is_admin"] == 1:
        return "NotAdmin"

    short = request.form['short']

    cursor = mysql.connection.cursor()
    cursor.execute("DELETE FROM `shorts` WHERE (`id` = %s);", (short,))
    mysql.connection.commit()

    return redirect("/admin", code=302)

@app.route("/admin/promoteform")
def promote_form():
    if "user" not in session:
        return "You are not logged in"
    if not session["user"]["is_admin"] == 1:
        return "You are not an admin"

    userid = request.args.get('user')

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM `users` WHERE (`id` = %s);", (userid,))
    user = cursor.fetchall()[0]

    if len(user) == 0:
        return "User doesn't exist."

    if user["is_admin"] == 1:
        return "User is already an admin."

    return render_template("promoteform.html", user=user, userid=userid)

@app.route("/admin/promote", methods=['POST'])
def promote_user():
    csrf.protect()

    if "user" not in session:
        return "NotLoggedIn"
    if not session["user"]["is_admin"] == 1:
        return "NotAdmin"

    user = request.form['user']

    cursor = mysql.connection.cursor()
    cursor.execute("UPDATE `users` SET `is_admin` = '1' WHERE (`id` = %s);", (user,))
    mysql.connection.commit()

    return redirect("/admin", code=302)

######################### END ADMIN STUFF ##############################
########################################################################

@app.route("/search")
def search_page():
    if "username" not in session:
        return "<script>window.location.href='/login';</script>"

    query = request.args.get('q')

    cur = mysql.connection.cursor()
    cur.execute("SELECT *, (SELECT count(*) FROM `likes` WHERE short_id = p.id) likes FROM shorts p INNER JOIN follows f ON (f.following_id = p.user_id) WHERE title LIKE %s ORDER BY f.follower_id = %s, p.user_id = %s LIMIT 20;", ("%" + query + "%", str(session["user"]["id"]), str(session["user"]["id"])))
    rv = cur.fetchall()

    return render_template('search.html', shorts=rv, session=session, query=query, logged_in = "username" in session)

@app.route("/explore")
def explore_page():
    logged_in = "username" in session

    cur = mysql.connection.cursor()
    cur.execute(
        "SELECT *, (SELECT count(*) FROM `likes` p WHERE p.short_id = shorts.id) likes FROM shorts ORDER BY likes DESC LIMIT 3;")
    rv = cur.fetchall()

    return render_template('explore.html', shorts=rv, session=session, logged_in = logged_in , page="explore")

@app.route("/livefeed")
def livefeed_page():
    logged_in = "username" in session

    cur = mysql.connection.cursor()
    cur.execute(
        "SELECT *, (SELECT count(*) FROM `likes` p WHERE p.short_id = shorts.id) likes FROM shorts ORDER BY id DESC LIMIT 3;")
    rv = cur.fetchall()

    return render_template('explore.html', shorts=rv, session=session, logged_in = logged_in, page="livefeed")

@app.route("/users/<user>")
def profile_page(user):
    if "@" in user:
        if user.split("@")[1] != str(urlparse(request.base_url).netloc):
            return remote_profile_page(user)
        else:
            return remote_profile_page(user) # TEMPORARY FOR TESTING
            user = user.split("@")[0]

    cur = mysql.connection.cursor()

    cur.execute("SELECT * FROM users WHERE username=%s;", (user, ))
    user = cur.fetchall()[0]

    cur.execute("SELECT * FROM shorts WHERE user_id=%s;", (str(user["id"]), ))
    latest_short_list = cur.fetchall()

    if "user" in session:
        cur.execute("SELECT * FROM follows WHERE follower_id=%s AND following_id=%s;", (str(session["user"]["id"]), str(user["id"])))
        following = False
        for i in cur.fetchall():
            following = True
    else:
        following = False

    return render_template('profile.html', user=user, session=session, latest_short_list=latest_short_list, following=following)

def remote_vidzy_profile_page(user):
    print("http://" + user.split("@")[1] + "/api/users/" + user.split("@")[0])
    r = requests.get("http://" + user.split("@")[1] + "/api/users/" + user.split("@")[0]).text
    data = json.loads(r)
    if not "followers" in data:
        data["followers"] = 0
    return render_template("remote_user.html", shorts=data["videos"], followers_count=data["followers"], user_info=data, full_username=user, logged_in = "username" in session)

@app.route("/remote_user/<user>")
def remote_profile_page(user):
    if requests.get("http://" + user.split("@")[1] + "/api/vidzy").text == "vidzy":
        print("Vidzy instance detected")
        return remote_vidzy_profile_page(user)

    variant = ""

    try:
        outbox = json.loads(requests.get("https://" + user.split("@")[1] + "/users/" + user.split("@")[0] + "/outbox?page=true").text)
        variant = "mastodon"
    except json.decoder.JSONDecodeError:
        outbox = json.loads(requests.get("https://" + user.split("@")[1] + "/accounts/" + user.split("@")[0] + "/outbox?page=1", headers={"Accept":"application/activity+json"}).text)
        variant = "peertube"

    shorts = []

    for post in outbox["orderedItems"]:
        if type(post["object"]) is dict:
            if variant == "peertube":
                for i in post["object"]["url"][1]["tag"]:
                    if "mediaType" in i:
                        if i["mediaType"] == "video/mp4":
                            shorts.append( {"id": 1, "url": i["href"], "username": user, "title": "test"} )
                            break
            else:
                if len(post["object"]["attachment"]) > 0:
                    if post["object"]["attachment"][0]["mediaType"].startswith("video"):
                        shorts.append( { "id": 1, "url": post["object"]["attachment"][0]["url"], "username": user, "title": cleanhtml(post["object"]["content"]) } )

    if variant == "mastodon":
        followers_count = json.loads(
            requests.get("https://" + user.split("@")[1] + "/users/" + user.split("@")[0] + "/followers", headers={"Accept":"application/activity+json"}, timeout=20).text
        )["totalItems"]
    else:
        followers_count = 0

    if variant == "mastodon":
        user_info = json.loads(
            requests.get("https://" + user.split("@")[1] + "/users/" + user.split("@")[0], headers={"Accept":"application/activity+json"}, timeout=20).text
        )
    else:
        user_info = {}

    return render_template("remote_user.html", shorts=shorts, followers_count=followers_count, user_info=user_info, full_username=user, logged_in = "username" in session)


@app.route("/hcard/users/<guid>")
def hcard_page(guid):
    user = bytes.fromhex(guid).decode('utf-8')

    cur = mysql.connection.cursor()

    cur.execute("SELECT * FROM users WHERE username=%s;", (user, ))
    user = cur.fetchall()[0]

    cur.execute("SELECT * FROM shorts WHERE user_id=%s;", (str(user["id"]), ))
    latest_short_list = cur.fetchall()

    return render_template('profile_hcard.html', user=user, session=session, latest_short_list=latest_short_list, guid=guid)


@app.route("/users/<user>/feed")
def profile_feed_page(user):
    cur = mysql.connection.cursor()

    cur.execute("SELECT * FROM users WHERE username=%s;", (user, ))
    user = cur.fetchall()[0]

    cur.execute("SELECT * FROM shorts WHERE user_id=%s;", (str(user["id"]), ))
    latest_short_list = cur.fetchall()

    resp = make_response(render_template(
        'profile_feed.xml', user=user, session=session, latest_short_list=latest_short_list))
    resp.headers['Content-type'] = 'text/xml; charset=utf-8'
    return resp


@app.route("/shorts/<short>")
def short_page(short):
    if "username" not in session:
        return "<script>window.location.href='/login';</script>"

    cur = mysql.connection.cursor()
    cur.execute("SELECT *, (SELECT count(*) FROM `likes` WHERE short_id = p.id) likes FROM shorts p WHERE id = %s;", (short,))
    rv = cur.fetchall()[0]

    return render_template('short.html', short=rv, session=session, logged_in = "username" in session)


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

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('id', None)
    session.pop('user', None)
    return app.make_response(redirect(url_for("login_page")))

@app.route('/register', methods =['GET', 'POST'])
def register():
    if "username" in session:
        return "<script>window.location.href='/';</script>"

    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        cursor = mysql.connection.cursor()
        cursor.execute('SELECT * FROM users WHERE username = %s', (username, ))
        account = cursor.fetchone()
        if account:
            msg = 'Account already exists!'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address!'
        elif not re.match(r'[A-Za-z0-9]+', username):
            msg = 'Username must contain only characters and numbers!'
        elif not username or not password or not email:
            msg = 'Please fill out the form!'
        else:
            cursor.execute('INSERT INTO users (`username`, `password`, `email`) VALUES (%s, %s, %s)', (username, hashlib.sha256(password.encode()).hexdigest(), email, ))
            mysql.connection.commit()
            msg = 'You have successfully registered! <a href="/login">Click here to login</a>'
    elif request.method == 'POST':
        msg = 'Please fill out the form!'
    return render_template('register.html', msg = msg)


@app.route('/users/<username>/inbox', methods=['POST'])
def user_inbox(username):
    if username != "testuser":
        abort(404)

    app.logger.info(request.headers)
    app.logger.info(request.data)

    return Response("", status=202)

@app.route('/.well-known/webfinger')
def webfinger():
    instance_url = str(urlparse(request.base_url).scheme) + "://" + str(urlparse(request.base_url).netloc)

    resource = request.args.get('resource')

    if resource != "acct:testuser@" + str(urlparse(request.base_url).netloc):
        abort(404)

    response = make_response({
        "subject": "acct:testuser@" + str(urlparse(request.base_url).netloc),
        "links": [
            {
                "rel": "self",
                "type": "application/activity+json",
                "href": instance_url + "/users/testuser"
            }
        ]
    })

    # Servers may discard the result if you do not set the appropriate content type
    response.headers['Content-Type'] = 'application/jrd+json'

    return response
'''
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
'''

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

####################################
############ API ROUTES ############

@app.route('/api/v1/instance')
def instance_info():
    info = {
        "uri": str(urlparse(request.base_url).scheme) + "://" + str(urlparse(request.base_url).netloc),
        "title": "Vidzy",
        "short_description": "The testing server operated by Vidzy",
        "description": "",
        "version": VIDZY_VERSION
    }

    resp = Response(json.dumps(info))
    resp.headers['Content-Type'] = 'application/json'
    return resp

@app.route("/api/search")
def api_search_page():
    query = request.args.get('q')

    cur = mysql.connection.cursor()
    cur.execute("SELECT p.id, p.title, p.user_id, p.url, p.description, p.date_uploaded, (SELECT count(*) FROM `likes` WHERE short_id = p.id) likes FROM shorts p INNER JOIN follows f ON (f.following_id = p.user_id) WHERE title LIKE %s LIMIT 20;", ("%" + query + "%", ))
    rv = cur.fetchall()

    for row in rv:
        row["url"] = str(urlparse(request.base_url).scheme) + "://" + str(urlparse(request.base_url).netloc) + "/static/uploads/" + row["url"]

    return jsonify(rv)

@app.route("/api/users/<user>")
def api_user_page(user):
    cur = mysql.connection.cursor()
    cur.execute("SELECT id, username, bio, (SELECT count(*) FROM `follows` WHERE following_id = u.id) followers FROM `users` u WHERE (`username` = %s);", (user,))
    rv = cur.fetchall()[0]

    cur.execute(
        "SELECT p.id, p.title, p.user_id, p.url, p.description, p.date_uploaded, (SELECT count(*) FROM `likes` WHERE short_id = p.id) likes FROM shorts p WHERE user_id=%s;",
        (rv["id"],)
    )
    shorts = cur.fetchall()

    for row in shorts:
        row["url"] = str(urlparse(request.base_url).scheme) + "://" + str(urlparse(request.base_url).netloc) + "/static/uploads/" + row["url"]

    rv["videos"] = shorts

    return jsonify(rv)

@app.route("/api/vidzy")
def api_vidzy_page():
    return "vidzy"

@app.route("/api/live_feed")
def api_livefeed_page():
    start_at = int(request.args.get('startat'))

    logged_in = "username" in session

    cur = mysql.connection.cursor()
    cur.execute(
        "SELECT date_uploaded, description, id, title, url, user_id, (SELECT count(*) FROM `likes` p WHERE p.short_id = shorts.id) likes FROM shorts ORDER BY id DESC LIMIT %s OFFSET %s;", (start_at+2,start_at))
    rv = cur.fetchall()

    nh3_tags = set() # Empty set

    for r in rv:
        r["title"] = nh3.clean(r["title"], tags=nh3_tags)
        if "description" in r:
            if r["description"] is not None:
                r["description"] = nh3.clean(r["description"], tags=nh3_tags)
        r["url"] = nh3.clean(r["url"], tags=nh3_tags)

    return jsonify(rv)

@app.route("/api/explore")
def api_explore_page():
    start_at = int(request.args.get('startat'))

    logged_in = "username" in session

    cur = mysql.connection.cursor()
    cur.execute(
        "SELECT id, title, url, user_id, date_uploaded, description, tags, (SELECT count(*) FROM `likes` p WHERE p.short_id = shorts.id) likes FROM shorts ORDER BY likes DESC LIMIT %s OFFSET %s;", (start_at+2,start_at))
    rv = cur.fetchall()

    nh3_tags = set() # Empty set

    for r in rv:
        r["title"] = nh3.clean(r["title"], tags=nh3_tags)
        if "description" in r:
            if r["description"] is not None:
                r["description"] = nh3.clean(r["description"], tags=nh3_tags)
        if "tags" in r:
            if r["tags"] is not None:
                r["tags"] = nh3.clean(r["tags"], tags=nh3_tags)
                r["tags"] = r["tags"].split(",")
        r["url"] = nh3.clean(r["url"], tags=nh3_tags)

    return jsonify(rv)

############ API ROUTES ############
####################################

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if not "username" in session:
        return "<script>window.location.href='/login';</script>"

    if "ALLOW_UPLOADS" in vidzyconfig.config:
        if vidzyconfig.config["ALLOW_UPLOADS"] is False:
            return "This instance does not allow uploading videos"

    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = datetime.today().strftime('%Y%m%d') + secure_filename(file.filename)
            if s3_enabled is True:
                new_filename = uuid.uuid4().hex + '.' + file.filename.rsplit('.', 1)[1].lower()

                bucket_name = app.config['S3_BUCKET_NAME']
                s3 = boto3.resource("s3")
                s3.Bucket(bucket_name).upload_fileobj(file, new_filename)

                s3_fileurl = app.config['AWS_ENDPOINT_URL'] + "/" + app.config['S3_BUCKET_NAME'] + "/" + new_filename

                cur = mysql.connection.cursor()

                cur.execute( """INSERT INTO shorts (title, url, user_id, date_uploaded) VALUES (%s,%s,%s,%s)""", (request.form.get("title"), s3_fileurl, str(session["user"]["id"]), datetime.now().strftime('%Y-%m-%d')) )
                mysql.connection.commit()
            else:
                if vidzyconfig.config["use_absolute_upload_path"]:
                    project_folder = vidzyconfig.config["vidzy_absolute_path"]
                    file.save(os.path.join(project_folder + '/' + app.config['UPLOAD_FOLDER'], filename))
                else:
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

                cur = mysql.connection.cursor()

                cur.execute( """INSERT INTO shorts (title, url, user_id, date_uploaded) VALUES (%s,%s,%s,%s)""", (request.form.get("title"), filename, str(session["user"]["id"]), datetime.now().strftime('%Y-%m-%d')) )
                mysql.connection.commit()

            return redirect(url_for('index_page'))
    return '''
    <!doctype html>
    <title>Upload a new video</title>
    <h1>Upload a new video</h1>
    <form method=post enctype=multipart/form-data>
      Video title: <input type=text name=title>
      <br><br>
      <input type=file name=file>
      <br><br>
      <input type=submit value=Upload>
    </form>
    '''

@app.route('/follow')
def follow():
    following_id = str(request.args.get("id"))


    cur = mysql.connection.cursor()


    cur.execute("SELECT * FROM follows WHERE following_id = %s AND follower_id = %s;", (following_id, str(session["user"]["id"])))

    myresult = cur.fetchall()

    for x in myresult:
        return "Already following"


    cur.execute("""INSERT INTO follows (follower_id, following_id) VALUES (%s,%s)""", (str(session["user"]["id"]), following_id))
    mysql.connection.commit()

    return "Done"

@app.route('/unfollow')
def unfollow():
    following_id = str(request.args.get("id"))


    cur = mysql.connection.cursor()


    cur.execute("SELECT * FROM follows WHERE following_id = %s AND follower_id = %s;", (following_id, str(session["user"]["id"])))

    myresult = cur.fetchall()

    following = False
    for x in myresult:
        following = True

    if not following:
        return "Not currently following user"

    cur.execute("""DELETE FROM `follows` WHERE `follower_id` = %s AND `following_id` = %s;""", (str(session["user"]["id"]), following_id))
    mysql.connection.commit()

    return "Done"

def round_to_multiple(number, multiple):
    return multiple * round(number / multiple)

def floor_to_multiple(number, multiple):
    return multiple * math.ceil(number / multiple)

@app.route("/about")
def about():
    cur = mysql.connection.cursor()
    cur.execute("SELECT count(*) total_accounts FROM `users`;")
    total_accounts = floor_to_multiple(cur.fetchall()[0]["total_accounts"], 5)

    return render_template('about.html', instance_domain=urlparse(request.base_url).hostname, total_accounts=total_accounts)

def create_app():
    return app

if __name__ == "__main__":
    app.run(host=app.config["HOST"], debug=True)
