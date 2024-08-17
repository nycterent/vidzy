from flask import *
from flask_mysqldb import MySQL
from flask_htmlmin import HTMLMIN

import hashlib
import requests
import json
from urllib.parse import quote, unquote, urlparse
import re
import os
from werkzeug.utils import secure_filename
from datetime import datetime




from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend

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




vidzy_version = "v0.1.0"

UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'mp4', 'webm'}

mysql = MySQL()
app = Flask(__name__, static_url_path='')

app.jinja_env.globals.update(vidzy_version=vidzy_version)

app.config.from_pyfile('settings.py', silent=False)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

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
    cur.execute("SELECT *, (SELECT count(*) FROM `likes` WHERE short_id = p.id) likes, (SELECT username FROM `users` WHERE id = p.user_id) username FROM shorts p INNER JOIN follows f ON (f.following_id = p.user_id) WHERE f.follower_id = %s OR p.user_id = %s ORDER BY p.id DESC LIMIT 20;", (str(session["user"]["id"]), str(session["user"]["id"]), ))
    rv = cur.fetchall()

    return render_template('index.html', shorts=rv, session=session)

@app.route("/settings", methods=['POST', 'GET'])
def settings_page():
    if "username" in request.form:
        cursor = mysql.connection.cursor()
        cursor.execute("UPDATE `vidzy`.`users` SET `username` = %s WHERE (`id` = %s);", (request.form["username"], session["user"]["id"]))
        mysql.connection.commit()

        cursor.execute("UPDATE `vidzy`.`users` SET `email` = %s WHERE (`id` = %s);", (request.form["email"], session["user"]["id"]))
        mysql.connection.commit()

        session.clear()

        return redirect("login")

    return render_template('settings.html', username=session["user"]["username"], email=session["user"]["email"])

@app.route("/search")
def search_page():
    if not "username" in session:
        return "<script>window.location.href='/login';</script>"

    query = request.args.get('q')

    cur = mysql.connection.cursor()
    cur.execute("SELECT *, (SELECT count(*) FROM `likes` WHERE short_id = p.id) likes FROM shorts p INNER JOIN follows f ON (f.following_id = p.user_id) WHERE title LIKE %s ORDER BY f.follower_id = %s, p.user_id = %s LIMIT 20;", ("%" + query + "%", str(session["user"]["id"]), str(session["user"]["id"])))
    rv = cur.fetchall()

    return render_template('search.html', shorts=rv, session=session, query=query)

@app.route("/api/search")
def api_search_page():
    query = request.args.get('q')

    cur = mysql.connection.cursor()
    cur.execute("SELECT p.id, p.title, p.user_id, (SELECT count(*) FROM `likes` WHERE short_id = p.id) likes FROM shorts p INNER JOIN follows f ON (f.following_id = p.user_id) WHERE title LIKE %s LIMIT 20;", ("%" + query + "%", ))
    rv = cur.fetchall()

    return jsonify(rv)

@app.route("/explore")
def explore_page():
    if not "username" in session:
        return "<script>window.location.href='/login';</script>"

    cur = mysql.connection.cursor()
    cur.execute(
        "SELECT *, (SELECT count(*) FROM `likes` p WHERE short_id = p.id) likes FROM shorts ORDER BY id DESC LIMIT 20;")
    rv = cur.fetchall()

    return render_template('explore.html', shorts=rv, session=session)

@app.route("/users/<user>")
def profile_page(user):
    instance_url = str(urlparse(request.base_url).scheme) + "://" + str(urlparse(request.base_url).netloc)

    if username != "zampano":
        abort(404)

    public_key = b'' # retrieve from file/database

    response = make_response({
        "@context": [
            "https://www.w3.org/ns/activitystreams",
            "https://w3id.org/security/v1",
        ],
        "id": instance_url + "/users/zampano",
        "inbox": instance_url + "/users/zampano/inbox",
        "outbox": instance_url + "/users/zampano/outbox",
        "type": "Person",
        "name": "Zampano",
        "preferredUsername": "zampano",
        "publicKey": {
            "id": instance_url + "/users/zampano#main-key",
            "id": instance_url + "/users/zampano",
            "publicKeyPem": public_key
        }
    })

    # Servers may discard the result if you do not set the appropriate content type
    response.headers['Content-Type'] = 'application/activity+json'

    return response

    ########################################################################################

    if not "username" in session:
        return "<script>window.location.href='/login';</script>"

    cur = mysql.connection.cursor()

    cur.execute("SELECT * FROM users WHERE username=%s;", (user, ))
    user = cur.fetchall()[0]

    cur.execute("SELECT * FROM shorts WHERE user_id=%s;", (str(user["id"]), ))
    latest_short_list = cur.fetchall()

    cur.execute("SELECT * FROM follows WHERE follower_id=%s AND following_id=%s;", (str(session["user"]["id"]), str(user["id"])))
    following = False
    for i in cur.fetchall():
        following = True

    return render_template('profile.html', user=user, session=session, latest_short_list=latest_short_list, following=following)

@app.route("/remote_user/<user>")
def remote_profile_page(user):
    varient = ""

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
                        shorts.append( {"id": 1, "url": post["object"]["attachment"][0]["url"], "username": user, "title": post["object"]["content"]} )

    if variant == "mastodon":
        followers_count = json.loads(requests.get("https://" + user.split("@")[1] + "/users/" + user.split("@")[0] + "/followers", headers={"Accept":"application/activity+json"}).text)["totalItems"]
    else:
        followers_count = 0

    if variant == "mastodon":
        user_info = json.loads(requests.get("https://" + user.split("@")[1] + "/users/" + user.split("@")[0], headers={"Accept":"application/activity+json"}).text)
    else:
        user_info = {}

    return render_template("remote_user.html", shorts=shorts, followers_count=followers_count, user_info=user_info, full_username=user)
    

@app.route("/hcard/users/<guid>")
def hcard_page(guid):
    user = bytes.fromhex(guid).decode('utf-8')

    cur = mysql.connection.cursor()

    cur.execute("SELECT * FROM users WHERE username=%s;", (user, ))
    user = cur.fetchall()[0]

    cur.execute("SELECT * FROM shorts WHERE user_id=%s;", (str(user["id"]), ))
    latest_short_list = cur.fetchall()

    return render_template('profile_hcard.html', user=user, session=session, latest_short_list=latest_short_list, guid=guid)


@app.route("/mastodon_external/users/<user>")
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


@app.route('/users/<username>/inbox', methods=['POST'])
def user_inbox(username):
    if username != "zampano":
        abort(404)

    app.logger.info(request.headers)
    app.logger.info(request.data)
    
    return Response("", status=202)

@app.route('/.well-known/webfinger')
def webfinger():
    instance_url = str(urlparse(request.base_url).scheme) + "://" + str(urlparse(request.base_url).netloc)

    resource = request.args.get('resource')

    if resource != "acct:zampano@" + str(urlparse(request.base_url).netloc):
        abort(404)

    response = make_response({
        "subject": "acct:zampano@" + str(urlparse(request.base_url).netloc),
        "links": [
            {
                "rel": "self",
                "type": "application/activity+json",
                "href": instance_url + "/users/zampano"
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

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if not "username" in session:
        return "<script>window.location.href='/login';</script>"

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
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            cur = mysql.connection.cursor()

            cur.execute("""INSERT INTO shorts (title, url, user_id) VALUES (%s,%s,%s)""", (request.form.get("title"), filename, str(session["user"]["id"])))
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


    cur.execute("SELECT * FROM follows WHERE following_id = " +
                     following_id + " AND follower_id = " + str(session["user"]["id"]))

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


    cur.execute("SELECT * FROM follows WHERE following_id = " +
                     following_id + " AND follower_id = " + str(session["user"]["id"]))

    myresult = cur.fetchall()

    following = False
    for x in myresult:
        following = True
    
    if following == False:
        return "Not currently following user"

    cur.execute("""DELETE FROM `vidzy`.`follows` WHERE `follower_id` = %s AND `following_id` = %s;""", (str(session["user"]["id"]), following_id))
    mysql.connection.commit()

    return "Done"

@app.route("/about")
def about():
    return render_template('about.html', instance_domain=urlparse(request.base_url).hostname)

def create_app():
    return app

if __name__ == "__main__":
    app.run(host=app.config["HOST"], debug=True)
