import os
from dotenv import load_dotenv

# BELOW CODE IS FOR PRODUCTION ONLY
#project_folder = os.path.expanduser('~/mysite')  # adjust as appropriate
#load_dotenv(os.path.join(project_folder, '.env'))
# ABOVE CODE IS FOR PRODUCTION ONLY

load_dotenv('.env')

MYSQL_USER = os.environ.get("VIDZY_DB_USER")
MYSQL_PASSWORD = os.environ.get("VIDZY_DB_PASS")
MYSQL_DB = os.environ.get("VIDZY_DATABASE")
MYSQL_HOST = os.environ.get("VIDZY_DB_HOST")
MYSQL_PORT = int(os.environ.get("VIDZY_DB_PORT"))
MYSQL_CURSORCLASS = "DictCursor"

SECRET_KEY = os.environ.get("VIDZY_APP_SECRET")

MINIFY_HTML = os.environ.get("MINIFY_HTML")
HOST = os.environ.get("HOST")
