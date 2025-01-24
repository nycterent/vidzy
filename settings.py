import os
from dotenv import load_dotenv

# BELOW CODE IS FOR PRODUCTION ONLY
# project_folder = os.path.expanduser('~/mysite')  # adjust as appropriate
# load_dotenv(os.path.join(project_folder, '.env'))
# ABOVE CODE IS FOR PRODUCTION ONLY

load_dotenv('.env')

MYSQL_USER = os.environ.get("VIDZY_DB_USER")
MYSQL_PASSWORD = os.environ.get("VIDZY_DB_PASS")
MYSQL_DB = os.environ.get("VIDZY_DATABASE")
MYSQL_HOST = os.environ.get("VIDZY_DB_HOST")
MYSQL_PORT = int(os.environ.get("VIDZY_DB_PORT"))
MYSQL_CURSORCLASS = "DictCursor"

SECRET_KEY = os.environ.get("VIDZY_APP_SECRET")

MINIFY_HTML = os.environ.get("MINIFY_HTML") == "True"
HOST = os.environ.get("HOST")

ALLOW_UPLOADS = os.environ.get("ALLOW_UPLOADS")

S3_ENABLED = os.environ.get("S3_ENABLED") == "True"
AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
S3_BUCKET_NAME = os.environ.get("S3_BUCKET_NAME")
AWS_ENDPOINT_URL = os.environ.get("AWS_ENDPOINT_URL")
S3_PUBLIC_URL = os.environ.get("S3_PUBLIC_URL")

SENTRY_DSN = os.environ.get("SENTRY_DSN")
SENTRY_ENABLED = os.environ.get("SENTRY_ENABLED") == "True"
