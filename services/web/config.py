import os
import redis

SECRET_KEY = os.environ.get("SECRET_KEY")

if not SECRET_KEY:
    raise ValueError("No SECRET_KEY set.")

SERVER_NAME = os.environ.get("SERVER_NAME")
SAML_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "saml")

SESSION_TYPE = "redis"
SESSION_REDIS = redis.Redis(
    host=os.environ.get("REDIS_HOST", "redis"),
    username=os.environ.get("REDIS_USERNAME"),
    password=os.environ.get("REDIS_PASSWORD"),
)
PERMANENT_SESSION_LIFETIME = 60 * 60 * 4
SESSION_COOKIE_SECURE = True
