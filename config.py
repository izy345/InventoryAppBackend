#from dotenv import load_dotenv
import os
#from redis import StrictRedis
import redis
import random
import string
import flask_session
from dotenv import load_dotenv
load_dotenv()



class ApplicationConfig:
    
    def generate_secret_key(length=32):
        characters = string.ascii_letters + string.digits + string.punctuation
        secret_key = ''.join(random.choice(characters) for _ in range(length))
        return secret_key
    
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ECHO = False
    FLASK_ENV = 'production'
    PROPAGATE_EXCEPTIONS = False
    # session stuff
    #secret key can be:
    """diewjoiewjdioejf0923f02f8028809283098309128dodk1"""
    SECRET_KEY = generate_secret_key()
    #SECRET_KEY = generate_secret_key()
    #SECRET_KEY = os.environ["SECRET_KEY"]
    #FLASK_ENV = 'production'
    #SESSION_TYPE = "redis" #redis
    SESSION_TYPE = "redis" #redis
    SESSION_PERMANENT = False
    SESSION_USE_SIGNER = True
    SESSION_KEY_PREFIX = 'InventoryApp:'
    # For localhost
    #SESSION_REDIS = redis.from_url("redis://mwridpawrtvjwi38@master.example.w1vcqy.use1.cache.amazonaws.com:6379")
    #SESSION_REDIS = redis.from_url("redis://127.0.0.1:6379")
    # for production side
    ELASTICACHE_ENDPOINT = os.getenv("ELASTICACHE_ENDPOINT")
    SESSION_REDIS = redis.StrictRedis(host=ELASTICACHE_ENDPOINT,decode_responses=False,port=6379,ssl=True, db=0,password='mwridpawrtvjwi38')
    #redis = Redis(host='primary.xxx.yyyyyy.zzz1.cache.amazonaws.com', port=6379, decode_responses=True, ssl=True, username=example, password=EXAMPLE)
    
    #this is the one that works with AWS Elasti Cache
    #SESSION_REDIS = redis.StrictRedis(host='localhost', port=6379, db=0)
    # running the redis server on macOS 
    #redis-stack-server
    #can also be
    #SESSION_TYPE = "filesystem"  # Use local filesystem for session storage
    #SESSION_PERMANENT = False
    #SESSION_USE_SIGNER = True
    
    #can also place here postgres config
ELASTICACHE_ENDPOINT = os.getenv("ELASTICACHE_ENDPOINT")
ELASTICACHE_PASSWORD = os.getenv("ELASTICACHE_PASSWORD")
redis_cache = redis.StrictRedis(host=ELASTICACHE_ENDPOINT,decode_responses=False,port=6379,ssl=True, db=0,password=ELASTICACHE_PASSWORD)