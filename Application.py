#ENV test V1.0.0
# urllib3<2.0
import os
from dotenv import load_dotenv
# usual flask stuff
# if deploying to elastic beanstalk, make sure psyopg-binary is the one you are using
from flask import Flask, jsonify, request, send_file, Response, abort, session #dont enable session on its own, do flask_session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import desc, asc, or_, func
from datetime import datetime, timedelta
from flask_marshmallow import Marshmallow # Easy jsonify 
from flask_cors import CORS,cross_origin
from flask_bcrypt import Bcrypt # hashing passwords 
from flask_caching import Cache
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import requests # installed  
import pytz # installed
# this is for live chat service 
from flask_socketio import SocketIO, emit, join_room, leave_room, disconnect, ConnectionRefusedError, Namespace
#server side sessions flask jwt extended can also be used? 
from flask_session import Session
# possibly better
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity, create_access_token, create_refresh_token, decode_token
import functools

from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
# import python apps from the server
from models import db,Accounts,Sections,Inventory,Reciept,Reciept_items, Divisions, Map, Reserve, Reserve_items
from config import ApplicationConfig, redis_cache
# encryption
from Cryptography import Cryptography
# 2FA
import pyotp
# images
from PIL import Image
from io import BytesIO
#scheduler
import time
# APScheduler
from apscheduler.schedulers.background import BackgroundScheduler

from flask_migrate import Migrate
# For search inquiries 
from nltk.stem import SnowballStemmer
from fuzzywuzzy import fuzz

load_dotenv()



application = Flask(__name__)
application.app_context().push()
application.config.from_object(ApplicationConfig) #not nessesary, can do app.config() instead 
#CORS(application, supports_credentials=True, resources = {r"/*":{"origins":"*"}})
CORS(application, supports_credentials=True, resources={r"/*": {"origins": ["https://hpinventory.com", "https://www.hpinventory.com"]}})
#CORS(application, supports_credentials=True, resources = {r"/*":{"origins":"*"}})
#CORS(app, resources = {r"/*":{"origins":"*"}})

# search
stemmer = SnowballStemmer("english")

#flask caching
cache = Cache(application, config={'CACHE_TYPE': 'simple'})
# time stuff
def get_ct():
    utc_now = datetime.utcnow()
    ct_timezone = pytz.timezone('US/Central')
    ct_now = utc_now.replace(tzinfo=pytz.utc).astimezone(ct_timezone) # variable to get timestamp
    return ct_now


#socketio = SocketIO(app, async_mode='eventlet')
DBLOCATION = os.getenv("DBLOCATION")
application.config['SQLALCHEMY_DATABASE_URI'] = DBLOCATION

# server_session = Session(app) # sessions
server_sessions = Session(application) # sessions
jwt = JWTManager(application)
#socketio = SocketIO(application,cors_allowed_origins="*", manage_session=False)
db.init_app(application) # imported db from models 
# migration
migrate = Migrate(application,db)

#run this commands in the root directory of the flask app. first command only once

# flask --app=application.py db init
# flask --app=application.py db migrate
# flask --app=application.py db upgrade

#redis-stack-server on terminal, python 3.8 application.py 

# flask limiter stuff
#limiter = Limiter(get_remote_address, app=application, default_limits=["12000 per day", "60 per hour"])


# bcrypt stuff
bcrypt = Bcrypt(application)

# DB stuff 

ma = Marshmallow(application)
# faux stone panels
# MACOS stuff
#python 3.8 -m venv venv
# pip install --upgrade pips

# Users
class AccountsSchema(ma.Schema):
    class Meta:
        fields = ("id","email","password","MultiFactor","time","permLvl")
singleAccountsSchema = AccountsSchema()
multiAccountsSchema = AccountsSchema(many=True)

class SectionsSchema(ma.Schema):
    class Meta:
        fields = ("id","division","section") #no image, call API to show
singleSectionsSchema = SectionsSchema()
multiSectionsSchema = SectionsSchema(many=True)

class InventorySchema(ma.Schema):
    class Meta:
        fields = ("id","name","amount","reserved","details","paint","map","section") # no image, call API to show
singleInventorySchema = InventorySchema()
multiInventorySchema = InventorySchema(many=True)

class DivisionSchema(ma.Schema):
    class Meta:
        fields = ("id","name")
singleDivisionSchema = DivisionSchema()
multiDivisionSchema = DivisionSchema(many=True)

class ReceiptItemsSchema(ma.Schema):
    class Meta:
        fields = ("id","reciept","inventory_id","section_id","change","original_change","name","updatedNumber","time")
singleReceiptItemsSchema = ReceiptItemsSchema()
multiReceiptItemsSchema = ReceiptItemsSchema(many=True)

class ReceiptSchema(ma.Schema):
    class Meta:
        fields = ("id","name","project","permLvl","condition","time")
singleReceiptSchema =  ReceiptSchema()
multiReceiptSchema = ReceiptSchema(many=True)

# Sections

# End of DB stuff
API_Check = "ej2f!nsj6N25f7beuA%k8e*m"

# Route limiting
default_rate_limit = 210
@application.before_request
def amount_request():
    ip_address = request.remote_addr
    def_rate_limit = default_rate_limit
    rate_limit = 100
    if 'key' in session and session['key'] == API_Check:
        limit = 0  # No rate limit for requests with the correct session key
        total_limit = 0
        def_rate_limit = float('inf')
        #cache.set(ip_address + request.path, 0, timeout=180)
        #cache.set(ip_address + 'total_requests', 0, timeout=180)
    elif request.path == '/hello':
        rate_limit = 10  # Rate limit for /route-1: 5 requests per minute
    elif request.path == '/request_account':
        rate_limit = 6   # Rate limit for /route-2: 1 requests per minute
    elif request.path == '/me':
        rate_limit = 92   # Rate limit for /route-2: 5 requests per minute
    elif request.path == '/login':
        rate_limit = 100
    elif request.path == '/':
        rate_limit = 80
    else:
        rate_limit = 50
    #limit = cache.get(ip_address)
    limit = int(redis_cache.get(ip_address + request.path) or 0)
    total_limit = int(redis_cache.get(ip_address + 'total_requests') or 0)
    
    if limit is None:
        limit = 0
    if total_limit is None:
        total_limit = 0
    if limit >= rate_limit or total_limit >= def_rate_limit:
        return jsonify(message="Too Many Request!"), 429
    #cache.set(ip_address, limit + 1, timeout=60)
    
    if 'key' in session and session['key'] == API_Check:
        redis_cache.set(ip_address + request.path, limit - 2, ex=260)
        redis_cache.set(ip_address + 'total_requests', total_limit - 2, ex=260)
    else:
        redis_cache.set(ip_address + request.path, limit + 1, ex=200)
        redis_cache.set(ip_address + 'total_requests', total_limit + 1, ex=200)
 
 # - - - Hello Test - - -
@application.route("/", methods = ["GET"])
#@limiter.limit('5 per minute')
def dash_test():
    APIKey = session.get("key")
    if (APIKey != API_Check):
        return jsonify({"msg":"Houston Painting S & S LLC."}),200
    return jsonify({"msg": "Houston Painting S & S LLC."}),200
  
@application.route("/hello", methods = ["GET"])
#@limiter.limit('5 per minute')
def hello_world():
    APIKey = session.get("key")
    if (APIKey != API_Check):
        return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    return jsonify({"msg": "Hello World!"})

# - - - register account - - -

    
@application.route("/request_account", methods = ["POST"])
def register_account():
    try:
        APIKey = session.get("key") #"ej2f!nsj6N25f7beuA%k8e*m"
        Access_Code = request.json["Code"]
        account = request.json["email"]
        thisPassword = request.json["password"]
        Activate2FA = request.json["activate2fa"] #true else <anything>
    except Exception as e:
        return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    
    if (APIKey != API_Check and Access_Code != "Jv1m1K8gBv5B2YjGf7HKI9uP8lO03I"):
        return jsonify({"msg":"Something went wrong. Please check your settings."}),403
        #print("Account requested started")
    
    # Check if user exists
    user_exists = Accounts.query.filter_by(email = account).first() is not None
    if user_exists:
        return jsonify({"Error":"User already registered"}),403
    user = Accounts.query.filter_by(email = account).first()
    
    # Accept password
    hashed_password = bcrypt.generate_password_hash(thisPassword)  
    # 2FA Keyword generator for Google Auth
    secret = pyotp.random_base32()  
    #Encryption
    encrypted_secret_key = Cryptography.Encrypt(secret)
    # Insert user
    if(Activate2FA == "true"):
        new_account = Accounts(email = account, password= hashed_password, MultiFactor=encrypted_secret_key, time = get_ct(),permLvl=0)
    else:
        new_account = Accounts(email = account, password= hashed_password,MultiFactor=None, time = get_ct(),permLvl=0)
    
    #done
    db.session.add(new_account)
    db.session.commit() 
    if(Activate2FA == "true"):
        return jsonify({"msg": "Success!","2FA":str(secret)}),200
    else:
        return jsonify({"msg": "Success!"}),200

# - - - Login - - -

@application.route("/login", methods = ["POST"])
def login_account():
    try:
        account = request.json["email"]
        thisPassword = request.json["password"]
    except Exception as e:
        return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    
    #if (APIKey != API_Check):
        #return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    
    user = Accounts.query.filter_by(email = account).first() # could write it as user.query.filter_by(...).first()...
    
    # Checking credentials 
    if user is None:
        return jsonify({"Error":"Unauthorized"}), 401
    if not bcrypt.check_password_hash(user.password, thisPassword):
        return jsonify({"Error":"Unauthorized"}), 401
    
    # Checking Multi Factor Authentication
    try:
        if (user.MultiFactor == None or ""):
            session["user_id"] = user.id
            session["cart"] = []
            session["key"] = API_Check
            session.modified = True
            print("logged in")
            return jsonify({"msg":"Success!"}),200
    except Exception as e:
        print(f"Failed to create/load sessions"),403
    try:
        multiFactor = request.json["MultiFactor"]
        if multiFactor == "":
            return jsonify({"msg":"Multi Factor Required"}),403
    except Exception as e:
        return jsonify({"msg":"Multi Factor incorrect"}),403
    # decryption 
    decrypted_secret_key = Cryptography.Decrypt(user.MultiFactor)
    
    # Check 2FA
    totp = pyotp.TOTP(decrypted_secret_key)
    decrypted_secret_key = None
    is_valid = totp.verify(multiFactor)
    if is_valid:
        session["user_id"] = user.id
        session["cart"] = []
        session["key"] = API_Check
        session.modified = True
        print("logged in")
        return jsonify({"msg":"Success!"}),200
    else:
        return jsonify({"msg":"Incorrect OTP"}),403


# - - - Logout - - -

@application.route("/logout", methods = ["POST"])
def logout_account():
    # Checking first level access
    try:
        APIKey = session.get("key")
    except Exception as e:
        return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    
    if (APIKey != API_Check):
        return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    
    user_id = session.get("user_id") 
    if not user_id:
        return jsonify({"Error":"Unauthorized"}), 401
    # Pop session
    user_id = session.get("user_id")
    session.pop("user_id")
    session.pop("cart")
    session.pop("key")
    return jsonify({"Msg" : "Log out successful"}),200

# - - - me - - -

@application.route("/me", methods = ["GET","POST"])
def me_account():
    try:
        APIKey = session.get("key")
        if (APIKey != API_Check):
            return jsonify({"msg":"Something went wrong. Please check your settings.E1"}),403
    except Exception as e:
        return jsonify({"msg":"Something went wrong. Please check your settings.E2"}),403
    
    user_id = session.get("user_id") 
    if not user_id:
        return jsonify({"Error":"Unauthorized"}), 401
    # logged in
    user = Accounts.query.filter_by(id=user_id).first()
    session["user_id"] = user_id
    session.modified = True
    return jsonify({"msg":str(user.email),"permi_lvl":str(user.permLvl)}),200

# - - - create division - - -

@application.route("/create_division",methods = ["POST"])
def create_division():
    #check what is coming in
    try:
        APIKey = session.get("key")
        division_name = request.form["name"]
        if (APIKey != API_Check):
            return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    except Exception as e:
        print(e)
        return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    
    user_id = session.get("user_id") 
    if not user_id:
        return jsonify({"Error":"Unauthorized"}), 401
    # logged in with perm lvl 9
    user = Accounts.query.filter_by(id=user_id).first()
    # check if name is being used
    try:
        division = Divisions.query.filter_by(name=division_name).first()
        if division is not None:
            return jsonify({"msg":"Name already being used."}),400
    except Exception as e:
        return jsonify({"msg":"Something went wrong. Please check your settings."}),400
    
    if (int(user.permLvl) <= 8):
        return jsonify({"Error":"Unauthorized"}), 401
    try:
        image = request.files["image"]
    except Exception as e:
        
        new_division = Divisions(name=division_name,image=None)
        db.session.add(new_division)
        db.session.commit()
        return jsonify({"msg":"Success!"}),200   
    # Has image
    try:
        image = request.files["image"]
        image_data = image.read() # binary conversion/read
    except Exception as e:
        image_data = None
    new_division = Divisions(name=division_name,image=image_data)
    db.session.add(new_division)
    db.session.commit()
    #Finish
    return jsonify({"Msg" : "Success!"}),200

# - - - division image - - - 
@application.route("/division_image/<ID>", methods = ["GET"])
def get_division_image(ID):
    # Check Control key
    try:
        APIKey = session.get("key")
        
        if (APIKey != API_Check):
            return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    except Exception as e:
        return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    # Check if valid session
    user_id = session.get("user_id") 
    if not user_id:
        return jsonify({"Error":"Unauthorized"}), 401
    # get image
    division = Divisions.query.filter_by(id=ID).first()
    if division and division.image:
        # Determine the image format using Pillow
        try:
            image = Image.open(BytesIO(division.image))
            image_format = image.format.lower()
        except Exception as e:
            return jsonify({"msg" : "Error determining image format. Perhaps it doesn't exist."}), 400

        if image_format:
            # Serve the image as a response with the correct content_type
            content_type = f'image/{image_format}'
            return Response(division.image, content_type=content_type)
        else:
            # Handle cases where the format couldn't be determined
            return "Unknown image format", 400
    else:
        # Return a default image or an error message
        #return jsonify({"msg":"No Img"}),403
        return Response(open('HPLogoNW.png', 'rb').read(), content_type='image/png')  # Adjust the path and content_type

# - - - all divisions - - - 

@application.route("/all_divisions", methods = ["GET"])
def all_divisions():
    # Check Control key
    try:
        APIKey = session.get("key")
        
        if (APIKey != API_Check):
            return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    except Exception as e:
        return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    # Check if valid session
    user_id = session.get("user_id") 
    if not user_id:
        return jsonify({"Error":"Unauthorized"}), 401
    # get all sections
    divisions = Divisions.query.all()
    # Sort the divisions based on the "name" column
    sorted_divisions = sorted(divisions, key=lambda x: x.name)

    results = multiDivisionSchema.dump(sorted_divisions)
    return jsonify(results),200

# - - - get division - - -  %20 is used for space

@application.route("/get_division/<ID>", methods = ["GET"])
def get_division(ID):
    # Check Control key
    try:
        APIKey = session.get("key")
        
        if (APIKey != API_Check):
            return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    except Exception as e:
        return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    
    # Check if valid session
    user_id = session.get("user_id") 
    if not user_id:
        return jsonify({"Error":"Unauthorized"}), 401
    
    # get all sections
    division = Divisions.query.filter_by(id=ID).first()
    if division is None:
        return jsonify({"msg":"Not Found."}),403
    results = multiDivisionSchema.dump([division])
    #return (singleSectionsSchema.jsonify(section)),200 use this for non-brackets
    return jsonify(results),200

# - - - update division - - -
@application.route("/update_division/<ID>",methods = ["PUT"])
def update_division(ID):
    #check what is coming in
    try:
        APIKey = session.get("key")
        div_name = request.form["name"]
        
        if (APIKey != API_Check):
            return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    except Exception as e:
        print(e)
        return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    
    user_id = session.get("user_id") 
    if not user_id:
        return jsonify({"Error":"Unauthorized"}), 401
    # logged in with perm lvl 9
    user = Accounts.query.filter_by(id=user_id).first()
    
    # check if name is being used
    try:
        division = Divisions.query.filter_by(id=ID).first()
        division_check = Divisions.query.filter(
        (Divisions.name == div_name) &
        (Divisions.id != ID)  # Exclude the current division
    ).first()
        
        if division_check is not None:
            return jsonify({"msg":"Name already being used."}),403
        if division is None:
            return jsonify({"msg":"Not found."}),403
    except Exception as e:
        return jsonify({"msg":"Division with same name found"}),403
    
    # check permission level
    if (int(user.permLvl) <= 8):
        return jsonify({"Error":"Unauthorized"}), 401
    try:
        image = request.files["image"]
        #print("Image file content:", image.read()) 
    except Exception as e:
        division.name = div_name
        # image = none
        db.session.commit()
        return jsonify({"msg":"Name change Succesful. Image error"}),200   
    # Has image
    try:
        image = request.files["image"]
        image_data = image.read() # binary conversion/read
    except Exception as error:
        print('img was not read',error)
        if image is None:
            division.name = div_name
        #division.image = None
        db.session.commit()
        return jsonify({"Msg" : "Success! However, image was not updated."}),200
    if image is not None:
        division.image = image_data
    division.name = div_name
    db.session.commit()
    #Finish
    return jsonify({"Msg" : "Success!"}),200

# - - - delete division - - -
@application.route("/delete_division/<ID>",methods=["DELETE"])
def delete_division(ID):
    #check what is coming in
    try:
        APIKey = session.get("key")
        
        if (APIKey != API_Check):
            return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    except Exception as e:
        print(e)
        return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    
    user_id = session.get("user_id") 
    if not user_id:
        return jsonify({"Error":"Unauthorized"}), 401
    # log in and check if perm lvl 9
    user = Accounts.query.filter_by(id=user_id).first()
    if (int(user.permLvl) <= 8):
        return jsonify({"Error":"Unauthorized"}), 401
    # check if name is being used
    try:
        division = Divisions.query.filter_by(id=ID).first()
        if division is None:
            return jsonify({"msg":"Not found."}),403
    except Exception as e:
        return jsonify({"msg":"Something went wrong. Please check your settings."+str(e)}),403
    
    #delete division
    try:
        linked_inventory_items = Sections.query.filter_by(division=division.id).all()
        print(linked_inventory_items)
        if not linked_inventory_items:
            db.session.delete(division)
            db.session.commit()
        else:
           return jsonify({"msg":"Denied. Root can only be deleted if it has nothing pointed to it."}),403 
    except Exception as e:
        return jsonify({"msg":"Something went wrong. Please check your settings."+str(e)}),403
    return jsonify({"Msg" : "Success!"}),200

# get all linked sections form a division
@application.route("/division/items/<ID>",methods=["GET"])
def division_items(ID):
    #check what is coming in
    try:
        APIKey = session.get("key")
        
        if (APIKey != API_Check):
            return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    except Exception as e:
        print(e)
        return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    
    user_id = session.get("user_id") 
    if not user_id:
        return jsonify({"Error":"Unauthorized"}), 401

    # check if name is being used
    try:
        section = Divisions.query.filter_by(id=ID).first()
        if section is None:
            return jsonify({"msg":"Not found."}),403
    except Exception as e:
        return jsonify({"msg":"Something went wrong. Please check your settings."+str(e)}),403

    linked_inventory_items = Sections.query.filter_by(division=ID).all()
    linked_inventory_items_sorted = sorted(linked_inventory_items, key=lambda x: x.section)
    results = multiAccountsSchema.dump(linked_inventory_items_sorted)
    return jsonify(results),200

# - - - Create_section - - -  /!\ THIS ONE USES THE FORM FORMAT !!!!!!!!!!! (form-format in  postman loc in body)

@application.route("/create_section",methods = ["POST"])
def create_section():
    #check what is coming in
    try:
        APIKey = session.get("key")
        section_name = request.form["section"]
        division = request.form["division"] #name of division
        if (APIKey != API_Check):
            return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    except Exception as e:
        print(e)
        return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    
    user_id = session.get("user_id") 
    if not user_id:
        return jsonify({"Error":"Unauthorized"}), 401
    # logged in with perm lvl 9
    user = Accounts.query.filter_by(id=user_id).first()
    # check if name is being used
    try:
        section = Sections.query.filter_by(section=section_name).first()
        division = Divisions.query.filter_by(id=division).first()
        division_id = division.id
        if section is not None:
            return jsonify({"msg":"Name already being used."}),403
    except Exception as e:
        return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    
    if (int(user.permLvl) <= 8):
        return jsonify({"Error":"Unauthorized"}), 401
    try:
        image = request.files["image"]
    except Exception as e:
        
        new_section = Sections(division=division_id,section=section_name,image=None)
        db.session.add(new_section)
        db.session.commit()
        return jsonify({"msg":"Success!"}),200   
    # Has image
    try:
        image = request.files["image"]
        image_data = image.read() # binary conversion/read
    except Exception as e:
        image_data = None
        db.session.add(new_section)
        db.session.commit()
        new_section = Sections(division=division_id,section=section_name,image=None)
        return jsonify({"Msg" : "Success!"}),200
    new_section = Sections(division=division_id,section=section_name,image=image_data)
    db.session.add(new_section)
    db.session.commit()
    #Finish
    return jsonify({"Msg" : "Success!"}),200

# - - - Section_image - - -

@application.route("/section_image/<subjectName>", methods = ["GET"])
def get_sections_image(subjectName):
    # Check Control key
    try:
        APIKey = session.get("key")
        
        if (APIKey != API_Check):
            return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    except Exception as e:
        return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    # Check if valid session
    user_id = session.get("user_id") 
    if not user_id:
        return jsonify({"Error":"Unauthorized"}), 401
    # get image
    section = Sections.query.filter_by(section=subjectName).first()
    if section and section.image:
        # Determine the image format using Pillow
        try:
            image = Image.open(BytesIO(section.image))
            image_format = image.format.lower()
        except Exception as e:
            return "Error determining image format. Perhaps it doesn't exist.", 500

        if image_format:
            # Serve the image as a response with the correct content_type
            content_type = f'image/{image_format}'
            return Response(section.image, content_type=content_type)
        else:
            # Handle cases where the format couldn't be determined
            return "Unknown image format", 500
    else:
        # Return a default image or an error message
        #return jsonify({"msg":"No Img"}),403
        return Response(open('HPLogoNW.png', 'rb').read(), content_type='image/png') 

# - - - Get All Sections - - -

@application.route("/all_sections", methods = ["GET"])
def all_sections():
    # Check Control key
    try:
        APIKey = session.get("key")
        
        if (APIKey != API_Check):
            return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    except Exception as e:
        return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    # Check if valid session
    user_id = session.get("user_id") 
    if not user_id:
        return jsonify({"Error":"Unauthorized"}), 401
    # get all sections
    sections = Sections.query.all()
    results = multiSectionsSchema.dump(sections)
    return jsonify(results),200

# - - - get_section - - -

@application.route("/get_section/<id>", methods = ["GET"])
def get_sections(id):
    # Check Control key
    try:
        APIKey = session.get("key")
        
        if (APIKey != API_Check):
            return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    except Exception as e:
        return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    
    # Check if valid session
    user_id = session.get("user_id") 
    if not user_id:
        return jsonify({"Error":"Unauthorized"}), 401
    
    # get all sections
    section = Sections.query.filter_by(id=id).first()
    if section is None:
        return jsonify({"msg":"Not Found."}),403
    results = multiSectionsSchema.dump([section])
    #return (singleSectionsSchema.jsonify(section)),200 use this for non-brackets
    return jsonify(results),200
    
# - - - update section - - -

@application.route("/update_section/<ID>",methods = ["PUT"])
def update_section(ID):
    #check what is coming in
    try:
        APIKey = session.get("key")
        section_name = request.form["section"]
        section_divisons = request.form["division"]
        
        if (APIKey != API_Check):
            return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    except Exception as e:
        print(e)
        return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    
    user_id = session.get("user_id") 
    if not user_id:
        return jsonify({"Error":"Unauthorized"}), 401
    # logged in with perm lvl 9
    user = Accounts.query.filter_by(id=user_id).first()
    
    # check if name is being used
    try:
        section = Sections.query.filter_by(id=ID).first()
        section_check = Sections.query.filter(
            (Sections.section == section_name) &
            (Sections.id != ID)
        ).first()
        if section_check is not None:
            return jsonify({"msg":"Name already being used."}),403
        if section is None:
            return jsonify({"msg":"Not found."}),403
    except Exception as e:
        return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    
    # check permission level
    if (int(user.permLvl) <= 8):
        return jsonify({"Error":"Unauthorized"}), 401
    try:
        image = request.files["image"]
    except Exception as e:
        section.section = section_name
        section.division = section_divisons
        #section.image = None
        db.session.commit()
        return jsonify({"msg":"Success!"}),200   
    # Has image
    try:
        image = request.files["image"]
        image_data = image.read() # binary conversion/read
    except Exception as e:
        if image is None:
            section.name = section_name
        #section.image = None
        db.session.commit()
        return jsonify({"Msg" : "Success! However, image was not updated."}),200
    if image is not None:
        section.image = image_data
    section.section = section_name
    section.division = section_divisons
    db.session.commit()
    #Finish
    return jsonify({"Msg" : "Success!"}),200
    
# - - - create inventory - - -

@application.route("/create_inventory",methods = ["POST"])
def create_inventory():
    #check what is coming in
    try:
        APIKey = session.get("key")
        thisName = request.form["name"]
        thisSection = request.form["section"]
        amount = request.form["amount"]
        
        if (APIKey != API_Check):
            return jsonify({"msg":"Something went wrong. Please check your settings."}),403
        
    except Exception as e:
        print(e)
        return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    
    user_id = session.get("user_id") 
    if not user_id:
        return jsonify({"Error":"Unauthorized"}), 401
    # logged in with perm lvl 9
    user = Accounts.query.filter_by(id=user_id).first()
    # check if name is being used
    try:
        inventory = Inventory.query.filter_by(name=thisName).first()
        if inventory is not None:
            return jsonify({"msg":"inventory with same name found"}),403
        section = Sections.query.filter_by(id=thisSection).first()
        if section is None:
            return jsonify({"msg":"No section or inventory dupe found with that name."}),403
        sectionid = section.id
        if inventory is not None:
            return jsonify({"msg":"Name already being used."}),403
    except Exception as e:
        return jsonify({"msg":"Something went wrong. Please check your settings."+str(e)}),403
    # deny if perm lvl is not high enough
    if (int(user.permLvl) <= 8):
        return jsonify({"Error":"Unauthorized"}), 401
    # set image
    try:
        image = request.files["image"]
        image_data = image.read()
        if image_data is None:
            image_data = None
    except Exception as e:
        image_data = None 
    # set details  
    try:
        details = request.form["details"]
        if details is None:
            details = None
    except Exception as e:
        details = None
    map = None
    try:
        paint = request.form["paint"]
        if paint is None:
            paint = None
    except Exception as e:
        paint = None
    map = None
    new_inventory = Inventory(name=thisName,amount=int(amount),reserved=int(0),details=details,paint=paint,map=map, section=sectionid,image=image_data)
    db.session.add(new_inventory)
    db.session.commit()
    return jsonify({"Msg" : "Success!"}),200

# - - - Get Inventory - - -
    
@application.route("/get_inventory/<ID>",methods = ["GET"])
def get_inventory(ID):
    #check what is coming in
    try:
        APIKey =session.get("key") 
        
        if (APIKey != API_Check):
            return jsonify({"msg":"Something went wrong. Please check your settings."}),403      
    except Exception as e:
        print(e)
        return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    #Check if logged in 
    user_id = session.get("user_id") 
    if not user_id:
        return jsonify({"Error":"Unauthorized"}), 401
    # get all sections
    inventory = Inventory.query.filter_by(id=ID).first()
    if inventory is None:
        return jsonify({"msg":"Not Found."}),403
    results = multiInventorySchema.dump([inventory])
    return jsonify(results),200

# - - - ALL INVENTORY - - - 

@application.route("/all_inventory",methods = ["GET"])
def all_inventory():
    #check what is coming in
    try:
        APIKey = session.get("key")   
        
        if (APIKey != API_Check):
            return jsonify({"msg":"Something went wrong. Please check your settings."}),403     
    except Exception as e:
        print(e)
        return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    #Check if logged in 
    user_id = session.get("user_id") 
    if not user_id:
        return jsonify({"Error":"Unauthorized"}), 401
    # get all inventory
    inventory = Inventory.query.order_by(asc(Inventory.name)).all()
    if inventory is None:
        return jsonify({"msg":"Not Found."}),403
    if not inventory:
        return jsonify({"msg": "Not Found."}),403
    results = multiInventorySchema.dump(inventory)
    return jsonify(results),200

# - - - ALL INVENTORY - - - 

@application.route("/search_inventory/<input>",methods = ["GET"])
def search_inventory(input):
    #check what is coming in
    try:
        APIKey = session.get("key")   
        
        if (APIKey != API_Check):
            return jsonify({"msg":"Something went wrong. Please check your settings."}),403     
    except Exception as e:
        print(e)
        return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    #Check if logged in 
    user_id = session.get("user_id") 
    if not user_id:
        return jsonify({"Error":"Unauthorized"}), 401
    # Stem the input for a more flexible search
    #stemmed_input = stemmer.stem(input)

    # Get all inventory matching the search input
    inventory = Inventory.query.all()

    # Filter inventory based on the search input
    inventory = [
        item for item in inventory if fuzz.partial_ratio(item.name.lower(), input.lower()) >= 83
    ]
    # check if we have results
    if inventory is None:
        return jsonify({"msg":"Not Found."}),403
    if not inventory:
        return jsonify({"msg": "Not Found."}),403
    results = multiInventorySchema.dump(inventory)
    return jsonify(results),200

# - - - get inventory image - - -

@application.route("/inventory_image/<inventoryID>", methods = ["GET"])
def get_inventory_image(inventoryID):
    # Check Control key
    try:
        APIKey = session.get("key")
        
        if (APIKey != API_Check):
            return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    except Exception as e:
        return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    # Check if valid session
    user_id = session.get("user_id") 
    if not user_id:
        return jsonify({"Error":"Unauthorized"}), 401
    # get image
    inventory = Inventory.query.filter_by(id=inventoryID).first()
    if inventory and inventory.image:
        # Determine the image format using Pillow
        try:
            image = Image.open(BytesIO(inventory.image))
            image_format = image.format.lower()
        except Exception as e:
            return "Error determining image format. Perhaps it doesn't exist.", 500

        if image_format:
            # Serve the image as a response with the correct content_type
            content_type = f'image/{image_format}'
            return Response(inventory.image, content_type=content_type)
        else:
            # Handle cases where the format couldn't be determined
            return "Unknown image format", 500
    else:
        # Return a default image or an error message
        #return jsonify({"msg":"No Img"}),403
        return Response(open('HPLogoNW.png', 'rb').read(), content_type='image/png') 

# - - - Update Inventory - - -

@application.route("/update_inventory/<id>", methods=["PUT"])
def update_inventory(id):
    #check what is coming in
    try:
        APIKey = session.get("key")
        
        if (APIKey != API_Check):
            return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    except Exception as e:
        print(e)
        return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    
    user_id = session.get("user_id") 
    if not user_id:
        return jsonify({"Error":"Unauthorized"}), 401
    # logged in with perm lvl 9
    user = Accounts.query.filter_by(id=user_id).first()
    # check if it exists
    try:
        inventory = Inventory.query.filter_by(id=id).first()     
        #section = Sections.query.filter_by(section=thisSection).first()
        if inventory is None:
            return jsonify({"msg":"Not found."}),403
            #return jsonify(inventory_check),403
    except Exception as e:
        return jsonify({"msg":"Something went wrong. Please check your settings: "+str(e)}),403
    # deny if perm lvl is not high enough
    if (int(user.permLvl) <= 8):
        return jsonify({"Error":"Unauthorized"}), 401
    #Check Name
    try:
        name = request.form["name"]
        inventory_check = Inventory.query.filter(
            (Inventory.name == name) & 
            (Inventory.id != id)
        ).first()
        if inventory_check is not None:
            return jsonify({"msg":"Same Name Found"}),403
        if name is None:
            name = inventory.name
        else:
            inventory.name = name
    except Exception as e:
        pass
    #Check Amount
    try:
        amount = int(request.form["amount"])
        if amount is None:
            amount = int(inventory.amount)
        else:
            inventory.amount = amount
    except Exception as e:
        pass
    try:
        reserve = int(request.form["reserve"])
        if reserve is None:
            reserve = int(inventory.reserve)
        else:
            inventory.reserved = reserve
    except Exception as e:
        pass
    #Check details
    try:
        details = request.form["details"]
        if details is None:
            details = inventory.details
        else:
            inventory.details = details
    except Exception as e:
        pass
    #Check paint
    try:
        this_paint = request.form["paint"]
        if this_paint is None:
            inventory.paint = None
        else:
            inventory.paint = str(this_paint)
    except Exception as e:
        inventory.paint = None
    #Check section
    try:
        sections = request.form["section"]
        if sections is None:
            section = inventory.section
        else:
            section_class = Sections.query.filter_by(id=sections).first()
            section = section_class.id
            inventory.section = section
    except Exception as e:
        
        return jsonify({"msg":"Section not found: "+str(e)}),400
    #Check image
    try:
        image = request.files["image"]
        image_data = image.read() # binary conversion/read
        inventory.image = image_data
    except Exception as e:
        pass
    db.session.commit()
    return jsonify({"Msg" : "Success!"}),200

# - - - Delete Inventory - - - 

@application.route("/delete_inventory/<id>",methods=["DELETE"])
def delete_inventory(id):
    #check what is coming in
    try:
        APIKey = session.get("key")
        
        if (APIKey != API_Check):
            return jsonify({"msg":"Something went wrong. Please check your settings."}),403
        
    except Exception as e:
        print(e)
        return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    
    user_id = session.get("user_id") 
    if not user_id:
        return jsonify({"Error":"Unauthorized"}), 401
    # log in and check if perm lvl 9
    user = Accounts.query.filter_by(id=user_id).first()
    if (int(user.permLvl) <= 8):
        return jsonify({"Error":"Unauthorized"}), 401
    # check if name is being used
    try:
        inventory = Inventory.query.filter_by(id=id).first()
        #section = Sections.query.filter_by(section=thisSection).first()
        if inventory is None:
            return jsonify({"msg":"Not found."}),403
    except Exception as e:
        return jsonify({"msg":"Something went wrong. Please check your settings."+str(e)}),403

    #delete inventory
    inventory = Inventory.query.get(id)
    db.session.delete(inventory)
    db.session.commit()
    return jsonify({"Msg" : "Success!"}),200

# - - - delete section - - -
@application.route("/delete_section/<ID>",methods=["DELETE"])
def delete_section(ID):
    #check what is coming in
    try:
        APIKey = session.get("key")
        
        if (APIKey != API_Check):
            return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    except Exception as e:
        print(e)
        return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    
    user_id = session.get("user_id") 
    if not user_id:
        return jsonify({"Error":"Unauthorized"}), 401
    # log in and check if perm lvl 9
    user = Accounts.query.filter_by(id=user_id).first()
    if (int(user.permLvl) <= 8):
        return jsonify({"Error":"Unauthorized"}), 401
    # check if name is being used
    try:
        section = Sections.query.filter_by(id=ID).first()
        if section is None:
            return jsonify({"msg":"Not found."}),403
    except Exception as e:
        return jsonify({"msg":"Something went wrong. Please check your settings."+str(e)}),403
    
    #delete section
    try:
        linked_inventory_items = Inventory.query.filter_by(section=section.id).all()
        for item in linked_inventory_items:
            db.session.delete(item)
        db.session.delete(section)
        db.session.commit()
    except Exception as e:
        return jsonify({"msg":"Something went wrong. Please check your settings."+str(e)}),403
    return jsonify({"Msg" : "Success!"}),200

# - - - get all inventory items from section - - -

@application.route("/section/items/<ID>",methods=["GET"])
def section_items(ID):
    #check what is coming in
    try:
        APIKey = session.get("key")
        
        if (APIKey != API_Check):
            return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    except Exception as e:
        print(e)
        return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    
    user_id = session.get("user_id") 
    if not user_id:
        return jsonify({"Error":"Unauthorized"}), 401

    # check if name is being used
    try:
        section = Sections.query.filter_by(id=ID).first()
        if section is None:
            return jsonify({"msg":"Not found."}),403
    except Exception as e:
        return jsonify({"msg":"Something went wrong. Please check your settings."+str(e)}),403

    linked_inventory_items = Inventory.query.filter_by(section=ID).all()
    sorted_linked_items = sorted(linked_inventory_items, key=lambda x: x.name)
    results = multiAccountsSchema.dump(sorted_linked_items)
    return jsonify(results),200

# - - - Section items first N amount (currently 10) - - -

@application.route("/section/items/first_few/<ID>",methods=["GET"])
def section_itemsFirstN(ID):
    #check what is coming in
    try:
        APIKey = session.get("key")
        
        if (APIKey != API_Check):
            return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    except Exception as e:
        print(e)
        return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    
    user_id = session.get("user_id") 
    if not user_id:
        return jsonify({"Error":"Unauthorized"}), 401

    # check if name is being used
    try:
        section = Sections.query.filter_by(id=ID).first()
        if section is None:
            return jsonify({"msg":"Not found."}),403
    except Exception as e:
        return jsonify({"msg":"Something went wrong. Please check your settings."+str(e)}),403

    linked_inventory_items = Inventory.query.filter_by(section=ID).all()
    # ABC for now, popularity metric later
    linked_inventory_items_sorted = sorted(linked_inventory_items, key=lambda x: x.name)
    first_few_items = linked_inventory_items_sorted[:10]
    results = multiAccountsSchema.dump(first_few_items)
    return jsonify(results),200

# - - - look at your cart (checkout)  - - -

@application.route("/cart", methods=["GET"])
def cart():
    #check what is coming in
    try:
        APIKey = session.get("key")
        
        if (APIKey != API_Check):
            return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    except Exception as e:
        print(e)
        return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    
    user_id = session.get("user_id") 
    if not user_id:
        return jsonify({"Error":"Unauthorized"}), 401
    cart = session.get("cart") 
    if not cart:
        session["cart"] = []
    # log in and check if perm lvl 1>
    user = Accounts.query.filter_by(id=user_id).first()
    if (int(user.permLvl) <= 0):
        return jsonify({"Error":"Unauthorized"}), 401
    # returns cart
    return jsonify(cart),200

# - - - cart get amount - - -

@application.route("/cart/total_items", methods=["GET"])
def cart_items():
    #check what is coming in
    try:
        APIKey = session.get("key")
        
        if (APIKey != API_Check):
            return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    except Exception as e:
        print(e)
        return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    
    user_id = session.get("user_id") 
    if not user_id:
        return jsonify({"Error":"Unauthorized"}), 401
    cart = session.get("cart") 
    if not cart:
        session["cart"] = []
    # log in and check if perm lvl 1>
    user = Accounts.query.filter_by(id=user_id).first()
    if (int(user.permLvl) <= 0):
        return jsonify({"Error":"Unauthorized"}), 401
    # get total items
    insert_total = 0
    withdraw_total = 0
    for item in cart:
        amount = int(item["amount"])  # Convert the amount to an integer
        if item["type"] == "insert":
            insert_total += amount
        elif item["type"] == "withdraw":
            withdraw_total += amount
    # returns results
    return jsonify({"insert total":str(insert_total),"withdraw total":str(withdraw_total)}),200


# - - - add to your cart (checkout)  - - -

@application.route("/cart/add_withdraw", methods=["POST"])
def add_withdraw_cart():
    #check what is coming in
    try:
        APIKey = session.get("key")
        inventoryID = request.json["inventory"]
        amount = request.json["amount"]
        
        if (APIKey != API_Check):
            return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    except Exception as e:
        print(e)
        return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    
    user_id = session.get("user_id") 
    if not user_id:
        return jsonify({"Error":"Unauthorized"}), 401
    cart = session.get("cart",[]) 
    if not cart:
        session["cart"] = []
    # log in and check if perm lvl 1>
    cart = session["cart"]
    user = Accounts.query.filter_by(id=user_id).first()
    inventory = Inventory.query.filter_by(id=inventoryID).first()
    invamount = inventory.amount
    # check perm lvl and if requested stock is available
    if (int(user.permLvl) <= 0):
        return jsonify({"Error":"Unauthorized"}), 401
    if ((int(amount)) > int(invamount)):
        return jsonify({"msg":"You cannot withdraw more than whats available"}), 401
    # check if already in cart
    if int(amount) <= 0:
        return jsonify({"msg":"Amount not allowed."}),403
    #check if already in cart
    for item in cart:
        if item["inventory"] == inventoryID and item["type"] == "withdraw":
            # Check if inventory is available
            if ((int(amount) + int(item["amount"])) <= int(invamount) ):
                # Update the amount 
                item["amount"] = str(int(amount) + int(item["amount"]))
            else:
                return jsonify({"msg":"You cannot withdraw more than whats available"}), 401
            session["cart"] = cart
            return jsonify(cart),200
            
    # add to cart if the item is new 
    if(int(amount) > 0):
        cart.append({"inventory":str(inventoryID),"amount":str(amount),"type":"withdraw"})
    else:
        return jsonify({"msg":"Denied. Quantity must be greater than 0."}),403
    session["cart"] = cart
    # returns cart
    return jsonify(cart),200

# - - - remove items from cart - - -

@application.route("/cart/update_item", methods=["PUT"])
def cart_update_item():
    #check what is coming in
    try:
        APIKey = session.get("key")
        inventoryID = request.json["inventory"]
        type = request.json["type"]
        delete = request.json["remove"]
        
        if (APIKey != API_Check):
            return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    except Exception as e:
        print(e)
        return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    
    user_id = session.get("user_id") 
    if not user_id:
        return jsonify({"Error":"Unauthorized"}), 401
    cart = session.get("cart",[]) 
    if not cart:
        session["cart"] = []
    # log in and check if perm lvl 1>
    cart = session["cart"]
    user = Accounts.query.filter_by(id=user_id).first()
    try:
        inventory = Inventory.query.filter_by(id=inventoryID).first()
        invamount = inventory.amount
    except Exception as e:
        pass
    # check perm lvl and if requested stock is available
    if (int(user.permLvl) <= 0):
        return jsonify({"Error":"Unauthorized"}), 401
    # remove item if true
    try:
        amount = request.json["amount"]
        test_amount = int(amount)
    except Exception as e:
        if(delete == "true"):
            for item in cart:
                if item["inventory"] == inventoryID and item["type"] == type:
                    cart.remove(item)
                    session["cart"] = cart
                    return jsonify(cart),200
        else:
            return jsonify({"msg":"Amount not specified."}),403
    if(delete == "true" or int(amount) == 0):
        removeThis = []
        for item in cart:
            if item["inventory"] == inventoryID and item["type"] == type:
                cart.remove(item)
                session["cart"] = cart
                return jsonify(cart),200
    else:
        for item in cart:
            print(item["inventory"])
            inventory = Inventory.query.filter_by(id=inventoryID).first()
            inventory_amount = inventory.amount
            if item["inventory"] == inventoryID and item["type"] == type:
                try:
                    amount = request.json["amount"]
                    item["inventory"] = inventoryID
                    item["type"] = type
                    if(int(amount) > 0 and item["type"] == "insert" and int(user.permLvl) >= 9):             
                        item["amount"] = amount
                        session["cart"] = cart
                        return jsonify(cart),200
                    elif (int(amount) > 0 and item["type"] == "insert" and int(user.permLvl) < 9): 
                        return({"msg":"You do not have permission to perform this action"}),403
                    
                    if(int(amount) > 0 and item["type"] == "withdraw" and int(amount) <= int(invamount)):             
                        item["amount"] = amount
                        session["cart"] = cart
                        return jsonify(cart),200
                    elif (int(amount) > 0 and item["type"] == "withdraw" and int(amount) > int(invamount)): 
                        return jsonify({"msg":"Requested more than whats available."}),403
                    return jsonify({"msg":"Request denied."}),401
                except Exception as e:
                    return jsonify({"msg":"Something went wrong. Did you forget your amount?."}),403
    return jsonify({"msg":"Item not found"}),401

# - - - add stock - - -

@application.route("/cart/add_stock", methods=["POST"])
def add_stock_cart():
    #check what is coming inki
    try:
        APIKey = session.get("key")
        inventoryID = request.json["inventory"]
        amount = request.json["amount"]
        
        if (APIKey != API_Check):
            return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    except Exception as e:
        print(e)
        return jsonify({"msg":"Something went wrong. Please check your settings.2"}),403
    
    # check authorization
    user_id = session.get("user_id") 
    if not user_id:
        return jsonify({"Error":"Unauthorized"}), 401
    # get cart, if it doesn't exist then make an empty one
    cart = session.get("cart",[]) 
    if not cart:
        session["cart"] = []
    # log in and check if perm lvl 1>
    cart = session["cart"]
    user = Accounts.query.filter_by(id=user_id).first()
    if (int(user.permLvl) <= 0):
        return jsonify({"Error":"Unauthorized"}), 401
    # check if already in cart
    if int(amount) <= 0:
        return jsonify({"msg":"Amount not allowed."}),403
    for item in cart:
        if item["inventory"] == inventoryID and item["type"] == "insert":
            # Update the amount 
            item["amount"] = str(int(amount) + int(item["amount"]))
            session["cart"] = cart
            return jsonify(cart),200
    # add to cart
    if (int(amount) > 0):
        cart.append({"inventory":str(inventoryID),"amount":str(amount),"type":"insert"})
    else:
        return jsonify({"msg":"Denied. Quantity must be greater than 0."}),403
    session["cart"] = cart
    # returns cart
    return jsonify(cart),200
    
# - - - checkout - - - 

@application.route("/cart/checkout", methods=["POST"])
def cart_checkout2():
    # Check what is coming in
    try:
        APIKey = session.get("key")
        costumer = request.json["user"]
        projectName = request.json["project"]
        
        if (APIKey != API_Check):
            return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    except Exception as e:
        print("erorr ",e)
        return jsonify({"msg": "Something went wrong. Please check your settings."}), 403
    user_id = session.get("user_id") 
    if not user_id:
        return jsonify({"Error":"Unauthorized"}), 401
    # Get the logged-in user
    user = Accounts.query.filter_by(id=user_id).first()

    # Check if the user is authorized
    if (int(user.permLvl) <= 0):
        return jsonify({"Error": "Unauthorized. PermLvl too low to add inventory."}), 401

    cart = session.get("cart", [])
    if cart is None or not cart:
        return jsonify({"msg": "Empty or null cart."}), 403

    # Initialize a flag to track if all items can be checked out
    can_checkout = True

    # Process each item
    try:
        for item in cart:
            inventory_id = str(item["inventory"])
            amount = int(item["amount"])
            is_insert = item.get("type") == "insert"

            if is_insert:
                # Check if the permlvl is 9
                if (int(user.permLvl) >= 9):
                    # Add the specified amount of inventory
                    inventory = Inventory.query.filter_by(id=inventory_id).first()
                    if inventory is None:
                        return jsonify({"msg":"Denied. The given data may be outdated."}),403
                    if inventory:
                        current_amount = int(inventory.amount)
                        new_amount = current_amount + amount
                        inventory.amount = int(new_amount)
                    else:
                        can_checkout = False  # Cannot checkout
                else:
                    can_checkout = False  # Cannot checkout
            else:
                # For withdraw
                inventory = Inventory.query.filter_by(id=inventory_id).first()
                if inventory is None:
                        return jsonify({"msg":"Denied. The given data may be outdated."}),403
                if inventory:
                    current_amount = int(inventory.amount)
                    if amount > current_amount:
                        can_checkout = False  # Cannot checkout
                    else:
                        new_amount = current_amount - amount
                        inventory.amount = new_amount
    except Exception as e:
        return jsonify({"msg":"Denied. The given data may be outdated."}),403

    # create a reciept
    if can_checkout:
        reciept = Reciept(name=costumer,project=str(projectName),permLvl=str(user.permLvl),condition="original", time=get_ct())
        db.session.add(reciept)
        db.session.commit() 

        # Add items into the reciept
        for item in cart:
            inventory_id = str(item["inventory"])
            inventory = Inventory.query.filter_by(id=inventory_id).first()
            section = inventory.section
            change = str(item["amount"])
            original_change = str(item["amount"])  

            if item["type"] == "insert":
                updatedNumber = str(int(inventory.amount))
            else:
                updatedNumber = str(int(inventory.amount))

            reciept_item = Reciept_items(
                reciept=reciept.id,
                inventory_id=inventory_id,
                section_id=section,
                change=change,
                original_change=original_change,
                name= str(item["type"]),
                updatedNumber=updatedNumber,
                time=get_ct()
            )

            db.session.add(reciept_item)

        db.session.commit()  

        # Clear the cart
        session["cart"] = []

        return jsonify({"msg": "Checkout successful!","Rec":reciept.id}), 200
    else:
        return jsonify({"msg": "Checkout failed due to insufficient permission or inventory."}), 401

# - - - Get items from a reciept - - -

@application.route("/Reciept/<ID>",methods=["GET"])
def get_Reciept(ID):
    #check what is coming in
    try:
        APIKey = session.get("key")
        
        if (APIKey != API_Check):
            return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    except Exception as e:
        print(e)
        return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    
    user_id = session.get("user_id") 
    if not user_id:
        return jsonify({"Error":"Unauthorized"}), 401

    # check if name is being used
    try:
        section = Reciept.query.filter_by(id=ID).first()
        if section is None:
            return jsonify({"msg":"Not found."}),403
    except Exception as e:
        return jsonify({"msg":"Something went wrong. Please check your settings."+str(e)}),403

    linked_inventory_items = Reciept_items.query.filter_by(reciept=ID).all()
    results = multiReceiptItemsSchema.dump(linked_inventory_items)
    return jsonify(results),200

# - - - Update reciept item; sideffects: updates inventory; reqs - - -

 
@application.route("/Reciept/item/<ID>",methods=["PUT"])
def Reciept_item_update(ID):
    try:
        APIKey = session.get("key")
        change = request.json["change"]
        
        if (APIKey != API_Check):
            return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    except Exception as e:
        print(e)
        return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    
    user_id = session.get("user_id") 
    if not user_id:
        return jsonify({"Error":"Unauthorized"}), 401
    
    # check permission level
    user = Accounts.query.filter_by(id=user_id).first()
    if (int(user.permLvl) <= 0):
        return jsonify({"Error": "Unauthorized. PermLvl too low to add inventory."}), 401
    reciept_item = Reciept_items.query.filter_by(id=ID).first()
    # make exception
    if reciept_item is None:
        return jsonify({"msg":"Not found"}),401
    reciept = Reciept.query.filter_by(id=reciept_item.reciept).first()
    # Check if Administrator level reciept 
    if (int(user.permLvl) < int(reciept.permLvl)):
        return jsonify({"Error":"Unauthorized"}), 401
    #for withdrawl
    if (reciept_item.name == "withdraw"):
        #check if request is less than the original order AND current change must be different than requested change
        if(int(reciept_item.original_change) >= int(change) and int(reciept_item.change) != int(change) and int(change) >= 0):
            
            # for the condition the requested number is higher (subtract inventory)
            if(int(change) > int(reciept_item.change)):
                # check if selected inventory exist
                try:
                    inventory = Inventory.query.filter_by(id=str(reciept_item.inventory_id)).first()
                except Exception as e:
                    return jsonify({"msg":"inventory not found. It may no longer exist."}),403
                current_inventory = int(inventory.amount)
                
                if (current_inventory - int(change)) < 0:
                    return jsonify({"msg":"Denied. Inventory will result in negative."}),403
                if (int(change) - int(reciept_item.change) <= -1):
                    return jsonify({"msg":"Denied. Exceeds original withdraw amount"}),403
                
                else:
                    inventory.amount = current_inventory - (int(change) - int(reciept_item.change))
                    reciept_item.updatedNumber = current_inventory - (int(change) - int(reciept_item.change))
                    reciept_item.change = str(change)
                    reciept_item.time = get_ct()
                    reciept.condition = "modified"
                    reciept.time = get_ct()
                    db.session.commit()
                    return jsonify({"msg":"Success!"}),200
                
            # for the condition the requested number is lower (add inventory)
            if(int(change) < int(reciept_item.change)):
                # check if selected inventory exist
                try:
                    inventory = Inventory.query.filter_by(id=str(reciept_item.inventory_id)).first()
                except Exception as e:
                    return jsonify({"msg":"inventory not found. It may no longer exist."}),403
                current_inventory = int(inventory.amount)
                if (current_inventory + int(change)) < int(reciept_item.original_change):
                    return jsonify({"msg":"Denied. Inventory will result in negative."}),403
                else:
                    inventory.amount = current_inventory + abs(int(change) - int(reciept_item.change))
                    reciept_item.updatedNumber = current_inventory + abs(int(change) - int(reciept_item.change))
                    reciept_item.change = str(change)
                    reciept_item.time = get_ct()
                    reciept.condition = "modified"
                    reciept.time = get_ct()
                    db.session.commit()
                    return jsonify({"msg":"Success!"}),200
    # for insert

    if (reciept_item.name == "insert" and int(change) >= 0 and int(change) != int(reciept_item.change)):
        
        # check permission level
        user = Accounts.query.filter_by(id=user_id).first()
        if (int(user.permLvl) <= 8):
            return jsonify({"Error": "Unauthorized. PermLvl too low to add inventory."}), 401
        try:
            inventory = Inventory.query.filter_by(id=reciept_item.inventory_id).first()
        except Exception as e:
            print(e)
            return jsonify({"msg":"inventory not found. It may no longer exist."}),403
        current_inventory = int(inventory.amount)
        # if we are adding inventory
        if(int(change) > int(reciept_item.change) and current_inventory + (int(change) - int(reciept_item.change)) >= 0 and int(change) >= 0):
            inventory.amount = current_inventory + (int(change) - int(reciept_item.change))
            reciept_item.updatedNumber = current_inventory + (int(change) - int(reciept_item.change))
            reciept_item.change = str(change)
            reciept.condition = "modified"
            reciept_item.time = get_ct()
            reciept.time = get_ct()
            db.session.commit()
            return jsonify({"msg":"Success!"}),200
        # if we are subtracting inventory
        elif (int(change) < int(reciept_item.change) and current_inventory - abs(int(change) - int(reciept_item.change)) >= 0 and int(change) >= 0):
            inventory.amount = current_inventory - abs(int(change) - int(reciept_item.change))
            reciept_item.updatedNumber = current_inventory - abs(int(change) - int(reciept_item.change))
            reciept_item.change = str(change)
            reciept.condition = "modified"
            reciept_item.time = get_ct()
            reciept.time = get_ct()
            db.session.commit()
            return jsonify({"msg":"Success!"}),200
    # same number on insert
    elif (int(change) == int(reciept_item.change)):
        return jsonify({"msg":"Denied. Result would not change"}),400
    return jsonify({"msg":"Could not do anything with the given data."}),403

# - - - - - get receipt info - - - - -
@application.route("/get_receipt_info/<ID>", methods = ["GET"])
def get_receipt_info(ID):
    # Check Control key
    try:
        APIKey = session.get("key")
        
        if (APIKey != API_Check):
            return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    except Exception as e:
        return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    
    # Check if valid session
    user_id = session.get("user_id") 
    if not user_id:
        return jsonify({"Error":"Unauthorized"}), 401
    
    # get all sections
    rec = Reciept.query.filter_by(id=ID).first()
    if rec is None:
        return jsonify({"msg":"Not Found."}),403
    results = multiReceiptSchema.dump([rec])
    #return (singleSectionsSchema.jsonify(section)),200 use this for non-brackets
    return jsonify(results),200

# - - - - - get all receipts  - - - - -
@application.route("/get_receipt_all", methods = ["GET"])
def get_receipt_all():
    # Check Control key
    try:
        APIKey = session.get("key")
        
        if (APIKey != API_Check):
            return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    except Exception as e:
        return jsonify({"msg":"Something went wrong. Please check your settings."}),403
    
    # Check if valid session
    user_id = session.get("user_id") 
    if not user_id:
        return jsonify({"Error":"Unauthorized"}), 401
    #Check if user has enough permission
    user = Accounts.query.filter_by(id=user_id).first()
    if (int(user.permLvl) <= 0):
        return jsonify({"Error": "Unauthorized. PermLvl too low to add inventory."}), 401
    
    # get all Receipts from recent -> old; excluding anything older than 90 days
    ninety_days_ago = datetime.now() - timedelta(days=90)
    rec = Reciept.query.filter(Reciept.time >= ninety_days_ago).order_by(desc(Reciept.time)).all()
    if rec is None:
        return jsonify({"msg":"Not Found."}),403
    results = multiReceiptSchema.dump(rec)
    #return (singleSectionsSchema.jsonify(section)),200 use this for non-brackets
    return jsonify(results),200

# Schedule stuff
def old_deletion():
    with application.app_context():
        cutoff_time = datetime.utcnow() - timedelta(days=91) # 91
        #Reciept 
        old_reciept = (
            Reciept.query
            .filter(Reciept.time < cutoff_time)
            .all()
        )
        # delete old receipts
        if not old_reciept:
            print("No old receipts found.")   
            return
        #delete section
        try:
            for rec_items in old_reciept:
                linked_rec_items = Reciept_items.query.filter_by(reciept=rec_items.id).all()
                #print(linked_rec_items)
                for item in linked_rec_items:
                    #print("1")
                    db.session.delete(item)
                #print("2")
                db.session.delete(rec_items)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            print("An error happened")
            return
        print("Deleted old receipts")
        return

@application.errorhandler(500)
def internal_server_error(e):
    #print(e)
    return jsonify("Internal Server Error"), 500
    #return jsonify(error="Internal Server Error"+str(e)), 500

# Loop and delete anything older than 90 days, inluding reciept_tems
scheduler = BackgroundScheduler()
scheduler.add_job(func=old_deletion, trigger='interval', days=7)
scheduler.start()         

      
                    

# at the bottom 
if __name__ == "__main__":
    db.create_all()
    with application.app_context():
        db.create_all()
    #app.run()
    #socketio.run(application, debug=True) # port = 5000
    #application.run(debug=True)
    #application.run(host="0.0.0.0",port=5000, debug=True)
    application.run(host="0.0.0.0",port=5001, debug=False)