# Flask nessesities 
from flask import Flask, jsonify, request, send_file, Response
from flask_sqlalchemy import SQLAlchemy
import datetime
from flask_marshmallow import Marshmallow
from flask_cors import CORS
import requests # installed
# optional for setting id's
from uuid import uuid4
from datetime import datetime
import pytz
import random, string

from alembic import op
from flask_migrate import Migrate

# - - - - - - - - - - - 
#app = Flask(__name__)
#CORS(app)
#app.app_context().push()
#app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://postgres:qkeMspr301#@localhost:5432/movies"
# - - - - - - - - - - -
db = SQLAlchemy()

def get_uuid():
    return uuid4().hex

def get_qrcode():
    x = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    return(x)

central_tz = pytz.timezone('US/Central')
current_time_in_central_tz = datetime.now(central_tz)

def upgrade():
    op.add_column('Inventory', db.Column('paint', db.Text(), nullable=True))

# Accounts table 
class Accounts(db.Model):
    __tablename__ = "Accounts"
    id = db.Column(db.String(32), primary_key = True, unique = True, default = lambda: get_uuid())
    email = db.Column(db.String(345), nullable = False)
    password = db.Column(db.LargeBinary(), nullable = False)
    MultiFactor = db.Column(db.LargeBinary(), nullable = True)
    time = db.Column(db.DateTime(timezone=True),nullable = True)
    permLvl = db.Column(db.Integer(), nullable = False)
    
    def __init__(self,email,password,MultiFactor,time,permLvl):
        self.email = email
        self.password = password
        self.MultiFactor = MultiFactor
        self.time = time
        self.permLvl = permLvl

# Divisions table

class Divisions(db.Model):
    __tablename__ = "Divisions"
    id = db.Column(db.String(32), primary_key = True, unique = True, default = lambda: get_uuid())
    name = db.Column(db.Text(), nullable = False)
    image = db.Column(db.LargeBinary, nullable = True)
    
    DivisionSec = db.relationship("Sections", back_populates="SectionDiv") # F
    
    def __init__(self,name,image):
        self.name = name
        self.image = image
        

# Section Table
class Sections(db.Model):
    __tablename__ = "Sections"
    id = db.Column(db.String(32), primary_key = True, unique = True, default = lambda: get_uuid())
    division = db.Column(db.String(32), db.ForeignKey(Divisions.id), nullable = False)
    section = db.Column(db.String(50), nullable = False)
    image = db.Column(db.LargeBinary, nullable=True)
    # class name and variable name connection
    SectionsRel = db.relationship("Inventory", back_populates="InventoryRel") # A
    SectionDiv = db.relationship("Divisions", back_populates="DivisionSec") # F
    #SectionsRelB = db.relationship("Reciept_items", back_populates="recieptsRelB") # B
    
    def __init__(self,division,section,image):
        self.division = division
        self.section = section
        self.image = image

# Map Table 
class Map(db.Model):
    __tablename__ = "map"
    id = db.Column(db.String(32), primary_key = True, unique = True, default = lambda: get_uuid())
    location = db.Column(db.Text(), nullable = False)
    image = db.Column(db.LargeBinary(), nullable = True)
    other = db.Column(db.Text(), nullable = False)
    
    Maprec = db.relationship("Inventory", back_populates="InvenmapRel") # D
    
    def __init__(self,location,image,other):
        self.location = location
        self.image = image
        self.other = other


# Inventory Table
class Inventory(db.Model):
    __tablename__ = "Inventory"
    id = db.Column(db.String(16), primary_key=True, unique=True, default=lambda: get_qrcode())
    name = db.Column(db.Text(), nullable = False)
    amount = db.Column(db.Integer(), nullable = False)
    reserved = db.Column(db.Integer(), nullable = False)
    details = db.Column(db.Text(), nullable = True)
    paint = db.Column(db.Text(), nullable = True)
    map = db.Column(db.Text(),db.ForeignKey(Map.id), nullable = True) #  foreign key? D
    section = db.Column(db.String(), db.ForeignKey(Sections.id), nullable = False)   
    image = db.Column(db.LargeBinary, nullable = True)
    
    InventoryRel = db.relationship("Sections", back_populates="SectionsRel") # A
    #invenrec = db.relationship("Reciept_items", back_populates="recieptsRel") # C
    InvenmapRel = db.relationship("Map", back_populates="Maprec") # D
    
    AlertInventoryRelI = db.relationship("Alert", back_populates="AlertInventoryRelA") # G
    
    def __init__(self,name,amount,reserved,details,paint,map,section,image):
        self.name = name
        self.amount = amount
        self.reserved = reserved
        self.details = details
        self.paint = paint
        self.map = map
        self.section = section
        self.image = image
        
# alert system
class Alert(db.Model):
    __tablename__ = "Alert"
    id = db.Column(db.String(32), primary_key = True, unique = True, default = lambda: get_uuid())
    inventory = db.Column(db.String(16), db.ForeignKey(Inventory.id), nullable = False)
    warn = db.Column(db.Integer(), nullable = False)
    critical = db.Column(db.Integer(), nullable = True)
    
    AlertInventoryRelA = db.relationship("Inventory", back_populates="AlertInventoryRelI") # G
    
    def __init__(self,inventory,warn,critical):
        self.inventory = inventory
        self.warn = warn
        self.critical = critical

# Reciept Table

class Reciept(db.Model):
    __tablename__ = "Reciept"
    id = db.Column(db.String(16), primary_key = True, unique = True, default=lambda: get_qrcode())
    name = db.Column(db.Text(), nullable = True)
    project = db.Column(db.Text(), nullable = True)
    permLvl = db.Column(db.Text(), nullable = True)
    condition = db.Column(db.Text(), nullable = True)
    time = db.Column(db.DateTime(timezone=True),nullable = False)
    
    def __init__(self,name,project,permLvl,condition,time):
        self.name = name
        self.project = project
        self.permLvl = permLvl
        self.condition = condition
        self.time = time
    
    iRecieptRelB = db.relationship("Reciept_items", back_populates="mRecieptRelB" ) # E

class Reciept_items(db.Model):
    __tablename__ = "Reciept_items"
    id = db.Column(db.Integer(),primary_key = True)
    reciept = db.Column(db.String(16), db.ForeignKey(Reciept.id))
    inventory_id = db.Column(db.String(16), nullable = False) # remove foreign key
    section_id = db.Column(db.String(32), nullable = True) # remove foreign_key
    change = db.Column(db.Text(), nullable = False)
    original_change = db.Column(db.Text(), nullable = False)
    name = db.Column(db.Text(), nullable = False)
    updatedNumber = db.Column(db.Text(), nullable = False)
    time = db.Column(db.DateTime(timezone=True),nullable = True)
    
    # Relationships
    #recieptsRel = db.relationship("Inventory", back_populates="invenrec") # C - 
    #recieptsRelB = db.relationship("Sections", back_populates="SectionsRelB") # B - 
    mRecieptRelB = db.relationship("Reciept", back_populates="iRecieptRelB" ) # E
        
    def __init__(self,reciept,inventory_id,section_id,change,original_change,name,updatedNumber,time):
        self.reciept = reciept
        self.inventory_id = inventory_id
        self.section_id = section_id
        self.change = change
        self.original_change = original_change
        self.name = name
        self.updatedNumber = updatedNumber
        self.time = time

class Reserve(db.Model):
    __tablename__ = "Reserve"
    id = db.Column(db.String(16), primary_key = True, unique = True, default=lambda: get_qrcode())
    name = db.Column(db.Text(), nullable = True)
    project = db.Column(db.Text(), nullable = True)
    time = db.Column(db.DateTime(timezone=True),nullable = False)
    
    def __init__(self,name,project,time):
        self.name = name
        self.project = project
        self.time = time
    
    iResRelB = db.relationship("Reserve_items", back_populates="mResRelB" ) # E

class Reserve_items(db.Model):
    __tablename__ = "Reserve_items"
    id = db.Column(db.Integer(),primary_key = True)
    reciept = db.Column(db.String(16), db.ForeignKey(Reserve.id))
    inventory_id = db.Column(db.String(16), nullable = False) # remove foreign key
    section_id = db.Column(db.String(32), nullable = True) # remove foreign_key
    change = db.Column(db.Text(), nullable = False)
    name = db.Column(db.Text(), nullable = False)
    updatedNumber = db.Column(db.Text(), nullable = False)
    time = db.Column(db.DateTime(timezone=True),nullable = True)
     
    mResRelB = db.relationship("Reserve", back_populates="iResRelB" ) # E
        
    def __init__(self,reciept,inventory_id,section_id,change,name,updatedNumber,time):
        self.reciept = reciept
        self.inventory_id = inventory_id
        self.section_id = section_id
        self.change = change
        self.name = name
        self.updatedNumber = updatedNumber
        self.time = time