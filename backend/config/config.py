import os

# configurations have been taken from previous project (sem 1...)

basedir = os.path.abspath(os.path.dirname(__file__)) 
instance_path = os.path.join(basedir, '..', 'instance')  
if not os.path.exists(instance_path): 
    os.makedirs(instance_path)  

class Config:
  SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(instance_path, 'database.db')
  SQLALCHEMY_TRACK_MODIFICATIONS = False 
  SESSION_COOKIE_SECURE = False  # Set to False for HTTP development
  SECRET_KEY = 'AviPushGarAdi@004'
  SESSION_COOKIE_SAMESITE = 'Lax'  # Changed from 'None' for better compatibility