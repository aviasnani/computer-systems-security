import os

# configurations have been taken from previous project (sem 1...)

basedir = os.path.abspath(os.path.dirname(__file__)) 
instance_path = os.path.join(basedir, '..', 'instance')  
if not os.path.exists(instance_path): 
    os.makedirs(instance_path)  

class Config:
  SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(instance_path, 'database.db')
  SQLALCHEMY_TRACK_MODIFICATIONS = False 
  SESSION_COOKIE_SECURE = True
  SECRET_KEY = os.getenv('SECRET_KEY')
  SESSION_COOKIE_SAMESITE = 'None'
  SESSION_COOKIE_SECURE = True