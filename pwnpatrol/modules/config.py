from dotenv import load_dotenv
import os

load_dotenv()

db_config = {
    'user': os.getenv('DB_USER'),    
    'password': os.getenv('DB_PASSWORD'),     
    'host': os.getenv('DB_HOST'),
    'database': os.getenv('DB_NAME'),
}

CLIENT_ID = os.getenv('CLIENT_ID')
CLIENT_SECRET = os.getenv('CLIENT_SECRET')
TENANT_ID = os.getenv('TENANT_ID')
