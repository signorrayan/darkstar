import pandas as pd
import mysql.connector
from datetime import datetime
from modules.config import db_config

connection = mysql.connector.connect(**db_config)        
if connection.is_connected():
    cursor = connection.cursor()
else:
    print("Connection to MySQL failed")

#query = "SELECT * FROM Vulnerability"
query = "SELECT * FROM asmevents"
cursor.execute(query)
data = cursor.fetchall()

#? print the data
for row in data:
    print(row)
