import mysql.connector
from mysql.connector import Error

from modules.config import db_config


try:
    # Connect to MySQL server
    connection = mysql.connector.connect(**db_config)

    if connection.is_connected():
        cursor = connection.cursor()

        # SQL command to create the Vulnerability table
        create_table_query = """
        CREATE TABLE IF NOT EXISTS Vulnerability (
            id INT AUTO_INCREMENT PRIMARY KEY,
            cve VARCHAR(50),
            title VARCHAR(255),
            affected_item TEXT,
            tool VARCHAR(100),
            confidence FLOAT,
            severity VARCHAR(50),
            host VARCHAR(255),
            cvss FLOAT,
            epss FLOAT,
            summary TEXT,
            cwe VARCHAR(50),
            `references` TEXT,
            capec VARCHAR(50),
            solution TEXT,
            impact TEXT,
            access TEXT,
            age INT,
            pocs TEXT,
            kev BOOLEAN
        );
        """

        # Execute the SQL command
        cursor.execute(create_table_query)
        print(f"Table 'Vulnerability' has been created in the edufort database.")

        #? Describe the table to check if it was created successfully
        cursor.execute("DESCRIBE Vulnerability")
        print(cursor.fetchall())
        

except Error as e:
    print(f"Error: {e}")

finally:
    if connection.is_connected():
        cursor.close()
        connection.close()
        print("MySQL connection is closed.")
