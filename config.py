import mysql.connector

db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="shoaib@8445",
    database="kernelguard"
)

cursor = db.cursor(dictionary=True)

print("Database Connected Successfully!")