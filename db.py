import psycopg2

try:
    conn = psycopg2.connect(
        host="localhost",
        database="cyber_twin",
        user="postgres",
        password="sql1507"
    )

    print("Database Connected Successfully!")

    conn.close()

except Exception as e:
    print("Connection Failed")
    print(e)