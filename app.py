from flask import Flask,render_template,request,redirect,session,send_file
import psycopg2
import requests
import smtplib
import os
from email.message import EmailMessage
from user_agents import parse
from reportlab.platypus import SimpleDocTemplate,Table,TableStyle
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter

app=Flask(__name__)
app.secret_key="secret123"

EMAIL_ADDRESS="monishakumar1507@gmail.com"
EMAIL_PASSWORD="gyjwupxulxpzdllc"

DB_HOST="ep-blue-king-aihiazrl-pooler.c-4.us-east-1.aws.neon.tech"
DB_NAME="neondb"
DB_USER="neondb_owner"
DB_PASSWORD="npg_Mv8s1oDPYhAn"
DB_PORT="5432"

def get_connection():
    return psycopg2.connect(
        host=DB_HOST,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
        port=DB_PORT,
        sslmode="require"
    )

def get_location(ip):
    try:
        if ip=="127.0.0.1":
            return "Localhost","Local"
        data=requests.get(f"http://ip-api.com/json/{ip}",timeout=3).json()
        if data["status"]=="success":
            return data["country"],data["city"]
    except Exception:
        pass
    return "Unknown","Unknown"

def send_security_alert(subject,message):
    try:
        email=EmailMessage()
        email["Subject"]=subject
        email["From"]=EMAIL_ADDRESS
        email["To"]=EMAIL_ADDRESS
        email.set_content(message)
        with smtplib.SMTP_SSL("smtp.gmail.com",465) as smtp:
            smtp.login(EMAIL_ADDRESS,EMAIL_PASSWORD)
            smtp.send_message(email)
    except Exception as e:
        print(e)

def threat_level(failed,sql):
    if failed>=10 or sql>=5:
        return "HIGH","#EF4444"
    elif failed>=5 or sql>=2:
        return "MEDIUM","#F59E0B"
    return "LOW","#22C55E"

SQL_KEYWORDS=[
    "'","--",";","/*","*/",
    "DROP","SELECT","INSERT",
    "DELETE","UPDATE","UNION",
    "OR 1=1","AND 1=1"
]
@app.route("/",methods=["GET","POST"])
def login():
    if request.method=="POST":
        username=request.form.get("username","").strip()
        password=request.form.get("password","").strip()
        user_input=(username+" "+password).upper()

        for keyword in SQL_KEYWORDS:
            if keyword.upper() in user_input:
                ip=request.remote_addr or "Unknown"
                country,city=get_location(ip)

                conn=get_connection()
                cur=conn.cursor()
                cur.execute("""
                INSERT INTO login_logs
                (username,status,ip_address,browser,operating_system,device_type,country,city,attack_type)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """,(username,"FAILED",ip,"Unknown","Unknown","Unknown",country,city,"SQL Injection Attempt"))
                conn.commit()
                conn.close()

                send_security_alert(
                    "SQL Injection Alert",
                    f"""SQL Injection Detected

Username : {username}
IP : {ip}
Country : {country}
City : {city}
Attack : SQL Injection
"""
                )

                return render_template("login.html",error="SQL Injection Detected!")

        ip=request.remote_addr or "Unknown"
        country,city=get_location(ip)

        ua=parse(request.headers.get("User-Agent",""))
        browser=ua.browser.family
        operating_system=ua.os.family

        if ua.is_mobile:
            device="Mobile"
        elif ua.is_tablet:
            device="Tablet"
        else:
            device="Desktop"

        conn=get_connection()
        cur=conn.cursor()

        cur.execute("""
        SELECT * FROM login
        WHERE username=%s AND password=%s
        """,(username,password))

        user=cur.fetchone()

        if user:

            cur.execute("""
            INSERT INTO login_logs
            (username,status,ip_address,browser,operating_system,device_type,country,city,attack_type)
            VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """,(username,"SUCCESS",ip,browser,operating_system,device,country,city,"Normal Login"))

            conn.commit()
            conn.close()

            session["user"]=username
            return redirect("/dashboard")

        cur.execute("""
        INSERT INTO login_logs
        (username,status,ip_address,browser,operating_system,device_type,country,city,attack_type)
        VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """,(username,"FAILED",ip,browser,operating_system,device,country,city,"Invalid Login"))

        conn.commit()
        send_security_alert(
    "Failed Login Alert",
    f"""A failed login attempt was detected.

Username : {username}
IP : {ip}
Browser : {browser}
OS : {operating_system}
Device : {device}
Country : {country}
City : {city}
"""
)
        conn.close()
        send_security_alert(
    "Failed Login Alert",
    f"""A failed login attempt was detected.

Username : {username}
IP : {ip}
Browser : {browser}
OS : {operating_system}
Device : {device}
Country : {country}
City : {city}
"""
)

        return render_template("login.html",error="Invalid Username or Password")

    return render_template("login.html")
@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/")
    return render_template("dashboard.html")

@app.route("/digital-twin")
def digital_twin():
    if "user" not in session:
        return redirect("/")

    conn=get_connection()
    cur=conn.cursor()

    cur.execute("SELECT COUNT(*) FROM login_logs")
    total_logs=cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM login_logs WHERE status='SUCCESS'")
    success_logs=cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM login_logs WHERE status='FAILED'")
    failed_logs=cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM login_logs WHERE attack_type='SQL Injection Attempt'")
    sql_attacks=cur.fetchone()[0]

    level,color=threat_level(failed_logs,sql_attacks)

    cur.execute("""
    SELECT username,ip_address,browser,operating_system,
    device_type,country,city,login_time
    FROM login_logs
    ORDER BY id DESC
    LIMIT 1
    """)
    latest_login=cur.fetchone()

    cur.execute("""
    SELECT username,status,ip_address,login_time
    FROM login_logs
    ORDER BY id DESC
    LIMIT 5
    """)
    recent_logs=cur.fetchall()

    conn.close()

    return render_template(
        "digital_twin.html",
        total_logs=total_logs,
        success_logs=success_logs,
        failed_logs=failed_logs,
        sql_attacks=sql_attacks,
        latest_login=latest_login,
        recent_logs=recent_logs,
        threat_level=level,
        threat_color=color
    )
@app.route("/admin")
def admin():
    if "user" not in session:
        return redirect("/")

    conn=get_connection()
    cur=conn.cursor()

    cur.execute("""
    SELECT id,username,status,ip_address,browser,
    operating_system,device_type,country,city,
    attack_type,login_time
    FROM login_logs
    ORDER BY id DESC
    """)
    logs=cur.fetchall()

    conn.close()

    return render_template("admin.html",logs=logs)

@app.route("/students")
def students():
    if "user" not in session:
        return redirect("/")

    conn=get_connection()
    cur=conn.cursor()

    cur.execute("""
    SELECT id,reg_no,name,father,mother,blood_group,address,phone,email,department,year
    FROM students
    ORDER BY id
    """)

    students=cur.fetchall()
    print(students)

    conn.close()

    return render_template("students.html",students=students)
@app.route("/report")
def report():
    if "user" not in session:
        return redirect("/")

    conn=get_connection()
    cur=conn.cursor()

    cur.execute("""
    SELECT username,status,ip_address,browser,
    operating_system,device_type,country,
    city,attack_type,login_time
    FROM login_logs
    ORDER BY id DESC
    """)
    logs=cur.fetchall()
    conn.close()

    pdf=SimpleDocTemplate("Security_Report.pdf",pagesize=letter)

    data=[[
        "Username","Status","IP","Browser",
        "OS","Device","Country","City",
        "Attack","Time"
    ]]

    for row in logs:
        data.append([
            str(row[0]),str(row[1]),str(row[2]),str(row[3]),
            str(row[4]),str(row[5]),str(row[6]),str(row[7]),
            str(row[8]),str(row[9])
        ])

    table=Table(data)

    table.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,0),colors.darkblue),
        ("TEXTCOLOR",(0,0),(-1,0),colors.white),
        ("GRID",(0,0),(-1,-1),1,colors.black),
        ("BACKGROUND",(0,1),(-1,-1),colors.beige),
        ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
        ("FONTSIZE",(0,0),(-1,-1),8),
        ("BOTTOMPADDING",(0,0),(-1,0),8)
    ]))

    pdf.build([table])

    return send_file("Security_Report.pdf",as_attachment=True)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

if __name__=="__main__":
    app.run(debug=True)