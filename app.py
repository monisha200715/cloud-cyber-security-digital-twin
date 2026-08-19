# ==========================================
# Cloud Cyber Security Digital Twin System
# ==========================================

from flask import Flask, render_template, request, redirect, session, send_file,url_for, flash
import psycopg2
import requests
import smtplib
import os
import random

from dotenv import load_dotenv
from email.message import EmailMessage
from user_agents import parse

from reportlab.platypus import SimpleDocTemplate, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter

# ==========================================
# Load Environment Variables
# ==========================================

load_dotenv()
print("DB_HOST =", os.getenv("DB_HOST"))

# ==========================================
# Flask App Configuration
# ==========================================

app = Flask(__name__)
app.secret_key = "secret123"

# ==========================================
# Email Configuration
# ==========================================

EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

# ==========================================
# Database Configuration
# ==========================================

DB_HOST = os.getenv("DB_HOST")
DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_PORT = os.getenv("DB_PORT")

# ==========================================
# Database Connection
# ==========================================

def get_connection():

    return psycopg2.connect(

        host=DB_HOST,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
        port=DB_PORT,
        sslmode="require"

    )

# ==========================================
# Get Location using IP Address
# ==========================================

def get_location(ip):

    try:

        if ip == "127.0.0.1":
            return "Localhost", "Local"

        response = requests.get(
            f"http://ip-api.com/json/{ip}",
            timeout=3
        )

        data = response.json()

        if data["status"] == "success":

            return data["country"], data["city"]

    except Exception:

        pass

    return "Unknown", "Unknown"

# ==========================================
# Send Security Alert Email
# ==========================================

def send_security_alert(receiver_email, subject, message):

    try:

        email = EmailMessage()

        email["Subject"] = subject
        email["From"] = EMAIL_ADDRESS
        email["To"] = receiver_email

        email.set_content(message)

        with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=10) as smtp:

            smtp.login(
                EMAIL_ADDRESS,
                EMAIL_PASSWORD
            )

            smtp.send_message(email)

    except Exception as e:

        print("EMAIL ERROR :", e)

# ==========================================
# Threat Level Calculator
# ==========================================

def threat_level(failed, sql):

    if failed >= 10 or sql >= 5:

        return "HIGH", "#EF4444"

    elif failed >= 5 or sql >= 2:

        return "MEDIUM", "#F59E0B"

    else:

        return "LOW", "#22C55E"

# ==========================================
# SQL Injection Keywords
# ==========================================

SQL_KEYWORDS = [

    "'",

    "--",

    ";",

    "/*",

    "*/",

    "DROP",

    "SELECT",

    "INSERT",

    "DELETE",

    "UPDATE",

    "UNION",

    "OR 1=1",

    "AND 1=1"

]

# ==========================================# 
# Login Route
# ==========================================

@app.route("/", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        user_input = (username + " " + password).upper()

        # ==========================================
        # SQL Injection Detection
        # ==========================================

        for keyword in SQL_KEYWORDS:

            if keyword.upper() in user_input:

                ip = request.remote_addr or "Unknown"

                country, city = get_location(ip)

                conn = get_connection()
                cur = conn.cursor()

                cur.execute("""
                    INSERT INTO login_logs
                    (
                        username,
                        status,
                        ip_address,
                        browser,
                        operating_system,
                        device_type,
                        country,
                        city,
                        attack_type
                    )
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """, (
                    username,
                    "FAILED",
                    ip,
                    "Unknown",
                    "Unknown",
                    "Unknown",
                    country,
                    city,
                    "SQL Injection Attempt"
                ))

                conn.commit()

                cur.close()
                conn.close()

                return render_template(
                    "login.html",
                    error="SQL Injection Detected!"
                )

        # ==========================================
        # Collect User Information
        # ==========================================

        ip = request.remote_addr or "Unknown"

        country, city = get_location(ip)

        ua = parse(
            request.headers.get("User-Agent", "")
        )

        browser = ua.browser.family
        operating_system = ua.os.family

        if ua.is_mobile:
            device = "Mobile"

        elif ua.is_tablet:
            device = "Tablet"

        else:
            device = "Desktop"

        # ==========================================
        # Database Connection
        # ==========================================

        conn = get_connection()
        cur = conn.cursor()

        # ==========================================
        # Check Username & Password
        # ==========================================

        cur.execute("""
            SELECT *
            FROM login
            WHERE username=%s AND password=%s
        """, (
            username,
            password
        ))

        user = cur.fetchone()

        # ==========================================
        # Login Success
        # ==========================================

        if user:

            cur.execute("""
                INSERT INTO login_logs
                (
                    username,
                    status,
                    ip_address,
                    browser,
                    operating_system,
                    device_type,
                    country,
                    city,
                    attack_type
                )
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """, (
                username,
                "SUCCESS",
                ip,
                browser,
                operating_system,
                device,
                country,
                city,
                "Normal Login"
            ))

            conn.commit()

            # ==========================================
            # Send Login Success Email
            # ==========================================

            if len(user) >= 4 and user[3]:

                send_security_alert(
                    user[3],
                    "Login Success Alert",
                    f"""
Your account was logged in successfully.

Username : {username}

IP Address : {ip}

Browser : {browser}

Operating System : {operating_system}

Device : {device}

Country : {country}

City : {city}
"""
                )

            cur.close()
            conn.close()

            session["user"] = username

            return redirect("/dashboard")

        # ==========================================
        # Failed Login
        # ==========================================

        cur.execute("""
            INSERT INTO login_logs
            (
                username,
                status,
                ip_address,
                browser,
                operating_system,
                device_type,
                country,
                city,
                attack_type
            )
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (
            username,
            "FAILED",
            ip,
            browser,
            operating_system,
            device,
            country,
            city,
            "Invalid Login"
        ))

        conn.commit()

        # ==========================================
        # Get User Email Using Username
        # ==========================================

        cur.execute(
            "SELECT email FROM login WHERE username=%s",
            (username,)
        )

        email_data = cur.fetchone()

        # ==========================================
        # Send Failed Login Email
        # ==========================================

        if email_data and email_data[0]:

            send_security_alert(
                email_data[0],
                "Failed Login Alert",
                f"""
A failed login attempt was detected.

Username : {username}

IP Address : {ip}

Browser : {browser}

Operating System : {operating_system}

Device : {device}

Country : {country}

City : {city}
"""
            )

        cur.close()
        conn.close()

        return render_template(
            "login.html",
            error="Invalid Username or Password"
        )

    # ==========================================
    # GET Request
    # ==========================================

    return render_template("login.html")

        # ==========================================
        # Send Failed Login Email
        # ==========================================

        
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():

    if request.method == "POST":

        email = request.form["email"]
        otp = random.randint(100000,999999)

        session["reset_email"] = email
        session["otp"] = str(otp)

        send_security_alert(
        email,
        "Cyber Security Command Center - Password Reset OTP",
        f"Your OTP for password reset is: {otp}"
        )

        flash("OTP has been sent to your registered email.", "success")

        return redirect(url_for("verify_otp"))

    return render_template("forgot_password.html")
@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():

    if request.method == "POST":

        user_otp = request.form["otp"]

        if user_otp == session.get("otp"):

            return redirect(url_for("reset_password"))

        flash("Invalid OTP", "danger")

    return render_template("verify_otp.html")
conn = get_connection()
cur = conn.cursor()

cur.execute("SELECT current_database();")
print("Current DB:", cur.fetchone())

cur.execute("""
SELECT table_name
FROM information_schema.tables
WHERE table_schema='public';
""")

print("Tables:", cur.fetchall())
@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():

    if request.method == "POST":

        password = request.form["password"]
        confirm = request.form["confirm_password"]

        if password != confirm:
            flash("Passwords do not match")
            return redirect(url_for("reset_password"))

        conn = get_connection()
        cur = conn.cursor()

        cur.execute(
            "UPDATE login SET password=%s WHERE email=%s",
            (password, session["reset_email"])
        )

        conn.commit()

        cur.close()
        conn.close()

        session.pop("otp", None)
        session.pop("reset_email", None)

        flash("Password Reset Successfully")

        return redirect(url_for("login"))

    return render_template("reset_password.html")


# ==========================================
# Dashboard Route
# ==========================================

@app.route("/dashboard")
def dashboard():

    if "user" not in session:
        return redirect("/")

    conn = get_connection()
    cur = conn.cursor()

    # Total Students
    cur.execute("SELECT COUNT(*) FROM students")
    student_count = cur.fetchone()[0]

    # Total Login Logs
    cur.execute("SELECT COUNT(*) FROM login_logs")
    log_count = cur.fetchone()[0]
    # ==========================
    # Recent Activities
    # ==========================

    cur.execute("""
    SELECT username,
           status,
           login_time
    FROM login_logs
    ORDER BY login_time DESC
    LIMIT 6
    """)

    recent_logs = cur.fetchall()
    cur.execute(
        "SELECT COUNT(*) FROM login_logs WHERE status='FAILED'"
    )
    threat_count = cur.fetchone()[0]

    # ==========================
    # Threat Level
    # ==========================

    if threat_count == 0:
        threat_level = "Low"
    elif threat_count <= 5:
        threat_level = "Medium"
    else:
        threat_level = "High"

    # ==========================
    # Database Status
    # ==========================

    try:
        test_conn = get_connection()
        test_conn.close()
        db_status = "Connected"
    except:
        db_status = "Disconnected"

    cur.close()
    conn.close()

    return render_template(
        "dashboard.html",
        student_count=student_count,
        log_count=log_count,
        threat_count=threat_count,
        username=session["user"],
        db_status=db_status,
        threat_level=threat_level,
        recent_logs=recent_logs
    )
@app.route("/digital-twin")
def digital_twin():

    if "user" not in session:
        return redirect("/")

    conn = get_connection()
    cur = conn.cursor()

    # Total Login Logs
    cur.execute("SELECT COUNT(*) FROM login_logs")
    total_logs = cur.fetchone()[0]

    # Successful Logins
    cur.execute("SELECT COUNT(*) FROM login_logs WHERE status='SUCCESS'")
    success_logs = cur.fetchone()[0]

    # Failed Logins
    cur.execute("SELECT COUNT(*) FROM login_logs WHERE status='FAILED'")
    failed_logs = cur.fetchone()[0]

    # SQL Injection Attempts
    cur.execute("""
        SELECT COUNT(*)
        FROM login_logs
        WHERE attack_type='SQL Injection Attempt'
    """)
    sql_attacks = cur.fetchone()[0]

    # Threat Level
    level, color = threat_level(failed_logs, sql_attacks)

    # Latest Login
    cur.execute("""
        SELECT username,
               ip_address,
               browser,
               operating_system,
               device_type,
               country,
               city,
               login_time
        FROM login_logs
        ORDER BY id DESC
        LIMIT 1
    """)
    latest_login = cur.fetchone()

    # Recent Login Logs
    cur.execute("""
        SELECT username,
               status,
               ip_address,
               login_time
        FROM login_logs
        ORDER BY id DESC
        LIMIT 5
    """)
    recent_logs = cur.fetchall()

    cur.close()
    conn.close()

    return render_template(
        "digital_twin.html",
        username=session["user"],
        total_logs=total_logs,
        success_logs=success_logs,
        failed_logs=failed_logs,
        sql_attacks=sql_attacks,
        latest_login=latest_login,
        recent_logs=recent_logs,
        threat_level=level,
        threat_color=color
    )


# ==========================================
# Admin Route
# ==========================================

@app.route("/admin")
def admin():

    if "user" not in session:
        return redirect("/")

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT id,
               username,
               status,
               ip_address,
               browser,
               operating_system,
               device_type,
               country,
               city,
               attack_type,
               login_time
        FROM login_logs
        ORDER BY id DESC
    """)

    logs = cur.fetchall()

    cur.close()
    conn.close()

    return render_template(
        "admin.html",
        logs=logs
    )


# ==========================================
# Students Route
# ==========================================

@app.route("/students")
def students():

    if "user" not in session:
        return redirect("/")

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT id,
               reg_no,
               name,
               father,
               mother,
               blood_group,
               address,
               phone,
               email,
               department,
               year,
               age
        FROM students
        ORDER BY id
    """)

    students = cur.fetchall()

    cur.close()
    conn.close()

    return render_template(
        "students.html",
        students=students
    )
@app.route("/add-student", methods=["GET", "POST"])
def add_student():

    if request.method == "POST":

        reg_no = request.form["reg_no"]
        name = request.form["name"]
        father = request.form["father"]
        mother = request.form["mother"]
        blood_group = request.form["blood_group"]
        address = request.form["address"]
        phone = request.form["phone"]
        email = request.form["email"]
        department = request.form["department"]
        year = request.form["year"]
        age = request.form["age"]

        conn = get_connection()
        cur = conn.cursor()

        cur.execute("""
            INSERT INTO students
            (reg_no, name, father, mother, blood_group,
             address, phone, email, department, year, age)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            reg_no,
            name,
            father,
            mother,
            blood_group,
            address,
            phone,
            email,
            department,
            year,
            age
        ))

        conn.commit()
        cur.close()
        conn.close()

        return redirect(url_for("students"))

    return render_template("add_student.html")
@app.route("/view-student/<int:id>")
def view_student(id):

    if "user" not in session:
        return redirect("/")

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT id,
               reg_no,
               name,
               father,
               mother,
               blood_group,
               address,
               phone,
               email,
               department,
               year,
               age
        FROM students
        WHERE id=%s
    """, (id,))

    student = cur.fetchone()

    cur.close()
    conn.close()

    return render_template(
        "view_student.html",
        student=student
    )
@app.route("/edit-student/<int:id>", methods=["GET", "POST"])
def edit_student(id):

    if "user" not in session:
        return redirect("/")

    conn = get_connection()
    cur = conn.cursor()

    if request.method == "POST":

        reg_no = request.form["reg_no"]
        name = request.form["name"]
        father = request.form["father"]
        mother = request.form["mother"]
        blood_group = request.form["blood_group"]
        address = request.form["address"]
        phone = request.form["phone"]
        email = request.form["email"]
        department = request.form["department"]
        year = request.form["year"]
        age = request.form["age"]
        print("reg_no      :", reg_no)
        print("name        :", name)
        print("father      :", father)
        print("mother      :", mother)
        print("blood_group :", blood_group)
        print("address     :", address)
        print("phone       :", phone)
        print("email       :", email)
        print("department  :", department)
        print("year        :", year)
        print("age         :", age)
      
        cur.execute("""
            UPDATE students
            SET reg_no=%s,
                name=%s,
                father=%s,
                mother=%s,
                blood_group=%s,
                address=%s,
                phone=%s,
                email=%s,
                department=%s,
                year=%s,
                age=%s
            WHERE id=%s
        """, (
            reg_no,
            name,
            father,
            mother,
            blood_group,
            address,
            phone,
            email,
            department,
            year,
            age,
            id
        ))

        conn.commit()

        cur.close()
        conn.close()

        return redirect(url_for("students"))

    cur.execute("""
        SELECT id,
               reg_no,
               name,
               father,
               mother,
               blood_group,
               address,
               phone,
               email,
               department,
               year,
               age
        FROM students
        WHERE id=%s
    """, (id,))

    student = cur.fetchone()

    cur.close()
    conn.close()

    return render_template(
        "edit_student.html",
        student=student
    )
@app.route("/delete-student/<int:id>")
def delete_student(id):

    if "user" not in session:
        return redirect("/")

    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        "DELETE FROM students WHERE id=%s",
        (id,)
    )

    conn.commit()

    cur.close()
    conn.close()

    return redirect(url_for("students"))
# ==========================================# 
# Generate PDF Report
# ==========================================

@app.route("/report")
def report():

    if "user" not in session:
        return redirect("/")

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT username,
               status,
               ip_address,
               browser,
               operating_system,
               device_type,
               country,
               city,
               attack_type,
               login_time
        FROM login_logs
        ORDER BY id DESC
    """)

    logs = cur.fetchall()

    cur.close()
    conn.close()

    pdf = SimpleDocTemplate(
        "Security_Report.pdf",
        pagesize=letter
    )

    data = [[
        "Username",
        "Status",
        "IP Address",
        "Browser",
        "Operating System",
        "Device",
        "Country",
        "City",
        "Attack Type",
        "Login Time"
    ]]

    for row in logs:

        data.append([
            str(row[0]),
            str(row[1]),
            str(row[2]),
            str(row[3]),
            str(row[4]),
            str(row[5]),
            str(row[6]),
            str(row[7]),
            str(row[8]),
            str(row[9])
        ])

    table = Table(data)

    table.setStyle(TableStyle([

        ("BACKGROUND", (0,0), (-1,0), colors.darkblue),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),

        ("GRID", (0,0), (-1,-1), 1, colors.black),

        ("BACKGROUND", (0,1), (-1,-1), colors.beige),

        ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),

        ("FONTSIZE", (0,0), (-1,-1), 8),

        ("BOTTOMPADDING", (0,0), (-1,0), 8)

    ]))

    pdf.build([table])

    return send_file(
        "Security_Report.pdf",
        as_attachment=True
    )


# ==========================================
# Logout
# ==========================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect("/")


# ==========================================
# Test Email
# ==========================================

@app.route("/test-email")
def test_email():

    send_security_alert(
        EMAIL_ADDRESS,

        "SMTP Test",

        "This is a test email from Cloud Cyber Security Digital Twin."

    )

    return "Test Email Sent Successfully!"


# ==========================================
# Run Flask Application
# ==========================================

if __name__ == "__main__":

    app.run(
        debug=True
    )