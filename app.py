import os, csv, io, json, secrets, time, smtplib
import psycopg2
from psycopg2.extras import RealDictCursor
from email.message import EmailMessage
from functools import wraps
from flask import (Flask, render_template, request, redirect, url_for,
                   session, flash, g, Response, abort)
from werkzeug.security import generate_password_hash, check_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))

# Use the Database URL from Render Environment Variables
DB_URL = os.environ.get("DATABASE_URL")

# --- EMAIL CONFIGURATION FOR OTP ---
SMTP_SERVER = os.environ.get("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", 465))
SMTP_EMAIL = os.environ.get("SMTP_EMAIL")       
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD") 

def send_otp_email(to_email, otp):
    if not SMTP_EMAIL or not SMTP_PASSWORD:
        print(f"\n{'='*40}\n[TEST MODE] OTP for {to_email}: {otp}\n{'='*40}\n")
        return
    try:
        msg = EmailMessage()
        msg.set_content(f"Your password reset OTP is: {otp}\n\nThis code expires in 10 minutes.")
        msg['Subject'] = "Password Reset - CampusVoice"
        msg['From'] = SMTP_EMAIL
        msg['To'] = to_email
        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as smtp:
            smtp.login(SMTP_EMAIL, SMTP_PASSWORD)
            smtp.send_message(msg)
    except Exception as e:
        print("Failed to send email:", e)

def get_secret():
    if os.environ.get("SECRET_KEY"):
        return os.environ["SECRET_KEY"]
    p = os.path.join(BASE, "secret.key")
    if not os.path.exists(p):
        with open(p, "w") as f:
            f.write(secrets.token_hex(32))
    with open(p) as f:
        return f.read().strip()

app = Flask(__name__)
app.secret_key = get_secret()
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  PERMANENT_SESSION_LIFETIME=7200)

# ---------- database ----------
def db():
    if "db" not in g:
        # Connect to PostgreSQL instead of SQLite
        g.db = psycopg2.connect(DB_URL, cursor_factory=RealDictCursor)
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    d = g.pop("db", None)
    if d:
        d.close()

def init_db():
    if not DB_URL:
        print("WARNING: DATABASE_URL is not set. Database will not work.")
        return
    
    c = db()
    cur = c.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id SERIAL PRIMARY KEY, name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'student');
    CREATE TABLE IF NOT EXISTS roster(
        id SERIAL PRIMARY KEY, name TEXT NOT NULL,
        user_id INTEGER UNIQUE REFERENCES users(id) ON DELETE SET NULL);
    CREATE TABLE IF NOT EXISTS reviews(
        id SERIAL PRIMARY KEY,
        giver_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        giver_role TEXT NOT NULL,
        kind TEXT NOT NULL CHECK(kind IN ('student')),
        target_id INTEGER NOT NULL, subject TEXT, scores TEXT NOT NULL, avg REAL,
        comment TEXT, hidden INTEGER DEFAULT 0, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(giver_id, kind, target_id));
    CREATE TABLE IF NOT EXISTS password_resets(
        email TEXT PRIMARY KEY, otp TEXT, expiry REAL);
    """)
    
    rp = os.path.join(BASE, "roster.txt")
    if os.path.exists(rp):
        cur.execute("SELECT 1 FROM roster LIMIT 1")
        if not cur.fetchone():
            with open(rp, encoding="utf-8") as f:
                for n in f:
                    if n.strip():
                        cur.execute("INSERT INTO roster(name) VALUES(%s)", (n.strip(),))
    
    em, pw = os.environ.get("ADMIN_EMAIL"), os.environ.get("ADMIN_PASSWORD")
    if em and pw:
        cur.execute("SELECT 1 FROM users WHERE role='admin'")
        if not cur.fetchone():
            cur.execute("INSERT INTO users(name,email,password_hash,role) VALUES('Admin',%s,%s,'admin')",
                      (em.lower(), generate_password_hash(pw)))
    c.commit()
    cur.close()

def admin_exists():
    cur = db().cursor()
    cur.execute("SELECT 1 FROM users WHERE role='admin'")
    res = cur.fetchone()
    cur.close()
    return res is not None

# ---------- security helpers ----------
def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(16)
    return session["_csrf"]

app.jinja_env.globals["csrf_token"] = csrf_token
ATTEMPTS = {}

def too_many_attempts():
    now, ip = time.time(), request.remote_addr
    ATTEMPTS[ip] = [t for t in ATTEMPTS.get(ip, []) if now - t < 600]
    return len(ATTEMPTS[ip]) >= 8

@app.before_request
def protect_forms():
    if request.method == "POST":
        if not secrets.compare_digest(request.form.get("_csrf", ""), session.get("_csrf", "none")):
            abort(400)

@app.after_request
def headers(r):
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["X-Frame-Options"] = "DENY"
    r.headers["Cache-Control"] = "no-store"
    return r

def login_required(*roles):
    def deco(f):
        @wraps(f)
        def wrapper(*a, **k):
            if "uid" not in session:
                flash("Please sign in to continue.", "error")
                return redirect(url_for("login"))
            if roles and session.get("role") not in roles:
                return redirect(url_for("home"))
            return f(*a, **k)
        return wrapper
    return deco

# ---------- public pages & auth ----------
@app.route("/")
def home():
    if not admin_exists():
        return redirect(url_for("setup"))
    if "uid" not in session:
        return redirect(url_for("login"))
    return redirect(url_for("admin" if session["role"] == "admin" else "dash"))

@app.route("/setup", methods=["GET", "POST"])
def setup():
    if admin_exists():
        return redirect(url_for("login"))
    if request.method == "POST":
        n, e, p = request.form["name"].strip(), request.form["email"].strip().lower(), request.form["password"]
        if not n or "@" not in e or len(p) < 8:
            flash("Enter a name, a valid email and a password of 8+ characters.", "error")
        else:
            c = db(); cur = c.cursor()
            cur.execute("INSERT INTO users(name,email,password_hash,role) VALUES(%s,%s,%s,'admin')",
                         (n, e, generate_password_hash(p)))
            c.commit(); cur.close()
            flash("Admin account created. Please sign in.", "ok")
            return redirect(url_for("login"))
    return render_template("setup.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    c = db(); cur = c.cursor()
    cur.execute("SELECT id,name FROM roster WHERE user_id IS NULL ORDER BY name")
    free = cur.fetchall()
    if request.method == "POST":
        e, p = request.form["email"].strip().lower(), request.form["password"]
        rid = request.form.get("roster_id", type=int) or 0
        cur.execute("SELECT * FROM roster WHERE id=%s AND user_id IS NULL", (rid,))
        row = cur.fetchone()
        if not row or "@" not in e or len(p) < 8:
            flash("Choose your name, enter a valid email and a password of 8+ characters.", "error")
        else:
            cur.execute("SELECT 1 FROM users WHERE email=%s", (e,))
            if cur.fetchone():
                flash("This email is already registered.", "error")
            else:
                cur.execute("INSERT INTO users(name,email,password_hash,role) VALUES(%s,%s,%s,'student') RETURNING id",
                            (row["name"], e, generate_password_hash(p)))
                uid = cur.fetchone()["id"]
                cur.execute("UPDATE roster SET user_id=%s WHERE id=%s", (uid, rid))
                c.commit()
                flash("Account created. You can sign in now.", "ok")
                return redirect(url_for("login"))
    cur.close()
    return render_template("register.html", free=free)

@app.route("/login", methods=["GET", "POST"])
def login():
    if not admin_exists():
        return redirect(url_for("setup"))
    if request.method == "POST":
        if too_many_attempts():
            flash("Too many attempts. Please wait 10 minutes.", "error")
            return render_template("login.html")
        c = db(); cur = c.cursor()
        cur.execute("SELECT * FROM users WHERE email=%s", (request.form["email"].strip().lower(),))
        u = cur.fetchone()
        cur.close()
        if u and check_password_hash(u["password_hash"], request.form["password"]):
            session.clear()
            session.permanent = True
            session.update(uid=u["id"], name=u["name"], role=u["role"])
            return redirect(url_for("home"))
        ATTEMPTS.setdefault(request.remote_addr, []).append(time.time())
        flash("Incorrect email or password.", "error")
    return render_template("login.html")

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        c = db(); cur = c.cursor()
        cur.execute("SELECT * FROM users WHERE email=%s", (email,))
        if cur.fetchone():
            otp = str(secrets.randbelow(900000) + 100000)
            expiry = time.time() + 600
            cur.execute("""INSERT INTO password_resets(email, otp, expiry) VALUES(%s,%s,%s) 
                           ON CONFLICT (email) DO UPDATE SET otp=EXCLUDED.otp, expiry=EXCLUDED.expiry""",
                         (email, otp, expiry))
            c.commit()
            send_otp_email(email, otp)
            flash("An OTP has been sent to your email.", "ok")
            cur.close()
            return redirect(url_for("reset_password", email=email))
        cur.close()
        flash("If an account with that email exists, an OTP has been sent.", "ok")
    return render_template("forgot_password.html")

@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    email = request.args.get("email") or request.form.get("email")
    if not email: return redirect(url_for("forgot_password"))
    
    if request.method == "POST":
        otp = request.form.get("otp", "").strip()
        new_pw = request.form.get("password", "")
        
        c = db(); cur = c.cursor()
        cur.execute("SELECT * FROM password_resets WHERE email=%s", (email,))
        row = cur.fetchone()
        
        if not row or row["otp"] != otp:
            flash("Invalid OTP code.", "error")
        elif time.time() > row["expiry"]:
            flash("This OTP has expired. Please request a new one.", "error")
        elif len(new_pw) < 8:
            flash("Password must be at least 8 characters.", "error")
        else:
            cur.execute("UPDATE users SET password_hash=%s WHERE email=%s",
                         (generate_password_hash(new_pw), email))
            cur.execute("DELETE FROM password_resets WHERE email=%s", (email,))
            c.commit()
            cur.close()
            flash("Password reset successfully. You can now sign in.", "ok")
            return redirect(url_for("login"))
        cur.close()
    return render_template("reset_password.html", email=email)

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))

# ---------- student corner ----------
QUESTIONS = {
    "student": [
        ("Academics", [
            ("s1", "Understands the concepts taught and can apply them"),
            ("s2", "Completes assignments and lab work on time, with good quality"),
            ("s3", "Takes part in class by asking questions and joining discussions"),
            ("s4", "Shows improvement in tests and exams over time")]),
        ("Behaviour and Conduct", [
            ("s5", "Attends regularly and arrives on time"),
            ("s6", "Is respectful towards teachers and classmates"),
            ("s7", "Stays focused and disciplined in class"),
            ("s8", "Works well in a team and helps others"),
            ("s9", "Takes responsibility and shows initiative")])]}
QTEXT = {k: t for g in QUESTIONS.values() for _, items in g for k, t in items}
SITE_NAME = os.environ.get("SITE_NAME", "CampusVoice")
app.jinja_env.globals["SITE_NAME"] = SITE_NAME
app.jinja_env.filters["fromjson"] = json.loads
app.jinja_env.globals.update(QTEXT=QTEXT)

BASE_Q = """SELECT rv.*, g.name giver, g.email giver_email, ro.name target
    FROM reviews rv JOIN users g ON g.id=rv.giver_id
    LEFT JOIN roster ro ON rv.kind='student' AND ro.id=rv.target_id"""

def my_roster_id():
    cur = db().cursor()
    cur.execute("SELECT id FROM roster WHERE user_id=%s", (session["uid"],))
    r = cur.fetchone()
    cur.close()
    return r["id"] if r else None

def people_for(kind):
    uid = session["uid"]
    cur = db().cursor()
    cur.execute("""SELECT o.id, o.name, EXISTS(SELECT 1 FROM reviews r WHERE r.giver_id=%s AND r.kind='student'
             AND r.target_id=o.id) as done FROM roster o WHERE COALESCE(o.user_id,0)!=%s ORDER BY o.name""", (uid, uid))
    res = cur.fetchall()
    cur.close()
    return res

@app.route("/home")
@login_required("student", "teacher")
def dash():
    uid = session["uid"]
    ps = people_for("student")
    stat = (sum(1 for x in ps if x["done"]), len(ps))
    rid = my_roster_id()
    tid = rid or 0
    cur = db().cursor()
    cur.execute("SELECT COUNT(*) as c FROM reviews WHERE kind='student' AND target_id=%s AND hidden=0", (tid,))
    got = cur.fetchone()["c"]
    cur.close()
    return render_template("home.html", s=stat, got=got)

@app.route("/corner/<kind>")
@login_required("student", "teacher")
def corner(kind):
    if kind != 'student': abort(404)
    return render_template("corner.html", kind=kind, people=people_for(kind))

@app.route("/give/<kind>/<int:tid>", methods=["GET", "POST"])
@login_required("student", "teacher")
def give(kind, tid):
    if kind != 'student': abort(404)
    uid = session["uid"]
    c = db(); cur = c.cursor()
    cur.execute("SELECT id,name,user_id FROM roster WHERE id=%s", (tid,))
    target = cur.fetchone()
    
    if not target or target["user_id"] == uid:
        cur.close(); abort(404)
        
    cur.execute("SELECT 1 FROM reviews WHERE giver_id=%s AND kind=%s AND target_id=%s", (uid, kind, tid))
    if cur.fetchone():
        cur.close()
        flash("You have already given feedback to " + target["name"] + ".", "error")
        return redirect(url_for("corner", kind=kind))
        
    if request.method == "POST":
        scores = {k: request.form.get(k, type=int) for k in QTEXT if k[0] == kind[0]}
        if any(v not in (1, 2, 3, 4, 5) for v in scores.values()):
            flash("Please answer every question.", "error")
        else:
            cur.execute("""INSERT INTO reviews(giver_id,giver_role,kind,target_id,subject,scores,avg,comment)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s)""",
                         (uid, session["role"], kind, tid, "",
                          json.dumps(scores), round(sum(scores.values()) / len(scores), 2),
                          request.form.get("comment", "").strip()[:300]))
            c.commit()
            cur.close()
            flash("Thank you! Your feedback for " + target["name"] + " has been submitted.", "ok")
            return redirect(url_for("corner", kind=kind))
    cur.close()
    named = session["role"] == "teacher"
    return render_template("give.html", kind=kind, target=target, groups=QUESTIONS[kind], named=named)

@app.route("/me")
@login_required("student", "teacher")
def inbox():
    kind, tid = "student", my_roster_id() or 0
    cur = db().cursor()
    cur.execute("""SELECT rv.scores, rv.avg, rv.comment,
        CASE rv.giver_role WHEN 'teacher' THEN g.name ELSE 'A classmate' END as label
        FROM reviews rv JOIN users g ON g.id=rv.giver_id
        WHERE rv.kind='student' AND rv.target_id=%s AND rv.hidden=0 ORDER BY rv.id DESC""", (tid,))
    rows = cur.fetchall()
    cur.close()
    
    sums = {}
    for r in rows:
        for k, v in json.loads(r["scores"]).items():
            sums[k] = sums.get(k, 0) + v
    avgs = {k: round(v / len(rows), 1) for k, v in sums.items()}
    overall = round(sum(r["avg"] for r in rows) / len(rows), 1) if rows else None
    return render_template("inbox.html", rows=rows, avgs=avgs, overall=overall,
                           groups=QUESTIONS[kind], kind=kind)

# ---------- admin ----------
@app.route("/admin")
@login_required("admin")
def admin():
    cur = db().cursor()
    cur.execute("SELECT COUNT(*) as c FROM users WHERE role='student'"); students = cur.fetchone()["c"]
    cur.execute("SELECT COUNT(*) as c FROM reviews"); total = cur.fetchone()["c"]
    cur.execute("SELECT ROUND(AVG(avg)::numeric, 1) as a FROM reviews"); avg = cur.fetchone()["a"]
    totals = dict(students=students, total=total, avg=avg)
    
    cur.execute("""SELECT o.name, COUNT(r.id) as n, ROUND(AVG(r.avg)::numeric,1) as avg FROM roster o
        JOIN reviews r ON r.kind='student' AND r.target_id=o.id GROUP BY o.id
        ORDER BY n DESC, avg DESC LIMIT 10""")
    ssum = cur.fetchall()
    
    cur.execute(BASE_Q + " WHERE rv.kind='student' ORDER BY rv.id DESC LIMIT 8")
    recent = cur.fetchall()
    cur.close()
    return render_template("admin.html", totals=totals, ssum=ssum, recent=recent)

@app.route("/admin/feedback")
@login_required("admin")
def adminfb():
    cur = db().cursor()
    cur.execute(BASE_Q + " WHERE rv.kind='student' ORDER BY rv.id DESC")
    rows = cur.fetchall()
    cur.close()
    return render_template("admin_feedback.html", rows=rows)

@app.route("/admin/hide/<int:i>", methods=["POST"])
@login_required("admin")
def hide(i):
    c = db(); cur = c.cursor()
    cur.execute("UPDATE reviews SET hidden=1-hidden WHERE id=%s", (i,))
    c.commit(); cur.close()
    return redirect(request.referrer or url_for("adminfb"))

def safe(v): 
    v = str(v or "")
    return "'" + v if v[:1] in "=+-@" else v

@app.route("/admin/export.csv")
@login_required("admin")
def export():
    out = io.StringIO()
    w = csv.writer(out)
    keys = list(QTEXT)
    w.writerow(["Given by", "Role", "Email", "Feedback about", "Corner"]
               + [QTEXT[k] for k in keys] + ["Average", "Comment", "Hidden", "Date"])
    
    cur = db().cursor()
    cur.execute(BASE_Q + " ORDER BY rv.id DESC")
    for r in cur.fetchall():
        sc = json.loads(r["scores"])
        w.writerow([safe(r["giver"]), r["giver_role"], safe(r["giver_email"]), safe(r["target"]), r["kind"]]
                   + [sc.get(k, "") for k in keys]
                   + [r["avg"], safe(r["comment"]), "yes" if r["hidden"] else "no", r["created_at"].strftime("%Y-%m-%d %H:%M") if r["created_at"] else ""])
    cur.close()
    return Response(out.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=feedback.csv"})

@app.route("/admin/delete/<kind>/<int:i>", methods=["POST"])
@login_required("admin")
def delete(kind, i):
    c = db(); cur = c.cursor()
    if kind == "review":
        cur.execute("DELETE FROM reviews WHERE id=%s", (i,))
    elif kind == "account":
        cur.execute("DELETE FROM users WHERE id=%s AND role='student'", (i,))
    elif kind == "roster":
        cur.execute("DELETE FROM reviews WHERE kind='student' AND target_id=%s", (i,))
        cur.execute("DELETE FROM roster WHERE id=%s", (i,))
    else:
        cur.close(); abort(404)
    c.commit(); cur.close()
    flash("Deleted.", "ok")
    return redirect(request.referrer or url_for("admin"))

@app.route("/admin/people")
@login_required("admin")
def people():
    cur = db().cursor()
    cur.execute("""SELECT r.id, r.name, u.id as uid, u.email FROM roster r
        LEFT JOIN users u ON u.id=r.user_id ORDER BY r.name""")
    roster = cur.fetchall()
    cur.close()
    return render_template("admin_people.html", roster=roster)

@app.route("/admin/roster/add", methods=["POST"])
@login_required("admin")
def add_roster():
    n = request.form["name"].strip()
    if n:
        c = db(); cur = c.cursor()
        cur.execute("INSERT INTO roster(name) VALUES(%s)", (n,))
        c.commit(); cur.close()
        flash("Student added to the class list.", "ok")
    return redirect(url_for("people"))

@app.route("/admin/roster/rename/<int:i>", methods=["POST"])
@login_required("admin")
def rename_roster(i):
    n = request.form["name"].strip()
    if n:
        c = db(); cur = c.cursor()
        cur.execute("UPDATE roster SET name=%s WHERE id=%s", (n, i))
        cur.execute("UPDATE users SET name=%s WHERE id=(SELECT user_id FROM roster WHERE id=%s)", (n, i))
        c.commit(); cur.close()
        flash("Name updated.", "ok")
    return redirect(url_for("people"))

@app.route("/admin/roster/bulk", methods=["POST"])
@login_required("admin")
def bulk_roster():
    names = [n.strip()[:100] for n in request.form["names"].splitlines() if n.strip()][:500]
    c = db(); cur = c.cursor()
    for n in names:
        cur.execute("INSERT INTO roster(name) VALUES(%s)", (n,))
    c.commit(); cur.close()
    flash(str(len(names)) + " names added to the class list.", "ok")
    return redirect(url_for("people"))

with app.app_context():
    init_db()

if __name__ == "__main__":
    app.run(debug=True)