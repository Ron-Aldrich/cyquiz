from flask import Flask, redirect, request, url_for, session, render_template
from psycopg2 import IntegrityError, OperationalError
import psycopg2
import os
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build

#os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

app = Flask(__name__)
app.secret_key = "NIGGAS AS THIS"

dbhost = "dpg-d3fmob7diees73audbk0-a.oregon-postgres.render.com"
dbname = "QUIZ"
dbuser = "ron"
dbpassword = "cTwAsx67nMiBNVxgMoaS3Jzmdd8ZHOIA"
dbport = 5432


conn = psycopg2.connect(
    host=dbhost,          
    user=dbuser,          
    dbname=dbname,        
    port=dbport,          
    password=dbpassword   
)

cur = conn.cursor() 

google_file = "cyber.json"

google_scopes = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile"
]

@app.route("/")
def index():
    if "username" in session:
        return redirect(url_for("dashboard"))
    return render_template("index.html")

@app.route("/login")
def login():
    flow = Flow.from_client_secrets_file(
        google_file,
        scopes=google_scopes,
        redirect_uri = "https://cyber-quiz-uo4i.onrender.com/authorize"

    )

    auth_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(auth_url)

@app.route("/authorize")
def authorize():
    flow = Flow.from_client_secrets_file(
        google_file,
        scopes=  google_scopes,
        redirect_uri = "https://cyber-quiz-uo4i.onrender.com/authorize"
    )

    flow.fetch_token(authorization_response=request.url)
    credentials = flow.credentials
    auth2 = build("oauth2", "v2", credentials=credentials)
    urser_info = auth2.userinfo().get().execute()

    session["name"] = urser_info.get("name")
    session["email"] = urser_info.get("email")
    session["picture"] = urser_info.get("picture")
    
    cur.execute(f"select username from accounts where username = '{session["name"]}'")
    data  = cur.fetchone()

    if not data:
        cur.execute(f"insert into accounts (username, password, score, done) values ('{session["name"]}', '', 0, False)")
        conn.commit()

        

    return redirect(url_for("dashboard"))


@app.route("/dashboard")
def dashboard():
    if "name" not in session:
        return redirect(url_for("index"))
    username = session["name"]
    cur.execute(f"select score from accounts where username = '{username}'")
    score = cur.fetchone()[0]

    return render_template("dashboard.html", name = session["name"], email = session["email"], picture = session["picture"], score = score)

@app.route("/logout")
def logout():
    session.clear()
    return render_template("index.html")

@app.route("/quiz", methods = ["POST", "GET"])
def quiz():
    if "name" not in session:
        redirect(url_for('index'))
    username = session["name"]
    cur.execute(f"select done from accounts where username = '{username}'")
    done_status = cur.fetchone()[0]

    if done_status:
        return "<script>alert('You already answered this sorry'); window.location.href='/dashboard' </script>"
    
    if request.method == 'POST':
        score = 0
        

        answers = {
            'q1':  'A',
            'q2':  'A'
        }

        for key in answers:
            if request.form.get(key) == answers[key]:
                score += 1
        cur.execute(f"update accounts set score = score + {score}, done = True where username = '{username}'")
        conn.commit()

        return redirect(url_for("dashboard"))




    return render_template("quiz.html")

@app.route("/quiz2", methods = ["POST", "GET"])
def quiz2():
    if "name" not in session:
        return redirect(url_for("index"))
    
    username = session["name"]
    cur.execute(f"select done2 from accounts where username = '{username}'")
    done_status = cur.fetchone()[0]

    if done_status:
        return "<script>alert('You already Answered this Quiz'); window.location = '/dashboard' </script>"
    
    if request.method == 'POST':
        score = 0
        answer2 = {
            'q1': 'B',
            'q2' : 'A'
        }

        for key in answer2:
            if request.form.get(key) == answer2[key]:
                score += 1

        cur.execute(f"update accounts set score = score + {score}, done2 = True where username = '{username}'")
        conn.commit()
        return redirect(url_for('dashboard'))
    return render_template("quiz2.html")

@app.route("/rank")
def rank():
    cur.execute("select username, score from accounts order by score desc")
    ranklist = cur.fetchall()

    return render_template("rank.html", ranking = ranklist)

if __name__ == "__main__":
    port = os.environ.get("PORT", 5000)
    app.run(host="0.0.0.0", port=port)
