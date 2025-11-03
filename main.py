from flask import Flask, request, render_template, session, redirect, url_for
from dotenv import load_dotenv
import os
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from psycopg2 import IntegrityError, OperationalError
import psycopg2

load_dotenv()
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

google_file = "cyber.json"

google_scopes = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile"
]


app = Flask(__name__)
app.secret_key = "NIGGAS"


conn = psycopg2.connect(
    host=os.getenv("dbhost"),
    user = os.getenv("dbuser"),
    dbname = os.getenv("dbname"),
    port = os.getenv("dbport"),
    password = os.getenv("dbpassword")
    )
cur = conn.cursor()



@app.route("/", methods = ["POST","GET"])
def index():
    if "name" in session:
        return redirect(url_for('dashboard'))
    userAccount = request.form.get("username")
    userPassword = request.form.get("password")
    action = request.form.get("action")


    if request.method == "POST":
        if action == "Sign Up":
            try:
                cur.execute(f"insert into accounts (username, password) values ('{userAccount}', '{userPassword}')")
                conn.commit()

                session["name"] = userAccount
                

                return redirect(url_for('dashboard'))
            
            except IntegrityError as e:
                conn.rollback()
                return f"<script>alert('{userAccount} has been taken. Try Another'); window.location='/'</script>"
            
        if action == "Login":
            cur.execute(f"select password from accounts where username = '{userAccount}'")
            pwd = cur.fetchone()
            if pwd:
                if pwd[0] == userPassword:
                    session["name"] = userAccount
                    session["name"] = userAccount


                    return redirect(url_for("dashboard"))
                else:
                    return "<script>alert('Invalis Username or Password'); window.location='/'</script>"
            else:
                return "<script>alert('Invalis Username or Password'); window.location='/'</script>"
            

    return render_template("index.html")


@app.route("/login")
def login():
    flow = Flow.from_client_secrets_file(
        google_file,
        scopes=google_scopes,
        redirect_uri = "https://cybertech-quiz.onrender.com/authorize"
    )

    aut_url, state = flow.authorization_url()
    return redirect(aut_url)

@app.route("/authorize")
def authorize():
    if "name" in session:
        return redirect(url_for('dashboard'))
    flow = Flow.from_client_secrets_file(
        google_file,
        scopes=google_scopes,
        redirect_uri = "https://cybertech-quiz.onrender.com/authorize"
    )

    flow.fetch_token(authorization_response = request.url)
    creds = flow.credentials
    auth2 = build ("oauth2", 'v2', credentials=creds)
    userinformation = auth2.userinfo().get().execute()

    session["name"] = userinformation.get("name")
    session["picture"] = userinformation.get("picture")
    session["email"] = userinformation.get("email")

    cur.execute(f"select username from accounts where username = '{session["name"]}'")
    data = cur.fetchone()
    

    if not data:
        cur.execute(f"insert into accounts(username, email ) values ('{session["name"]}', '{session["email"]}')")

        conn.commit()

    
    return redirect(url_for('dashboard'))

@app.route("/dashboard")
def dashboard():
    if "name" not in session:
        return redirect(url_for('index'))
    
    username = session.get("name")
    cur.execute(f"select score from accounts where username = '{username}'")
    score = cur.fetchone()[0]
    return render_template("dashboard.html", name = username, score = score)



@app.route("/rank")
def rank():
    username = session.get("name")
    cur.execute(f"select username, score from accounts order by score desc")
    ranks = cur.fetchall()
    return  render_template("rank.html", ranks = ranks)



@app.route("/quiz1", methods = ["POST", "GET"])
def quiz1():
    if "name" not in session:
        return redirect(url_for('index'))
    username = session.get("name")
    cur.execute(f"select quiz1 from accounts where username = '{username}'")
    done_status = cur.fetchone()[0]

    if done_status:
        return "<script>alert('You already Answered this!'); window.location='/dashboard'</script>"

    
    answers = {
        "quiz1": "A",
        "quiz2": "A",
        "quiz3": "B",
        "quiz4": "A",
        "quiz5": "A"
    }
    
    if request.method == "POST":
        score = 0
        for key in answers:
            if request.form.get(key) == answers[key]:
                score += 1
        cur.execute(f"update accounts set score = score + {score}, quiz1 = TRUE where username = '{username}'")
        conn.commit()
        
        return f"<script>alert('Congratulations you got {score} over 5'); window.location='/dashboard'</script>"

    

    return render_template("QUIZ/quiz1.html")




@app.route("/quiz2", methods = ["POST", "GET"])
def quiz2():
    if "name" not in session:
        return redirect(url_for('index'))
    
    username = session.get("name")
    cur.execute(f"select quiz2 from accounts where username = '{username}'")
    done_status = cur.fetchone()[0]

    if done_status:
        return "<script>alert('You already Answered this!'); window.location='/dashboard'</script>"

    
    answers = {
        "quiz1": "A",
        "quiz2": "A",
        "quiz3": "A",
        "quiz4": "A",
        "quiz5": "A"
    }
    
    if request.method == "POST":
        score = 0
        for key in answers:
            if request.form.get(key) == answers[key]:
                score += 1
        cur.execute(f"update accounts set score = score + {score}, quiz2 = TRUE where username = '{username}'")
        conn.commit()
        
        return f"<script>alert('Congratulations you got {score} over 5'); window.location='/dashboard'</script>"
    
    
    

    return render_template("QUIZ/quiz2.html")


@app.route("/quiz3", methods = ["POST","GET"])
def quiz3():
    if "name" not in session:
        return redirect(url_for('index'))
    
    username = session.get("name")
    cur.execute(f"select quiz3 from accounts where username = '{username}'")
    done_status = cur.fetchone()[0]

    if done_status:
        return "<script>alert('You already Answered this!'); window.location='/dashboard'</script>"

    
    answers = {
        "quiz1": "B",
        "quiz2": "B",
        "quiz3": "B",
        "quiz4": "B",
        "quiz5": "B"
    }
    
    if request.method == "POST":
        score = 0
        for key in answers:
            if request.form.get(key) == answers[key]:
                score += 1
        cur.execute(f"update accounts set score = score + {score}, quiz3 = TRUE where username = '{username}'")
        conn.commit()
        
        return f"<script>alert('Congratulations you got {score} over 5'); window.location='/dashboard'</script>"
    
    return render_template("QUIZ/quiz3.html")



@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__  == "__main__":
    port = os.environ.get("PORT", 5000)
    app.run(host="0.0.0.0", port=port)






