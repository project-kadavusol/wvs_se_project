from flask import Flask, request, render_template, redirect, url_for,make_response,flash,send_file,Response
import pymongo,requests
from bson import ObjectId
import test,port,os,pdff,base64,template
from datetime import datetime
from urllib.parse import urlparse
myclient = pymongo.MongoClient("mongodb+srv://web_vul:web_vul@team20.znx7o.mongodb.net/")
mydb = myclient["wvs"]
mycol=mydb["user_data"]

i_id=''
app = Flask(__name__, template_folder='.')

app.secret_key="We_are_the only_cyber_team"


@app.route('/signup', methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        try:
            mail=request.form.get("email")
            username = request.form.get("username")
            password = request.form.get("password")
            mydict={"email":mail}
            mydict2={"name":username}
            cond=mycol.find_one(mydict)
            cond2=mycol.find_one(mydict2)
            if cond:
                flash("Email already exists","error")        
            elif cond2:
                flash("Username already exists","error")        
            else:
                password_bytes = password.encode("ascii")
                base64_bytes = base64.b64encode(password_bytes)
                base64_string = base64_bytes.decode("ascii")
                mydict = { "email": mail, "name": username, "pass": base64_string }
                mycol.insert_one(mydict)
                return redirect(url_for('login'))
        except Exception as e:
            flash("Counld not reach the server")
    return render_template("html/signup.html")
@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        try:
            username = request.form.get("username")
            password = request.form.get("password")
            password_bytes = password.encode("ascii")
            base64_bytes = base64.b64encode(password_bytes)
            base64_string = base64_bytes.decode("ascii")
            mydict= {"name":username,"pass":base64_string}
            find={"_id"}
            id=mycol.find_one(mydict,find)    
            if id:
                y=list(id.values())
                usr=str(y[0])
                res = make_response(redirect(url_for('home')))
                res.set_cookie("usr", usr, max_age=3600, httponly=True)
                return res
            else:
                flash("USERNAME OR PASSWORD IS INVALID.","error")
                return render_template("html/index.html")
        except Exception as e:
            flash("Counld not reach the server")
    return render_template("html/index.html")

@app.route('/')
def home():
   return render_template("html/home_page.html")

@app.route('/scan',methods=['GET','POST'])
def scan():
        usr=request.cookies.get("usr")
        if usr:
            target=request.form.get("target")
            ping_result=test.ping(target)
            if ping_result.find("Failed")==0:
                port_result="The host is down"
                send_to_file(usr,target,ping_result,port_result)
                return render_template("html/result.html", presult=ping_result,poresult=port_result)
            port_result=port.port_scan(target)
            temp=template.scan_application(target,depth=2)
            send_to_file(usr,target,ping_result,port_result,temp)
            return render_template("html/result.html", presult=ping_result,poresult=port_result,temp_result=temp)
        else:
            flash("Login/Signup to continue")
            return render_template("html/home_page.html")
def send_to_file(usr,ta,r1,r2,tr):
    global i_id
    parsed_url = urlparse(ta)
    domain = parsed_url.hostname if parsed_url.hostname else ta

    if domain.replace('.', '').isdigit():
        t = domain
    else:
        t = domain

    print(tr)
    filename = f"{t}_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt"
    with open(filename, "w") as f:
        f.write(f"Target: {t}\n\n")
        f.write("Ping Result:\n\n")
        f.write(r1 + "\n\n")
        f.write("Port Scan Result:\n\n")
        f.write(r2 + "\n\n")
        if tr:
                    f.write("SSTI Scan Result:\n\n")
                    f.write(tr + "\n\n")

    with open(filename,"rb")as f:
        file_data=f.read()
    if usr:
        user = mycol.find_one({'_id': ObjectId(usr)}, {'_id': 0, 'name': 1})
        if user:
            name = user.get('name')
            col = mydb[name] 

            _id=col.insert_one({
                "target": t,
                "filename": filename,
                "date": datetime.now(),
                "file_data": file_data
            })

            os.remove(filename)
        else:
            return "User not found in the database"
    else:
        return "No cookie found for 'usr'"
    i_id=_id.inserted_id
@app.route('/download_report')
def download_report():
    print(i_id)
    inserted_id=i_id
    usr = request.cookies.get('usr')
    if usr:
        user_data = mycol.find_one({'_id': ObjectId(usr)})
        if user_data:
            col = mydb[user_data['name']]
            scan = col.find_one({"_id": ObjectId(inserted_id)}, {'_id': 0,'file_data': 1,'filename':1})
            
            if scan:
                filename=scan['filename']

                file_path = os.path.join("downloads", filename) 
                os.makedirs("downloads", exist_ok=True)  

                with open(file_path, "wb") as f:
                     f.write(scan['file_data'])
                file_name= pdff.txt_to_pdf(filename)
     
                return send_file(file_name, as_attachment=True)
    
    flash("File not found!", "error")
    return render_template('html/result.html')
'''
@app.route('/result')
def result():
    return render_template('html/result.html')'''

@app.route('/logout')
def logout():
    res = make_response(redirect(url_for('home')))
    res.set_cookie("usr", "", max_age=0, httponly=True)
    res.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    res.headers["Pragma"] = "no-cache"
    res.headers["Expires"] = "0"
    
    return res

name=''
@app.route('/profile')
def profile():
    usr = request.cookies.get('usr')
    if not usr:
        return redirect(url_for('login'))

    data = mycol.find_one({'_id': ObjectId(usr)}, {'_id': 0})
    if data:
        col = mydb[data['name']]
        scan_history = list(col.find({}, {'_id': 0, 'file_data': 0}))
        
        res = make_response(render_template('html/profile.html', data=data, scan_history=scan_history))
        
        # Prevent caching
        res.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        res.headers["Pragma"] = "no-cache"
        res.headers["Expires"] = "0"
        
        return res

    return "<h1>ERROR 404</h1><br><h3>User not found<h3>"

@app.route('/download/<filename>')
def download_scan(filename):
    usr = request.cookies.get('usr')
    if usr:
        user_data = mycol.find_one({'_id': ObjectId(usr)})
        if user_data:
            col = mydb[user_data['name']]
            scan = col.find_one({'filename': filename}, {'_id': 0, 'file_data': 1})
            
            if scan and 'file_data' in scan:

                file_path = os.path.join("downloads", filename) 
                os.makedirs("downloads", exist_ok=True)  

                with open(file_path, "wb") as f:
                     f.write(scan['file_data'])
                file_name= pdff.txt_to_pdf(filename)
     
                return send_file(file_name, as_attachment=True)
    
    flash("File not found!", "error")
    return redirect(url_for('profile'))

@app.route('/delete/<filename>')
def delete_scan(filename):
    usr = request.cookies.get('usr')
    if usr:
        user_data = mycol.find_one({'_id': ObjectId(usr)})
        if user_data:
            col = mydb[user_data['name']]
            result = col.delete_one({'filename': filename})

            if result.deleted_count > 0:
                flash("File deleted successfully!", "success")
            else:
                flash("File not found!", "error")

    return redirect(url_for('profile'))

@app.route("/update",methods=["POST"])
def update_password():
    old_pass=request.form.get("old_pass")
    new_pass=request.form.get("new_pass")
    con_pass=request.form.get("con_pass")
    usr=request.cookies.get("usr")

    if not usr:
        return redirect(url_for('login'))
    password_bytes = old_pass.encode("ascii")
    base64_bytes = base64.b64encode(password_bytes)
    base64_string = base64_bytes.decode("ascii")
    user_data =mycol.find_one({'_id': ObjectId(usr)})
    print(base64_string,user_data["pass"])
    if base64_string != user_data["pass"]:
        flash("The old password doesn't match!", "error")
        return redirect(url_for("profile"))
    if old_pass == new_pass :
        flash("The old password and the new password are same", "error")
        return redirect(url_for("profile"))
    if new_pass != con_pass:
        flash("The new password and confirm password dosen't match", "error")
        return redirect(url_for("profile"))
    password_bytes = new_pass.encode("ascii")
    base64_bytes = base64.b64encode(password_bytes)
    base64_string = base64_bytes.decode("ascii")
    try:
        mycol.update_one({"name": user_data['name']},{'$set':{'pass':base64_string}})
        flash("updated successfully","message")
        return redirect(url_for("logout"))
    except:
        flash("Error while updating","error")

    return redirect(url_for("profile"))


@app.route('/proxy')
def proxy():
    target = request.args.get('target')  # Get the user’s local website
    if not target:
        return "No target provided", 400

    try:
        response = requests.get(target, stream=True)

        return Response(response.iter_content(), status=response.status_code, headers=dict(response.headers))

    except requests.exceptions.RequestException as e:
        return f"Error connecting to {target}: {str(e)}", 500


if __name__ == '__main__':
    app.run( debug=True,port='1234',threaded=True)