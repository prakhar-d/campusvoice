CAMPUSVOICE - student and teacher feedback website (Python + Flask + SQLite)

RUN ON YOUR LAPTOP
1. Install Python 3 from python.org (tick "Add python.exe to PATH").
2. Open a terminal in this folder and run:  py -m pip install flask
3. Then run:  py app.py
4. Open http://127.0.0.1:5000 and create the ADMIN account (first time only).

FIRST SETUP (as admin)
1. "Teachers & students" -> add your teachers (email + password).
2. The class list (61 students) is already loaded. To add more names, use "Paste many names at once".
3. Students open the site, register by choosing their name, and start giving feedback.

WHO SEES WHAT
- Feedback about a teacher is anonymous to the teacher.
- Feedback about a student shows the teacher's name, or "A classmate" for peers.
- Only the admin sees who wrote what, and can hide or delete any feedback.

CHANGE THE SITE NAME: open app.py and edit  SITE_NAME = os.environ.get("SITE_NAME", "CampusVoice")

PUT IT ONLINE FREE (PythonAnywhere)
1. Sign up at pythonanywhere.com (free Beginner account).
2. Files tab -> upload the zip. Consoles -> Bash -> run:  unzip campusvoice.zip
3. Web tab -> Add a new web app -> Manual configuration -> Python 3.12 (or latest shown).
4. Set "Source code" and "Working directory" to  /home/YOURNAME/campusvoice
5. Open the WSGI configuration file, delete everything, paste (change YOURNAME):
      import sys
      path = '/home/YOURNAME/campusvoice'
      if path not in sys.path: sys.path.insert(0, path)
      from app import app as application
6. Click the green Reload button.
7. Open your site and create the admin account FIRST, then share the link.
