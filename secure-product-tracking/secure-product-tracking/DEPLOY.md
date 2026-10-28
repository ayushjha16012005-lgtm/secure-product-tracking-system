# Putting the website online

The site is a normal Flask app. `wsgi.py` is the file a hosting service runs.
I have only tested it locally (Flask server + automated tests); the steps below are the standard
way these hosts work, so check their current screens if something looks different.

## Option 1: Render (free tier)
1. Push the project to GitHub.
2. On render.com: New + -> Blueprint (or Web Service) -> pick your repo.
   `render.yaml` already has the build and start commands.
3. Wait for the build. Render gives you a link like `https://secure-product-tracking.onrender.com`.

## Option 2: PythonAnywhere
1. Upload the project (or `git clone` it in a Bash console).
2. `pip install --user -r requirements.txt`
3. Web tab -> add a new Flask web app -> in the WSGI file add:
   ```python
   import sys
   sys.path.insert(0, "/home/<username>/secure-product-tracking")
   from wsgi import app as application
   ```
4. Reload the web app.

## Settings (environment variables)
| Name | What it does | Default |
|---|---|---|
| SECRET_KEY | Signs the login cookie. Set a long random value when deploying. | random each start |
| SEED_DEMO | `1` creates the demo accounts and sample products on first start. Set `0` for real use. | 1 |
| DATA_DIR | Folder for the database and keys. | `data` |
| PRODUCTION | `1` makes the cookie HTTPS-only. | off |

## Things to know
- Free hosts often wipe the disk on restart. The demo data is re-created automatically, but anything you add is lost.
  That is fine for a demo. A real system would use a proper database and keep keys somewhere safer.
- Keep `--workers 1`. The login lock-out counter lives in memory and SQLite is meant for a small app.
- The demo accounts all share one password. Turn `SEED_DEMO` off if the site is public for long.
