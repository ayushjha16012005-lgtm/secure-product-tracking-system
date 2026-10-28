# START HERE

## What is in this ZIP
- `secure-product-tracking/` - the whole project, ready to run, deploy and push to GitHub (git history included)
  - `app.py` + `templates/` + `static/` = the website
  - `sptrack/` = the security logic (hash chain, signatures, roles)
  - `tests/` = 33 automated tests, `experiments/` = scripts behind the report numbers
  - `README.md` explains the project in simple words, `DEPLOY.md` explains going online
  - `report/` = final PBL report (.docx + PDF, 19 pages with screenshots)
- `START_HERE.md` = this file

## Try it in 2 minutes
```
cd secure-product-tracking
pip install -r requirements.txt
python app.py            # open http://127.0.0.1:5000
```
Demo logins (password `demo1234`): acme_factory, delhi_hub, city_store, auditor, customer1.
Try: log in as acme_factory -> register a product -> note the label code -> open "Verify a product" and use it.
Then open "Tamper demo".

## What I tested, and what I could not
Tested: the website on a local server and through automated tests (all 33 pass, from a fresh clone too).
Not possible from here: creating your GitHub repo, and putting it online on Render/PythonAnywhere
(no GitHub or internet access from my side). `render.yaml`, `Procfile` and `DEPLOY.md` follow the normal
setup for those hosts, but you are the first to run them, so if a step fails, the host's build log will say why.

## Step 1: GitHub repo (5 minutes)
1. github.com -> New repository -> name `secure-product-tracking` -> Public -> do NOT add a README/licence (they exist).
2. In the project folder:
```
git config user.name  "Ayush Jha"
git config user.email "your-github-email"
git rebase -r --root --exec "git commit --amend --reset-author --no-edit"
git remote add origin https://github.com/<your-username>/secure-product-tracking.git
git branch -M main
git push -u origin main
```
(The commits currently carry a placeholder email; the rebase line fixes the author on all of them.)
3. The Actions tab will run the tests automatically (`.github/workflows/tests.yml`).
4. Replace `<your-username>` in README.md and paste the repo link on the report cover page.

## Step 2: put the website online (optional but impressive)
Open `DEPLOY.md`. Render is the easiest: New -> Blueprint -> pick your repo. Add the live link to README and report.

## Step 3: make it yours (important)
Your declaration says AI-generated work gets 0%. The project is real and working, but it only counts as your
work if you understand it and the words are yours.
1. Run the site, the demo (`python demo.py`) and the tests yourself. Take your own screenshots.
2. Read through `sptrack/ledger.py`, `service.py`, `auth.py` and `app.py`. Change a small thing (a role, a location name,
   a rule), re-run the tests, see what breaks. You should be able to explain every file.
3. Rewrite `README.md` sections "Why this project" and "What I found" in your own sentences. Shorter and less polished is fine.
4. In the report, fill the yellow highlighted parts (repo link, date, your own design struggle and conclusion) and reword
   the rest in your voice.
5. Open every reference link and confirm it. The GitHub projects and GS1 page came from a web search; the RFC/NIST/OWASP/
   Stallings entries are standard references I cited from knowledge.
6. Sign the declaration only after all this.

## Two bugs found while testing (good to mention in your viva)
1. A form without a CSRF token was accepted (both sides were empty, so they matched). Fixed and tested.
2. The database connection crashed when the web server used several threads. Fixed with a thread-safe connection,
   a lock and a transaction around writing an event.

## Likely viva questions
1. Why a hash chain? -> Editing an old record changes its hash, which no longer matches the next record.
2. Why also signatures? -> They show who created a record and catch someone who edits and recalculates hashes.
3. Can the admin or DB owner cheat? -> They can edit, but it is detected. They could forge only with the private keys (stored on the same server - a limit).
4. What if the newest records are deleted? -> The chain alone cannot tell. Keep the "anchor" from the Audit page outside the system.
5. Why not Caesar or substitution? -> Experiment 1 breaks them by frequency analysis, and they only hide data, they do not detect changes.
6. HMAC vs digital signature? -> HMAC uses one shared secret (label code, login token). A signature uses a private/public key pair, so anyone can verify.
7. Why PBKDF2 with a salt? -> Slows password guessing and gives different hashes for equal passwords.
8. Can a fake label still work? -> A copied genuine label can; the code only proves the ID is real.
9. What does CSRF protection do? -> Stops another website from making your browser submit a form on this site.
10. What would you improve first? -> Keys on each company's device, QR codes, a real database, checkpoints for faster verification.
