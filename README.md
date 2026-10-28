# Secure Product Tracking System

A small website that follows a product from the factory to the customer and keeps its history safe
from quiet changes. If someone edits an old record, the system notices.

PBL project for **Cryptography (CCSCY0301)**, B.Tech CSE (Cyber Security), NIET Greater Noida.
Student: Ayush Jha. Faculty: Dr. Rashmi Sharma. SDG 9 and SDG 12.



## Why this project

Products pass through many hands: manufacturer, distributor, shop, customer. Each of them writes
records. If those records sit in a normal spreadsheet or database, anyone with access can change
them and nobody can tell. Fake products make this worse, because a fake can copy a product number.
I wanted to see how much of this can be fixed with the cryptography we study in class.

## The idea in simple words

Think of a notebook where every page starts with a fingerprint of the page before it.
If someone rips out or rewrites an old page, the fingerprint on the next page stops matching,
so the change shows. My system does the same thing with computer records:

1. Every step of a product (registered, shipped, received, sold) is saved as a record.
2. Each record contains the SHA-256 hash (the fingerprint) of the record before it. So the records form a chain.
3. The person who adds a record also signs it with their private key. This shows who made it.
4. Every role has its own permissions. A shop cannot create new products, a customer cannot ship anything.
5. Steps must follow the right order. A product cannot be sold before it was received.
6. Each product gets a label code. A fake product with an invented ID will not have a matching code.

## What you can do on the website

| Who | What they can do |
|---|---|
| Manufacturer | register new products, ship them |
| Distributor | receive products, ship them onwards |
| Retailer | receive products, sell them |
| Admin | run the audit (re-checks the whole chain) |
| Customer / anyone | verify a product with its ID and label code, see its history |

There is also a **Tamper demo** page. It makes a temporary copy of the data, edits one old record
in the copy, and shows the check failing. The real data is never touched.


## Run it on your computer

You need Python 3.10 or newer.

```
git clone https://github.com/<your-username>/secure-product-tracking.git
cd secure-product-tracking
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000 in the browser.

On the first start the site creates demo accounts and three sample products.
Password for all of them is `demo1234`:

| Username | Role |
|---|---|
| acme_factory | manufacturer |
| delhi_hub | distributor |
| city_store | retailer |
| auditor | admin |
| customer1 | customer |

To see a full walkthrough in the terminal instead of the website: `python demo.py`


## How the files are arranged

```
app.py            the website (Flask): pages, login, forms
wsgi.py           file used when deploying
templates/        HTML pages
static/           CSS
sptrack/          the real project logic
    ledger.py         the hash chain and the integrity check
    signing.py        digital signatures (Ed25519)
    auth.py           passwords, login token, roles
    service.py        product steps and the rules about order
    crypto_basics.py  Caesar and substitution cipher + how I broke them (Module 1)
    demo_data.py      demo accounts and sample products
    cli.py            same system from the command line
tests/            automated tests (33)
experiments/      scripts for the numbers and graphs in my report
docs/             design notes, references, screenshots
report/           final PBL report
```

## Testing

```
python -m unittest discover -s tests -v
```

The tests check, among other things, that wrong passwords and forged login tokens are rejected,
that each role can only do its own job, that editing or deleting a record is detected, and that
several people writing at the same time do not break the chain.

## What I found in my experiments

(`python experiments/run_experiments.py` runs them again; timings will differ on your computer.)

- I attacked a chain of 300 records 600 times (edit a record, delete a record, edit and recalculate the hash). All 600 were detected.
- Changing one character in a record changes about half of the 256 bits of its SHA-256 hash (average 128).
- The Caesar cipher from Module 1 was broken every time once the text had 40 letters or more, using only letter frequencies.
- My simple attack on the substitution cipher only recovered 16% to 33% of the letters. A smarter attack would do better.
- Even a cipher nobody can break would only hide data. It would not tell us if the data was changed. That is why I used hashes and signatures instead.

## What it cannot do (limits)

- The private keys are stored as files on the same computer as the database. Someone who controls that computer could sign fake records. A real system would keep keys on each company's own device.
- If somebody deletes the newest records, the chain alone cannot show it. The admin page shows an "anchor" (the latest fingerprint). Keep a copy outside the system and the audit can catch this.
- It detects changes, it does not stop them. Anyone with access to the database can still change it.
- A real label can be copied onto a fake product. The label code only proves the product ID is genuine.
- The records are not encrypted, only protected against changes.
- No QR codes or mobile app yet, and it is built for one small server, not for thousands of users.
- The login and token code was written to learn how it works. A real project should use well-reviewed libraries.

## References

- GS1, EPCIS standard (idea of recording what / where / when / why for each product event): https://www.gs1.org/epcis
- GitHub projects I studied for hash-chained logs: [ForgeProof](https://github.com/bxrist/ForgeProof), [nexuscone](https://github.com/Aperintel), [AI-Risk-Based-Inventory-ERP](https://github.com/falltwo/AI-Risk-Based-Inventory-ERP)
- NIST FIPS 180-4 (SHA-256), RFC 8032 (Ed25519), RFC 2104 (HMAC), NIST SP 800-132 (password hashing), OWASP Top 10
- W. Stallings, Cryptography and Network Security (classical ciphers and frequency analysis)

Full list with details is in `docs/REFERENCES.md`. I read these projects to understand the idea and wrote my own code.

## License

MIT
