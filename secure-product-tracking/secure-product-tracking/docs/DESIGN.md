# Design notes

## Event model
Inspired by the GS1 EPCIS idea that each supply-chain event answers *what, where,
when, why* (and who). My event fields: `product_id` (what), `location` (where),
`timestamp` (when), `action` (why / business step), `actor` (who), plus `note`.

## Why a global chain and not one chain per product?
One chain for the whole database means deleting or reordering events anywhere
shows up as a broken link. Per-product chains are simpler but an attacker could
cleanly cut out one whole product's history. Cost: verification walks all events
(measured: ~273 ms for ~2000 events; grows linearly).

## Why both hash and signature?
- Hash chain: detects edits and deletions made without the actor's key.
- Signature: proves WHICH actor created the event. If an attacker edits an event
  and recomputes the hashes, the old signature no longer matches.

## Why not encrypt events with Caesar / substitution?
Experiment 1 shows both are broken by frequency analysis. They also give secrecy,
not integrity: a changed ciphertext is not detected. Integrity needs hashes/MACs/signatures.

## Threat model (summary)
| Threat | Defence | Residual risk |
|---|---|---|
| Edit an old record | event hash + chain link | none if DB keys are safe |
| Edit and recompute hashes | Ed25519 signature | attacker who also steals the actor's private key |
| Delete a middle record | broken prev_hash link | - |
| Delete latest records | external anchor hash | needs anchor kept outside DB |
| Fake product label | HMAC label code (secret on server) | label copying (clone of a real label) |
| Unauthorised user action | RBAC + state machine | compromised account |
| Stolen password DB | PBKDF2-HMAC-SHA256, per-user salt, 200k rounds | weak passwords |
| Forged / replayed token | HMAC signature + expiry | token theft within 15 min |

## Web layer (app.py)
- Flask pages call the same `TrackingService` used by the command line.
- Login stores the HMAC token in a signed session cookie (HttpOnly, SameSite=Lax, Secure when PRODUCTION=1).
- Every form has a CSRF token. Responses carry security headers (CSP, X-Frame-Options, nosniff).
- Login is locked for 60 seconds after 5 wrong attempts (kept in memory, so one server process only).
- The tamper demo works on an in-memory copy of the database, never on the real one.
- Writes use `BEGIN IMMEDIATE` plus a lock so two users cannot add an event at the same instant and fork the chain.
