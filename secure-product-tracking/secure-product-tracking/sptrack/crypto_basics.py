"""
Module 1 material: classical ciphers + hashing basics.

These are written from scratch (Caesar, monoalphabetic substitution) to
understand WHY they are not enough for protecting product records. The real
system uses SHA-256 and Ed25519 instead (see ledger.py and signing.py).
"""
import hashlib
import random
import string
from collections import Counter

ALPHABET = string.ascii_uppercase

# Approximate letter frequency of English text (percent), the standard table
# used in cryptanalysis textbooks (e.g. Stallings, Cryptography and Network
# Security, ch. 2).
ENGLISH_FREQ = {
    "E": 12.7, "T": 9.1, "A": 8.2, "O": 7.5, "I": 7.0, "N": 6.7, "S": 6.3,
    "H": 6.1, "R": 6.0, "D": 4.3, "L": 4.0, "C": 2.8, "U": 2.8, "M": 2.4,
    "W": 2.4, "F": 2.2, "G": 2.0, "Y": 2.0, "P": 1.9, "B": 1.5, "V": 1.0,
    "K": 0.8, "J": 0.15, "X": 0.15, "Q": 0.10, "Z": 0.07,
}


# ---------------------------------------------------------------- Caesar
def caesar_encrypt(text: str, shift: int) -> str:
    out = []
    for ch in text.upper():
        if ch in ALPHABET:
            out.append(ALPHABET[(ALPHABET.index(ch) + shift) % 26])
        else:
            out.append(ch)          # keep digits, spaces, punctuation
    return "".join(out)


def caesar_decrypt(text: str, shift: int) -> str:
    return caesar_encrypt(text, -shift)


def caesar_brute_force(ciphertext: str):
    """Only 25 possible keys, so just try all of them."""
    return {k: caesar_decrypt(ciphertext, k) for k in range(26)}


def _chi_squared(text: str) -> float:
    letters = [c for c in text.upper() if c in ALPHABET]
    n = len(letters)
    if n == 0:
        return float("inf")
    counts = Counter(letters)
    score = 0.0
    for ch in ALPHABET:
        expected = ENGLISH_FREQ[ch] * n / 100
        score += (counts.get(ch, 0) - expected) ** 2 / expected
    return score


def caesar_crack(ciphertext: str) -> int:
    """Pick the shift whose plaintext looks most like English (lowest chi-squared)."""
    best_shift, best_score = 0, float("inf")
    for k, plain in caesar_brute_force(ciphertext).items():
        s = _chi_squared(plain)
        if s < best_score:
            best_shift, best_score = k, s
    return best_shift


# ------------------------------------------------- monoalphabetic substitution
def random_substitution_key(seed=None) -> str:
    rng = random.Random(seed)
    letters = list(ALPHABET)
    rng.shuffle(letters)
    return "".join(letters)


def substitution_encrypt(text: str, key: str) -> str:
    table = {a: b for a, b in zip(ALPHABET, key)}
    return "".join(table.get(c, c) for c in text.upper())


def substitution_decrypt(text: str, key: str) -> str:
    table = {b: a for a, b in zip(ALPHABET, key)}
    return "".join(table.get(c, c) for c in text.upper())


def frequency_attack(ciphertext: str) -> str:
    """
    Very simple attack: rank cipher letters by frequency and map them to
    English letters of the same rank. Not perfect, but on long texts it
    already recovers a large part of the message.
    """
    letters = [c for c in ciphertext.upper() if c in ALPHABET]
    cipher_rank = [c for c, _ in Counter(letters).most_common()]
    cipher_rank += [c for c in ALPHABET if c not in cipher_rank]
    english_rank = sorted(ENGLISH_FREQ, key=ENGLISH_FREQ.get, reverse=True)
    guess = {c: e for c, e in zip(cipher_rank, english_rank)}
    return "".join(guess.get(c, c) for c in ciphertext.upper())


def letter_accuracy(original: str, recovered: str) -> float:
    pairs = [(a, b) for a, b in zip(original.upper(), recovered.upper()) if a in ALPHABET]
    if not pairs:
        return 0.0
    return sum(a == b for a, b in pairs) / len(pairs)


# ------------------------------------------------------------------ hashing
def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def avalanche_bits(a: str, b: str) -> int:
    """Number of differing bits between SHA-256(a) and SHA-256(b) (out of 256)."""
    x = int(sha256_hex(a), 16) ^ int(sha256_hex(b), 16)
    return bin(x).count("1")
