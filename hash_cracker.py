# hash_cracker.py
import hashlib
import bcrypt
from argon2 import PasswordHasher
import itertools
import sys

def md5_of(s): return hashlib.md5(s.encode()).hexdigest()
def sha256_of(s): return hashlib.sha256(s.encode()).hexdigest()

def load_wordlist(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [w.strip() for w in f if w.strip()]

def mutations(word):
    # small set of mutations: original, capitalize, add 1..3 digits suffix, common leet
    yield word
    yield word.capitalize()
    yield word.upper()
    for d in range(10):
        yield f"{word}{d}"
    for d in range(100):
        yield f"{word}{d}"
    # simple leet subs
    yield word.replace("a","@")
    yield word.replace("o","0")
    yield word.replace("s","$")

def crack_hash(target_hash, alg, wordlist):
    print(f"[+] Cracking {alg} hash: {target_hash}")
    tries = 0
    for w in wordlist:
        for m in mutations(w):
            tries += 1
            if alg == "md5":
                if md5_of(m) == target_hash:
                    return m, tries
            elif alg == "sha256":
                if sha256_of(m) == target_hash:
                    return m, tries
            elif alg == "bcrypt":
                # for bcrypt use bcrypt.checkpw
                if bcrypt.checkpw(m.encode(), target_hash.encode()):
                    return m, tries
            elif alg == "argon2":
                ph = PasswordHasher()
                try:
                    if ph.verify(target_hash, m):
                        return m, tries
                except Exception:
                    pass
    return None, tries

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python hash_cracker.py <alg> <hash> <wordlist>")
        print("example: python hash_cracker.py md5 d41d8cd98f00b204e9800998ecf8427e small.txt")
        sys.exit(1)
    alg = sys.argv[1].lower()
    target = sys.argv[2].strip()
    wfile = sys.argv[3]
    words = load_wordlist(wfile)
    res, tries = crack_hash(target, alg, words)
    if res:
        print(f"[+] Cracked! password = {res} (tries: {tries})")
    else:
        print(f"[-] Not found after {tries} attempts")
