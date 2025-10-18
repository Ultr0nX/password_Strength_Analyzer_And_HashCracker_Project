# make_hashes.py
import hashlib, bcrypt, sys, os
from argon2 import PasswordHasher

def md5_hash(pw):
    return hashlib.md5(pw.encode()).hexdigest()

def sha256_hash(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def bcrypt_hash(pw):
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

def argon2_hash(pw):
    ph = PasswordHasher()
    return ph.hash(pw)

if __name__ == "__main__":
    example_pw = "sunil123"  # change this to any test password you want
    print("MD5  :", md5_hash(example_pw))
    print("SHA256:", sha256_hash(example_pw))
    print("bcrypt:", bcrypt_hash(example_pw))
    print("argon2:", argon2_hash(example_pw))
