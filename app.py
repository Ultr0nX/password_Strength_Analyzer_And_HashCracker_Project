from flask import Flask, render_template, request, jsonify
import os
from password_analyzer import score_password
from hash_cracker import crack_hash, load_wordlist, mutations

app = Flask(__name__)

# Load wordlist once at startup
WORDLIST_PATH = os.path.join(os.path.dirname(__file__), "small.txt")
wordlist = load_wordlist(WORDLIST_PATH)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    password = data.get('password', '')
    
    if not password:
        return jsonify({"error": "No password provided"}), 400
    
    result = score_password(password)
    return jsonify(result)

@app.route('/hash_cracker')
def hash_cracker_page():
    return render_template('hashes.html')

@app.route('/crack', methods=['POST'])
def crack():
    target_hash = request.form.get('hash', '')
    algorithm = request.form.get('algorithm', 'md5')
    
    if not target_hash:
        return render_template('hashes.html', error="No hash provided")
    
    # Validate algorithm
    if algorithm not in ['md5', 'sha256', 'bcrypt', 'argon2']:
        return render_template('hashes.html', error="Invalid algorithm")
    
    # Validate hash format based on algorithm
    if algorithm == 'md5' and (len(target_hash) != 32 or not all(c in '0123456789abcdefABCDEF' for c in target_hash)):
        return render_template('hashes.html', error="Invalid MD5 hash format. Must be 32 hexadecimal characters.", hash=target_hash, algorithm=algorithm)
    elif algorithm == 'sha256' and (len(target_hash) != 64 or not all(c in '0123456789abcdefABCDEF' for c in target_hash)):
        return render_template('hashes.html', error="Invalid SHA256 hash format. Must be 64 hexadecimal characters.", hash=target_hash, algorithm=algorithm)
    elif algorithm == 'bcrypt' and not target_hash.startswith('$2'):
        return render_template('hashes.html', error="Invalid bcrypt hash format.", hash=target_hash, algorithm=algorithm)
    elif algorithm == 'argon2' and not target_hash.startswith('$argon2'):
        return render_template('hashes.html', error="Invalid argon2 hash format.", hash=target_hash, algorithm=algorithm)
    
    # Attempt to crack the hash
    result, attempts = crack_hash(target_hash, algorithm, wordlist)
    
    if result:
        return render_template('hashes.html', 
                              success=True, 
                              password=result, 
                              attempts=attempts, 
                              hash=target_hash,
                              algorithm=algorithm)
    else:
        return render_template('hashes.html', 
                              success=False, 
                              attempts=attempts, 
                              hash=target_hash,
                              algorithm=algorithm)

if __name__ == '__main__':
    app.run(debug=True)