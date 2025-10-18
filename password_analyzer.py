# strength_analyzer.py
import re
import math

COMMON_PATTERNS = [
    "password","123456","qwerty","letmein","admin","welcome","iloveyou","sunil"
]

def char_classes(pw):
    classes = 0
    if re.search(r"[a-z]", pw): classes += 1
    if re.search(r"[A-Z]", pw): classes += 1
    if re.search(r"[0-9]", pw): classes += 1
    if re.search(r"[^\w\s]", pw): classes += 1
    return classes

def entropy_estimate(pw):
    """Very rough entropy estimate in bits based on char classes and length."""
    classes = char_classes(pw)
    # estimate charset size
    if classes == 1:
        charset = 26
    elif classes == 2:
        charset = 52
    elif classes == 3:
        charset = 62
    elif classes == 4:
        charset = 95
    else:
        charset = 26
    return round(len(pw) * math.log2(charset), 2)

def common_pattern_check(pw):
    lw = pw.lower()
    for p in COMMON_PATTERNS:
        if p in lw:
            return True, p
    return False, None

def score_password(pw):
    length = len(pw)
    classes = char_classes(pw)
    entropy = entropy_estimate(pw)
    common, pattern = common_pattern_check(pw)

    score = 0
    # length scoring
    if length >= 12: score += 3
    elif length >= 8: score += 2
    elif length >= 6: score += 1

    # classes scoring
    score += classes  # 0-4

    # penalty for common patterns
    if common:
        score -= 2

    # normalize
    score = max(0, score)
    return {
        "password": pw,
        "length": length,
        "classes": classes,
        "entropy_bits": entropy,
        "common_pattern": pattern,
        "score": score,
        "strength": strength_label(score, entropy)
    }

def strength_label(score, entropy):
    if score >= 6 and entropy >= 60:
        return "Very Strong"
    if score >= 4 and entropy >= 40:
        return "Strong"
    if score >= 3 and entropy >= 28:
        return "Medium"
    return "Weak"

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python strength_analyzer.py <password>")
        sys.exit(1)
    pw = sys.argv[1].strip()
    res = score_password(pw)
    for k,v in res.items():
        print(f"{k:15}: {v}")
