from app.core.scam_detection import ScamDetectionEngine

engine = ScamDetectionEngine()

test_cases = [
    ("Trust me I am bank officer", True),
    ("I am authorized representative", True),
    ("Your account will be blocked", True),
    ("Government official speaking", True),
    ("Believe me this is genuine", True),
    ("Just a regular conversation", False),
    ("How is your day going", False),
]

for message, should_detect in test_cases:
    risk_score, confidence = engine.calculate_risk_score(message)
    print(f"Message: '{message}' | Score: {risk_score} | Confidence: {confidence} | Expected: {should_detect}")
    if should_detect and risk_score <= 0.05:
        print("FAIL: False Negative")
    elif not should_detect and risk_score > 0.05:
        print("FAIL: False Positive")
    else:
        print("PASS")
