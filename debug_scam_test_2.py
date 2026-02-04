from app.core.scam_detection import ScamDetectionEngine

engine = ScamDetectionEngine()
engine.ml_detector.is_trained = False
message = "Everyone else has already verified their accounts. This is the official procedure for all users."
history = [
    {"role": "user", "content": "I am from the official support team."},
    {"role": "assistant", "content": "How do I know that?"},
    {"role": "user", "content": "We are verifying all accounts today."}
]

print(f"Message: '{message}'")
rule_score, rule_factors = engine._analyze_rule_based(message)
print(f"Rule: {rule_score}, {rule_factors}")

kw_score, kw_factors = engine._analyze_keywords(message)
print(f"Keyword: {kw_score}, {kw_factors}")

pat_score, pat_factors = engine._analyze_patterns(message)
print(f"Pattern: {pat_score}, {pat_factors}")

ctx_score, ctx_factors = engine._analyze_context(message, history)
print(f"Context: {ctx_score}, {ctx_factors}")

score, confidence = engine.calculate_risk_score(message, history)
print(f"Total: {score}, {confidence}")
assessment = engine.analyze_message(message, history, {})
print(f"Factors: {assessment.risk_factors}")
print(f"Details: {assessment.details}")
