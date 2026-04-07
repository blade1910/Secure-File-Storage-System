import joblib
import pandas as pd

model = joblib.load("ml_model/model.pkl")

def extract_features(query):
    return {
        "query_length": len(query),
        "single_quote_count": query.count("'"),
        "double_quote_count": query.count('"'),
        "special_char_count": sum(1 for c in query if not c.isalnum() and not c.isspace()),
        "sql_keyword_count": sum(word in query.lower() for word in ["select", "drop", "union", "or", "and"]),
        "comment_symbol_present": int("--" in query or "#" in query or "/*" in query),
        "or_operator_present": int(" or " in query.lower()),
        "and_operator_present": int(" and " in query.lower()),
        "tautology_present": int("1=1" in query.replace(" ", "")),
        "union_present": int("union" in query.lower()),
        "dangerous_keyword_present": int(any(word in query.lower() for word in ["drop", "delete", "truncate"])),
        "time_based_attack_present": int(any(word in query.lower() for word in ["sleep", "benchmark", "waitfor"]))
    }

def predict_sql_injection(user_input):
    features = extract_features(user_input)
    df = pd.DataFrame([features])

    prediction = model.predict(df)[0]

    if hasattr(model, "predict_proba"):
        confidence = max(model.predict_proba(df)[0])
    else:
        confidence = None

    return prediction, confidence