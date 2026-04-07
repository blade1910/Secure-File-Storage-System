import joblib
import pandas as pd

model = joblib.load("ml_model/model.pkl")

FEATURE_ORDER = [
    "query_length",
    "single_quote_count",
    "double_quote_count",
    "special_char_count",
    "sql_keyword_count",
    "comment_symbol_present",
    "or_operator_present",
    "and_operator_present",
    "tautology_present",
    "union_present",
    "dangerous_keyword_present",
    "time_based_attack_present"
]

def extract_features(query):
    query_lower = query.lower()
    query_no_spaces = query.replace(" ", "")

    return {
        "query_length": len(query),
        "single_quote_count": query.count("'"),
        "double_quote_count": query.count('"'),
        "special_char_count": sum(1 for c in query if not c.isalnum() and not c.isspace()),
        "sql_keyword_count": sum(word in query_lower for word in ["select", "drop", "union", "or", "and"]),
        "comment_symbol_present": int("--" in query or "#" in query or "/*" in query),
        "or_operator_present": int(" or " in query_lower),
        "and_operator_present": int(" and " in query_lower),
        "tautology_present": int("1=1" in query_no_spaces),
        "union_present": int("union" in query_lower),
        "dangerous_keyword_present": int(any(word in query_lower for word in ["drop", "delete", "truncate"])),
        "time_based_attack_present": int(any(word in query_lower for word in ["sleep", "benchmark", "waitfor"]))
    }

def predict_sql_injection(user_input):
    features = extract_features(user_input)

    df = pd.DataFrame([[features[col] for col in FEATURE_ORDER]], columns=FEATURE_ORDER)

    prediction = model.predict(df)[0]

    if hasattr(model, "predict_proba"):
        confidence = float(max(model.predict_proba(df)[0]))
    else:
        confidence = None

    return prediction, confidence