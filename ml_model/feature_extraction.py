def extract_features(query: str):
    query = str(query).lower()

    special_chars = ["'", '"', ";", "-", "#", "=", "(", ")", "*", ","]
    sql_keywords = [
        "select", "union", "drop", "delete", "update", "insert",
        "or", "and", "where", "sleep", "benchmark", "waitfor",
        "create", "exec", "xp_"
    ]

    return [
        len(query),  # query length
        query.count("'"),  # single quotes
        query.count('"'),  # double quotes
        sum(1 for c in query if c in special_chars),  # special char count
        sum(1 for word in sql_keywords if word in query),  # sql keyword count
        int("--" in query or "#" in query or "/" in query or "/" in query),  # comment symbols
        int(" or " in query),  # OR operator
        int(" and " in query),  # AND operator
        int("1=1" in query or "'a'='a" in query or '"a"="a' in query),  # tautology
        int("union" in query),  # union attack
        int(any(x in query for x in ["drop", "delete", "update", "insert", "create"])),  # dangerous keywords
        int(any(x in query for x in ["sleep", "benchmark", "waitfor"])),  # time-based attack
    ]