import requests

def check_file_hash_virustotal(file_hash, api_key):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "x-apikey": api_key
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()

        stats = data["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)

        return {
            "status": "success",
            "message": f"Malicious: {malicious}, Suspicious: {suspicious}, Harmless: {harmless}, Undetected: {undetected}"
        }

    elif response.status_code == 404:
        return {
            "status": "not_found",
            "message": "File hash not found in VirusTotal database."
        }

    else:
        return {
            "status": "error",
            "message": f"VirusTotal API error: {response.status_code}"
        }