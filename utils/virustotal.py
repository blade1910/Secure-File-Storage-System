import requests

def check_file_hash_virustotal(file_hash, api_key):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "x-apikey": api_key
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return response.json()
    elif response.status_code == 404:
        return {"error": "File hash not found in VirusTotal database."}
    else:
        return {"error": f"VirusTotal API error: {response.status_code}", "details": response.text}