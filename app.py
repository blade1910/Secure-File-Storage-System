from ml_model.predict import predict_sql_injection
from flask import Flask, render_template, request
import pandas as pd
import uuid
import os
import hashlib
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import requests

app = Flask(__name__)

HASH_DB = "database/hashes.csv"
LOG_DB = "database/logs.csv"
UPLOAD_FOLDER = "uploads"
ENCRYPTED_FOLDER = "uploads/encrypted"
DECRYPTED_FOLDER = "uploads/decrypted"

VT_API_KEY = "1e73ed7f97b0cc5cb063c0e6a120d62900c60e73313aa614cecd59176e46599d"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)
os.makedirs(DECRYPTED_FOLDER, exist_ok=True)

def generate_hashes(file):
    data = file.read()
    sha256 = hashlib.sha256(data).hexdigest()
    sha512 = hashlib.sha512(data).hexdigest()
    file.seek(0)
    return sha256, sha512

def save_hash(file_name, sha256, sha512):
    file_id = str(uuid.uuid4())[:8]

    new_row = {
        "file_id": file_id,
        "file_name": file_name,
        "sha256": sha256,
        "sha512": sha512
    }

    if os.path.exists(HASH_DB):
        df = pd.read_csv(HASH_DB)
    else:
        df = pd.DataFrame(columns=["file_id", "file_name", "sha256", "sha512"])

    df = pd.concat([df, pd.DataFrame([new_row])], ignore_index=True)
    df.to_csv(HASH_DB, index=False)

    return file_id

def log_action(file_name, action):
    log_entry = {
        "file_name": file_name,
        "action": action,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    if os.path.exists(LOG_DB):
        df = pd.read_csv(LOG_DB)
    else:
        df = pd.DataFrame(columns=["file_name", "action", "timestamp"])

    df = pd.concat([df, pd.DataFrame([log_entry])], ignore_index=True)
    df.to_csv(LOG_DB, index=False)

def encrypt_file_data(data):
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    return key, cipher.iv, ciphertext

def decrypt_file_data(key, encrypted_blob):
    iv = encrypted_blob[:16]
    ciphertext = encrypted_blob[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext

def check_integrity(file_id, uploaded_file):
    if not os.path.exists(HASH_DB):
        return False, "Hash database not found."

    df = pd.read_csv(HASH_DB)
    matched_rows = df[df["file_id"] == file_id]

    if matched_rows.empty:
        return False, "Invalid File ID. No record found."

    stored_sha256 = matched_rows.iloc[0]["sha256"]
    stored_sha512 = matched_rows.iloc[0]["sha512"]

    new_sha256, new_sha512 = generate_hashes(uploaded_file)

    if stored_sha256 == new_sha256 and stored_sha512 == new_sha512:
        return True, "Integrity Verified: File is unchanged."
    else:
        return False, "Integrity Check Failed: File has been tampered with."

def check_malware(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "x-apikey": VT_API_KEY
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)

        return f"Malicious: {malicious}, Suspicious: {suspicious}, Harmless: {harmless}, Undetected: {undetected}"

    elif response.status_code == 404:
        return "File not found in VirusTotal database."

    else:
        return f"Error checking malware. Status code: {response.status_code}"

@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        action = request.form.get("action")
        uploaded_file = request.files.get("file")

        if not uploaded_file or uploaded_file.filename == "":
            return render_template("index.html", error="Please upload a file.")

        file_data = uploaded_file.read()
        uploaded_file.seek(0)

        if action == "hash":
            sha256, sha512 = generate_hashes(uploaded_file)
            file_id = save_hash(uploaded_file.filename, sha256, sha512)
            log_action(uploaded_file.filename, "Hash generated")

            return render_template(
                "index.html",
                success="Hash generated successfully.",
                file_name=uploaded_file.filename,
                file_id=file_id,
                sha256=sha256,
                sha512=sha512
            )

        elif action == "encrypt":
            key, iv, ciphertext = encrypt_file_data(file_data)

            encrypted_path = os.path.join(ENCRYPTED_FOLDER, uploaded_file.filename + ".enc")
            with open(encrypted_path, "wb") as f:
                f.write(iv + ciphertext)

            key_hex = key.hex()
            log_action(uploaded_file.filename, "File encrypted")

            return render_template(
                "index.html",
                success="File encrypted successfully.",
                file_name=uploaded_file.filename,
                encrypted_file=encrypted_path,
                secret_key=key_hex
            )

        elif action == "decrypt":
            key_hex = request.form.get("secret_key")

            if not key_hex:
                return render_template("index.html", error="Secret key is required for decryption.")

            try:
                key = bytes.fromhex(key_hex)
                plaintext = decrypt_file_data(key, file_data)

                original_name = uploaded_file.filename
                if original_name.endswith(".enc"):
                    original_name = original_name[:-4]

                decrypted_path = os.path.join(DECRYPTED_FOLDER, "decrypted_" + original_name)
                with open(decrypted_path, "wb") as f:
                    f.write(plaintext)

                log_action(uploaded_file.filename, "File decrypted")

                return render_template(
                    "index.html",
                    success="File decrypted successfully.",
                    file_name=uploaded_file.filename,
                    decrypted_file=decrypted_path
                )
            except Exception as e:
                return render_template("index.html", error=f"Decryption failed: {str(e)}")

        elif action == "integrity":
            file_id_input = request.form.get("file_id_input")

            if not file_id_input:
                return render_template("index.html", error="File ID is required for integrity check.")

            is_valid, message = check_integrity(file_id_input, uploaded_file)
            log_action(uploaded_file.filename, "Integrity checked")

            if is_valid:
                return render_template(
                    "index.html",
                    success=message,
                    file_name=uploaded_file.filename
                )
            else:
                return render_template(
                    "index.html",
                    error=message,
                    file_name=uploaded_file.filename
                )

        elif action == "malware":
            sha256, _ = generate_hashes(uploaded_file)
            result = check_malware(sha256)
            log_action(uploaded_file.filename, "Malware checked")

            return render_template(
                "index.html",
                success="Malware check completed.",
                file_name=uploaded_file.filename,
                malware_result=result
            )
        elif action == "sql_detect":
            user_query = request.form.get("user_query")

            if not user_query:
                return render_template("index.html", error="Please enter a query to check.")

            prediction, confidence = predict_sql_injection(user_query)
            log_action("SQL Query", "SQL injection checked")

            if str(prediction).lower() in ["1", "malicious", "attack", "sql injection"]:
                result_message = "SQL Injection Detected"
            else:
                result_message = "Input appears safe"

            if confidence is not None:
                result_message += f" (Confidence: {confidence:.2f})"

            return render_template(
                "index.html",
                success="SQL injection detection completed.",
                user_query=user_query,
                sql_result=result_message
            )

    return render_template("index.html")


if __name__ == "__main__":
    app.run()