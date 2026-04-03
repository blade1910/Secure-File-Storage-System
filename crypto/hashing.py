import hashlib

def generate_hashes(file):
    data = file.read()

    sha256 = hashlib.sha256(data).hexdigest()
    sha512 = hashlib.sha512(data).hexdigest()

    file.seek(0)
    return sha256, sha512